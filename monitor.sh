#!/usr/bin/env bash
# AUREO external monitor (runs on GitHub Actions, independent of the Beohosting account).
# Only anonymous GETs of public pages. No cookies, no POST, no -L. Secrets arrive via env; nothing secret is ever echoed.
# Env: BASE (https origin), NTFY_BASE (secret prefix of three ntfy.sh topics: -alert, -hb collector, -mon monitor),
#      CANARY_PATH (B0 deny URL), KEYLESS_PATH (P0-6 keyless 400 URL), CART_EN/CART_IT/CHK_EN/CHK_IT (paths),
#      DRILL_CART_PATH / DRILL_HB_BASE / DRILL_MON_BASE (drill overrides, empty in production).
set -u
UA="AUREO-Synthetic/1.0 (external-gh)"
BASE=${BASE:-https://aureo-collection.com}
CART_EN=${CART_EN:-/cart/}; CART_IT=${CART_IT:-/it/cart-it/}; CHK_EN=${CHK_EN:-/checkout/}; CHK_IT=${CHK_IT:-/it/checkout-it/}
[ -n "${DRILL_CART_PATH:-}" ] && CART_EN=$DRILL_CART_PATH
NTFY=https://ntfy.sh
: "${NTFY_BASE:?NTFY_BASE missing}"; : "${HB_PATH:?HB_PATH missing}"
ALERT_T="${NTFY_BASE}-alert"; HB_T="${DRILL_HB_BASE:-$NTFY_BASE}-hb"; MON_T="${NTFY_BASE}-mon"
FAILS=(); NOTES=(); SHED=(); SIDE=$(mktemp)   # checks run in $(...) subshells: they report shed/notes through this file
note() { echo "$1 $2" >>"$SIDE"; }
# duplicate-run guard: native schedule and the external scheduler may both fire; skip when a full run completed in the last 150 s
if [ -z "${DRILL_MON_BASE:-}" ] && [ "${FORCE_RUN:-}" != 1 ]; then
  lastmon=$(curl -sS -m 15 "$NTFY/$MON_T/json?poll=1&since=3m" 2>/dev/null | jq -r 'select(.event=="message")|.time' 2>/dev/null | tail -1)
  if [ -n "$lastmon" ] && [ $(( $(date +%s) - lastmon )) -lt 150 ]; then echo "duplicate run guard: last run $(( $(date +%s) - lastmon )) s ago, skipping"; exit 0; fi
fi
ts() { date -u +%FT%TZ; }

# fetch <path> [nocache] -> sets F_CODE F_TTFB F_TOTAL F_LOC F_BYTES F_MARK F_CHAL F_WALL F_L3 F_GATE F_SERVER F_ORIGIN F_CLASS
#   F_HEAD40, and overwrites $LASTF with a safe fingerprint of this response (no path, no Location, no body; see diag below)
# Origin evidence = LiteSpeed/PHP/X-Aureo headers or WordPress markers. Normal responses keep `Server: LiteSpeed` through the
# hoster's openresty front; the Imunify WebShield challenge (2026-10-09, run #154) is answered by openresty itself (~12 KB, 200).
# F_CLASS: origin | challenge (openresty 200/403/429, no origin evidence) | proxy_5xx (openresty 5xx = backend unreachable) |
#          transport (no HTTP response) | unknown (anything else: neither provably the shop nor a recognised challenge)
LASTF=$(mktemp)
fetch() {
  local h b nc=(); h=$(mktemp); b=$(mktemp); [ "${2:-}" = nocache ] && nc=(-H 'Cache-Control: no-cache' -H 'Pragma: no-cache')
  local w; w=$(curl -sS -m 30 -A "$UA" "${nc[@]}" -o "$b" -D "$h" -w '%{http_code} %{time_starttransfer} %{time_total}' "$BASE$1" 2>/dev/null) || w="000 0 30"
  read -r F_CODE F_TTFB F_TOTAL <<<"$w"
  F_LOC=$(tr -d '\r' <"$h" | sed -n 's/^[Ll]ocation: *//p' | head -1)
  F_WALL=$(tr -d '\r' <"$h" | sed -n 's/^[Xx]-[Aa]ureo-[Ww]all: *//p' | head -1)
  F_L3=$(tr -d '\r' <"$h" | sed -n 's/^[Xx]-[Aa]ureo-[Ll]3: *//p' | head -1)
  F_GATE=$(tr -d '\r' <"$h" | sed -n 's/^[Xx]-[Aa]ureo-[Gg]ate: *//p' | head -1)
  F_SERVER=$(tr -d '\r' <"$h" | sed -n 's/^[Ss]erver: *//p' | tail -1 | tr -cd 'A-Za-z0-9./_ -' | tr ' ' '_' | cut -c1-32)
  F_BYTES=$(wc -c <"$b"); F_MARK=0; grep -qE 'aureo-page-cart|woocommerce-cart' "$b" && F_MARK=1
  F_CHAL=0; [ "$F_BYTES" -lt 3000 ] && grep -q 'aureo_fv' "$b" && F_CHAL=1   # static Filter Shield 2A challenge page (~1 KB, sets aureo_fv)
  F_HEAD40=$(head -c 40 "$b" | tr -d '\r\n ')
  F_ORIGIN=0
  { tr -d '\r' <"$h" | grep -qiE '^(x-litespeed-[a-z-]+|x-aureo-[a-z0-9-]+|x-powered-by: *php)'; } && F_ORIGIN=1
  case "$F_SERVER" in [Ll]ite[Ss]peed*) F_ORIGIN=1;; esac
  grep -qE '/wp-content/|/wp-includes/|woocommerce' "$b" && F_ORIGIN=1
  if [ "$F_CODE" = 000 ]; then F_CLASS=transport; elif [ "$F_ORIGIN" = 1 ]; then F_CLASS=origin
  else case "$F_SERVER:$F_CODE" in [Oo]pen[Rr]esty*:200|[Oo]pen[Rr]esty*:403|[Oo]pen[Rr]esty*:429) F_CLASS=challenge;;
    [Oo]pen[Rr]esty*:5??) F_CLASS=proxy_5xx;; *) F_CLASS=unknown;; esac; fi
  local lc=none; case "$F_LOC" in '') ;; */cart/|*/cart-it/|*/cart/\?*|*/cart-it/\?*) lc=cart;; "$BASE"*|/*) lc=same-host;; *) lc=external;; esac
  printf 'http=%s server=%s origin=%s class=%s loc=%s bytes=%s sha8=%s ttfb=%s\n' "$F_CODE" "${F_SERVER:-none}" "$F_ORIGIN" "$F_CLASS" \
    "$lc" "$F_BYTES" "$(sha256sum "$b" | cut -c1-8)" "$F_TTFB" >"$LASTF"
  rm -f "$h" "$b"
}
over() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0>b+0)}'; }

# each check echoes "" on pass or a short reason on fail
c_cart()  { fetch "$1"; [ -n "$F_WALL" ] && { echo "wall_denied_transactional"; return; }
  [ "$F_CODE" = 200 ] || { echo "cart_http_$F_CODE"; return; }
  [ "$F_BYTES" -ge 2000 ] || { echo "cart_small"; return; }
  [ "$F_MARK" = 1 ] || { echo "cart_marker_missing"; return; }
  over "$F_TTFB" 10 && { echo "cart_slow"; return; }; note S "${F_GATE:-}"; }
c_chk()   { fetch "$1"; [ -n "$F_WALL" ] && { echo "wall_denied_transactional"; return; }
  case "$F_CODE" in 301|302|303|307|308) ;; *) echo "checkout_http_$F_CODE"; return;; esac
  case "$F_LOC" in */cart/|*/cart-it/|*cart*) ;; *) echo "checkout_redirect_not_cart"; return;; esac
  over "$F_TTFB" 10 && { echo "checkout_slow"; return; }; }
c_l3()    { fetch "$KEYLESS_PATH"; [ "$F_CODE" = 400 ] || { echo "l3_keyless_http_$F_CODE"; return; }
  [ -n "$F_L3" ] || { echo "l3_header_missing"; return; }; note S "L3:$F_L3"; }
c_b0_present() { fetch "$CANARY_PATH"; [ "$F_CODE" = 503 ] && [ -n "$F_WALL" ] || { echo "b0_not_denying_$F_CODE"; return; }
  over "$F_TTFB" 2 && { echo "b0_slow"; return; }
  c_shop; }
# plain Shop: 200 from the origin (a generic 200, e.g. a hosting challenge page, is not the shop), no wall, not the 2A page
c_shop()  { fetch /shop/; [ "$F_CODE" = 200 ] && [ -z "$F_WALL" ] && [ "$F_CHAL" = 0 ] || { echo "shop_$F_CODE"; return; }
  [ "$F_ORIGIN" = 1 ] || echo "shop_200_not_origin"; }
# B0 removed (plan 21a9d291 G6): the cookieless filtered canary must reach the app. 200 with a real page, or the designed F cap
# (429 shed-F / L3 header). Never deny-expensive, never a 503, never the 2A challenge page. A reappearing B0 is its own alert key.
c_b0_absent() { fetch "$CANARY_PATH"
  case "$F_WALL" in deny-expensive*) echo "b0_reappeared_deny_expensive"; return;; esac
  [ "$F_CODE" = 503 ] && { echo "b0_reappeared_503${F_WALL:+_$F_WALL}"; return; }
  [ "$F_CHAL" = 1 ] && { echo "filter_challenge_page_served"; return; }
  case "$F_CODE" in
    200) [ "$F_BYTES" -ge 2000 ] || { echo "filtered_200_small_${F_BYTES}B"; return; }; [ -z "$F_WALL" ] || { echo "filtered_200_wall_$F_WALL"; return; }
         [ "$F_ORIGIN" = 1 ] || { echo "filtered_200_not_origin"; return; };;
    429) case "$F_WALL" in shed-F*) ;; *) [ -n "$F_L3" ] || { echo "filtered_429_unrecognised"; return; };; esac; note S "F429:${F_WALL:-$F_L3}";;
    *) echo "filtered_http_$F_CODE"; return;;
  esac
  over "$F_TTFB" 10 && { echo "filtered_slow"; return; }
  c_shop; }
c_b0()    { if [ "${B0_EXPECT:-present}" = absent ]; then c_b0_absent; else c_b0_present; fi; }
# TLS certificate only (chain + hostname + days left). It says nothing about the shop: application availability is the HTTP checks.
c_tls()   { local host=${BASE#https://} out end d v
  out=$(echo | timeout 15 openssl s_client -servername "$host" -verify_hostname "$host" -connect "$host:443" 2>/dev/null)
  v=$(printf '%s\n' "$out" | sed -n 's/^ *Verify return code: *\([0-9]*\).*/\1/p' | tail -1)
  end=$(printf '%s\n' "$out" | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  echo "class=tls verify=${v:-none}" >"$LASTF"
  [ -n "$end" ] || { echo "tls_unreadable"; return; }
  [ "$v" = 0 ] || { echo "tls_verify_failed_${v:-none}"; return; }
  d=$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 )); echo "class=tls verify=0 days=$d" >"$LASTF"
  [ "$d" -ge 14 ] || echo "tls_${d}d_left"; note N "tls_days=$d"; }
poll() { curl -sS -m 15 "$NTFY/$1/json?poll=1&since=$2" 2>/dev/null | jq -r 'select(.event=="message") | "\(.time) \(.message)"' 2>/dev/null; }
c_dead()  { # pull-based collector heartbeat: public file holding one epoch, rewritten by the on-host collector every minute
  local p=${DRILL_HB_PATH:-$HB_PATH} ep age; fetch "$p?c=$RANDOM$RANDOM" nocache
  ep=$F_HEAD40; [ "$F_CODE" = 200 ] || ep=; case "$ep" in ''|*[!0-9]*) echo "collector_heartbeat_unreadable"; return;; esac
  age=$(( $(date +%s) - ep )); note N "collector_hb_age_s=$age"; [ "$age" -le 2400 ] || echo "collector_heartbeat_stale_${age}s"; }

[ "${MONITOR_LIB:-}" = 1 ] && return 0 2>/dev/null   # test hook: load the check functions only
pub() { local c i
  if [ "${MONITOR_DRY:-}" = 1 ]; then echo "dry run, not published: [$2] AUREO $1 | ${3:0:240}"; return 0; fi   # drill=dry: rollout check
  for i in 1 2 3; do   # verify the HTTP status: a 429/5xx must never look like a delivered alert
    c=$(curl -sS -m 15 -o /dev/null -w '%{http_code}' -H "Title: AUREO $1" -H "Priority: $2" -d "$3" "$NTFY/$ALERT_T" 2>/dev/null) || c=000
    [ "$c" = 200 ] && { echo "ntfy alert delivery http 200"; return 0; }; echo "ntfy alert delivery http $c (try $i)"; sleep 5; done
  echo "ALERT DELIVERY FAILED"; DELIVERY_FAILED=1; return 1; }
# G5a receipt drill (drill=g5a): one ALERT-drill and one RECOVERED-drill message through the real pub(), priority default (the
# lowest that still sounds/vibrates). No checks and no -mon liveness. The bodies start with "AUREO G5a DRILL", never with ALERT or
# RECOVERED, so the alert state machine below (and the next scheduled run) ignores them. Prints the stored ntfy message ids.
if [ "${G5A_DRILL:-}" = 1 ]; then
  n=${G5A_NONCE:-}; case "$n" in ''|*[!A-Za-z0-9-]*) echo "g5a: nonce missing or invalid"; exit 1;; esac
  q=$(curl -sS -m 10 "$NTFY/v1/account" 2>/dev/null | jq -c '{basis:.limits.basis,limit:.limits.messages,used:.stats.messages,remaining:.stats.messages_remaining}' 2>/dev/null)
  echo "g5a runner ntfy quota before: ${q:-unreadable}"
  pub "G5a DRILL ALERT (test)" default "AUREO G5a DRILL $(ts) $n — test, no action needed (ALERT path)" || exit 1
  sleep "${G5A_GAP:-20}"
  pub "G5a DRILL RECOVERED (test)" default "AUREO G5a DRILL $(ts) $n — test, no action needed (RECOVERED path)" || exit 1
  sleep "${G5A_SETTLE:-3}"; curl -sS -m 15 "$NTFY/$ALERT_T/json?poll=1&since=10m" 2>/dev/null | jq -r --arg n "$n" \
    'select(.event=="message" and (.message|contains($n))) | "g5a stored id=\(.id) time=\(.time) priority=\(.priority // 3) title=\(.title)"'
  exit 0
fi
# Each final failure gets a verdict from the class of the response that failed it (the last fetch of the failing attempt):
#   challenge -> blocked (hosting challenge layer answered, the shop was never asked); unknown -> ambiguous;
#   origin / proxy_5xx / transport / tls / no fingerprint -> confirmed (fail safe: a genuine failure is never downgraded).
VERDS=(); DIAG=()
run() { # name fn arg  (one retry after RETRY_GAP, default 20 s, so a single dropped request never pages)
  local r v c; : >"$LASTF"; r=$("$2" "${3:-}"); if [ -n "$r" ]; then sleep "${RETRY_GAP:-20}"; : >"$LASTF"; r=$("$2" "${3:-}"); fi
  if [ -z "$r" ]; then echo "pass $1"; return; fi
  c=$(sed -n 's/.*class=\([a-z_0-9]*\).*/\1/p' "$LASTF" | head -1)
  case "$c" in challenge) v=blocked;; unknown) v=ambiguous;; *) v=confirmed;; esac
  FAILS+=("$1:$r"); VERDS+=("$v"); DIAG+=("$1 $r verdict=$v $(head -1 "$LASTF")"); echo "FAIL $1 $r"; echo "diag ${DIAG[${#DIAG[@]}-1]}"; }

run cart-en c_cart "$CART_EN"; run cart-it c_cart "$CART_IT"
run checkout-en c_chk "$CHK_EN"; run checkout-it c_chk "$CHK_IT"
run p06-l3 c_l3; run b0 c_b0; run tls c_tls; run collector-dead-man c_dead
rm -f "$LASTF"

# run verdict: any confirmed failure is a SALES/WALL ALERT (urgent, unchanged); otherwise the store status is UNVERIFIED and the
# owner is told so at once: ambiguous -> MONITOR FAILURE (urgent), only recognised challenges -> MONITOR ACCESS BLOCKED (high)
verdict=; case " ${VERDS[*]:-} " in *" confirmed "*) verdict=confirmed;; *" ambiguous "*) verdict=ambiguous;; *" blocked "*) verdict=blocked;; esac
names=$(printf '%s\n' "${FAILS[@]:-}" | sed 's/:.*//' | sort | tr '\n' ',' ); names=${names%,}
key=; [ -n "$names" ] && key="$verdict:$names"
RIP=; if [ -n "$key" ]; then   # runner public IP, only for a failing run (lets a hosting block be put to the hoster with IP + time)
  RIP=$(curl -sS -m 8 https://api.ipify.org 2>/dev/null | head -c 64 | tr -cd '0-9a-fA-F:.')
  case "$RIP" in *.*.*.*|*:*:*) ;; *) RIP=unavailable;; esac; echo "runner_ip=$RIP"; fi
last=$(poll "$ALERT_T" 6h | grep -E "^[0-9]+ (ALERT|RECOVERED)" | tail -1); lt=${last%% *}; lm=${last#* }; now=$(date +%s)
if [ -n "$key" ]; then
  detail=; for i in "${!FAILS[@]}"; do detail+="${FAILS[$i]}[${VERDS[$i]}]; "; done
  case "$verdict" in
    confirmed) title="SALES/WALL ALERT"; prio=urgent; msg="ALERT $key $detail$(ts)";;
    ambiguous) title="MONITOR FAILURE - STORE STATUS UNVERIFIED"; prio=urgent
               msg="ALERT $key STORE STATUS UNVERIFIED: the monitor got responses that are neither the shop nor a recognised hosting challenge. $detail runner_ip=$RIP $(ts)";;
    *)         title="MONITOR ACCESS BLOCKED - STORE STATUS UNVERIFIED"; prio=high
               msg="ALERT $key STORE STATUS UNVERIFIED: the hosting challenge layer answered the monitor, the shop was not reached (not a shop failure). $detail runner_ip=$RIP $(ts)";;
  esac
  if [ "${lm%% *}" = ALERT ] && [ "${lm#ALERT }" != "$lm" ] && [ "$(echo "$lm" | sed -n 's/^ALERT \([^ ]*\) .*/\1/p')" = "$key" ] && [ $((now-${lt:-0})) -lt 3600 ]; then
    echo "alert unchanged, not repeated (last $((now-lt)) s ago)"
  else pub "$title" "$prio" "$msg"; echo "alert published: $key"; fi
else
  if [ "${lm%% *}" = ALERT ]; then pub "RECOVERED" default "RECOVERED all checks pass $(ts)"; echo "recovery published"; fi
fi
# monitor liveness for the on-host dead-man (published only when the run completed)
[ -z "${DRILL_MON_BASE:-}" ] && curl -sS -m 10 -o /dev/null -d "ok $(ts)" "$NTFY/$MON_T"
while read -r k v; do case "$k" in S) SHED+=("$v");; N) NOTES+=("$v");; esac; done <"$SIDE"; rm -f "$SIDE"
{ echo "### AUREO external monitor $(ts)"; echo "result: ${key:-ALL PASS}"; echo "shed/gate: ${SHED[*]:-n/a}"; echo "${NOTES[*]:-}"
  [ -n "$key" ] && { echo "runner_ip: $RIP"; printf -- '- %s\n' "${DIAG[@]}"; }; } >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
[ "${MONITOR_DRY:-}" = 1 ] && { echo "dry run result: ${key:-ALL PASS} (exit 0: no publish, no failed-run mail)"; exit 0; }
[ -z "$key" ] && [ -z "${DELIVERY_FAILED:-}" ]
