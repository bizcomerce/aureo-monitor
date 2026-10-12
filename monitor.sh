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
FAILS=(); NOTES=(); SHED=()
# duplicate-run guard: native schedule and the external scheduler may both fire; skip when a full run completed in the last 150 s
if [ -z "${DRILL_MON_BASE:-}" ] && [ "${FORCE_RUN:-}" != 1 ]; then
  lastmon=$(curl -sS -m 15 "$NTFY/$MON_T/json?poll=1&since=3m" 2>/dev/null | jq -r 'select(.event=="message")|.time' 2>/dev/null | tail -1)
  if [ -n "$lastmon" ] && [ $(( $(date +%s) - lastmon )) -lt 150 ]; then echo "duplicate run guard: last run $(( $(date +%s) - lastmon )) s ago, skipping"; exit 0; fi
fi
ts() { date -u +%FT%TZ; }

# fetch <path> -> sets F_CODE F_TTFB F_TOTAL F_LOC F_BYTES F_MARK F_WALL F_L3 F_GATE
fetch() {
  local h b; h=$(mktemp); b=$(mktemp)
  local w; w=$(curl -sS -m 30 -A "$UA" -o "$b" -D "$h" -w '%{http_code} %{time_starttransfer} %{time_total}' "$BASE$1" 2>/dev/null) || w="000 0 30"
  read -r F_CODE F_TTFB F_TOTAL <<<"$w"
  F_LOC=$(tr -d '\r' <"$h" | sed -n 's/^[Ll]ocation: *//p' | head -1)
  F_WALL=$(tr -d '\r' <"$h" | sed -n 's/^[Xx]-[Aa]ureo-[Ww]all: *//p' | head -1)
  F_L3=$(tr -d '\r' <"$h" | sed -n 's/^[Xx]-[Aa]ureo-[Ll]3: *//p' | head -1)
  F_GATE=$(tr -d '\r' <"$h" | sed -n 's/^[Xx]-[Aa]ureo-[Gg]ate: *//p' | head -1)
  F_BYTES=$(wc -c <"$b"); F_MARK=0; grep -qE 'aureo-page-cart|woocommerce-cart' "$b" && F_MARK=1
  rm -f "$h" "$b"
}
over() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a+0>b+0)}'; }

# each check echoes "" on pass or a short reason on fail
c_cart()  { fetch "$1"; [ -n "$F_WALL" ] && { echo "wall_denied_transactional"; return; }
  [ "$F_CODE" = 200 ] || { echo "cart_http_$F_CODE"; return; }
  [ "$F_BYTES" -ge 2000 ] || { echo "cart_small"; return; }
  [ "$F_MARK" = 1 ] || { echo "cart_marker_missing"; return; }
  over "$F_TTFB" 10 && { echo "cart_slow"; return; }; SHED+=("${F_GATE:-}"); }
c_chk()   { fetch "$1"; [ -n "$F_WALL" ] && { echo "wall_denied_transactional"; return; }
  case "$F_CODE" in 301|302|303|307|308) ;; *) echo "checkout_http_$F_CODE"; return;; esac
  case "$F_LOC" in */cart/|*/cart-it/|*cart*) ;; *) echo "checkout_redirect_not_cart"; return;; esac
  over "$F_TTFB" 10 && { echo "checkout_slow"; return; }; }
c_l3()    { fetch "$KEYLESS_PATH"; [ "$F_CODE" = 400 ] || { echo "l3_keyless_http_$F_CODE"; return; }
  [ -n "$F_L3" ] || { echo "l3_header_missing"; return; }; SHED+=("L3:$F_L3"); }
c_b0()    { fetch "$CANARY_PATH"; [ "$F_CODE" = 503 ] && [ -n "$F_WALL" ] || { echo "b0_not_denying_$F_CODE"; return; }
  over "$F_TTFB" 2 && { echo "b0_slow"; return; }
  fetch /shop/; [ "$F_CODE" = 200 ] && [ -z "$F_WALL" ] || echo "shop_$F_CODE"; }
c_tls()   { local host=${BASE#https://} end d
  end=$(echo | timeout 15 openssl s_client -servername "$host" -connect "$host:443" 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
  [ -n "$end" ] || { echo "tls_unreadable"; return; }
  d=$(( ( $(date -d "$end" +%s) - $(date +%s) ) / 86400 )); [ "$d" -ge 14 ] || echo "tls_${d}d_left"; NOTES+=("tls_days=$d"); }
poll() { curl -sS -m 15 "$NTFY/$1/json?poll=1&since=$2" 2>/dev/null | jq -r 'select(.event=="message") | "\(.time) \(.message)"' 2>/dev/null; }
c_dead()  { # pull-based collector heartbeat: public file holding one epoch, rewritten by the on-host collector every minute
  local p=${DRILL_HB_PATH:-$HB_PATH} body ep age; body=$(curl -sS -m 15 -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' -A "$UA" "$BASE$p?c=$RANDOM$RANDOM" 2>/dev/null | head -c 40)
  ep=$(printf '%s' "$body" | tr -d ' \r\n'); case "$ep" in ''|*[!0-9]*) echo "collector_heartbeat_unreadable"; return;; esac
  age=$(( $(date +%s) - ep )); NOTES+=("collector_hb_age_s=$age"); [ "$age" -le 2400 ] || echo "collector_heartbeat_stale_${age}s"; }

run() { # name fn arg  (one retry after 20 s so a single dropped request never pages)
  local r; r=$("$2" "${3:-}"); if [ -n "$r" ]; then sleep 20; r=$("$2" "${3:-}"); fi
  if [ -n "$r" ]; then FAILS+=("$1:$r"); echo "FAIL $1 $r"; else echo "pass $1"; fi; }

run cart-en c_cart "$CART_EN"; run cart-it c_cart "$CART_IT"
run checkout-en c_chk "$CHK_EN"; run checkout-it c_chk "$CHK_IT"
run p06-l3 c_l3; run b0 c_b0; run tls c_tls; run collector-dead-man c_dead

key=$(printf '%s\n' "${FAILS[@]:-}" | sed 's/:.*//' | sort | tr '\n' ',' ); key=${key%,}
last=$(poll "$ALERT_T" 6h | grep -E "^[0-9]+ (ALERT|RECOVERED)" | tail -1); lt=${last%% *}; lm=${last#* }; now=$(date +%s)
pub() { curl -sS -m 15 -o /dev/null -H "Title: AUREO $1" -H "Priority: $2" -d "$3" "$NTFY/$ALERT_T" || echo "ALERT DELIVERY FAILED"; }
if [ -n "$key" ]; then
  detail=$(printf '%s; ' "${FAILS[@]}")
  if [ "${lm%% *}" = ALERT ] && [ "${lm#ALERT }" != "$lm" ] && [ "$(echo "$lm" | sed -n 's/^ALERT \([^ ]*\) .*/\1/p')" = "$key" ] && [ $((now-${lt:-0})) -lt 3600 ]; then
    echo "alert unchanged, not repeated (last $((now-lt)) s ago)"
  else pub "SALES/WALL ALERT" urgent "ALERT $key $detail $(ts)"; echo "alert published: $key"; fi
else
  if [ "${lm%% *}" = ALERT ]; then pub "RECOVERED" default "RECOVERED all checks pass $(ts)"; echo "recovery published"; fi
fi
# monitor liveness for the on-host dead-man (published only when the run completed)
[ -z "${DRILL_MON_BASE:-}" ] && curl -sS -m 10 -o /dev/null -d "ok $(ts)" "$NTFY/$MON_T"
{ echo "### AUREO external monitor $(ts)"; echo "result: ${key:-ALL PASS}"; echo "shed/gate: ${SHED[*]:-n/a}"; echo "${NOTES[*]:-}"; } >>"${GITHUB_STEP_SUMMARY:-/dev/null}"
[ -z "$key" ]
