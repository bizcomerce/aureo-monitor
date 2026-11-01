#!/usr/bin/env bash
# Offline tests for the external monitor's B0 checks (plan 21a9d291 G6). A stub curl serves canned responses; no network.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); M="$HERE/../monitor.sh"; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cat >"$T/curl" <<'STUB'
#!/usr/bin/env bash
# args: ... -o BODY -D HDRS -w FMT ... URL ; scenario in $SCEN: code|wall|l3|bodyfile-kind|ttfb|server (server default LiteSpeed,
# "-" = no Server header); /shop/ uses SHOP_CODE / SHOP_SERVER; LOC adds a Location header; code 000 = no HTTP response
o=; D=; U=; while [ $# -gt 0 ]; do case "$1" in -o) o=$2; shift;; -D) D=$2; shift;; -w|-m|-A|-H|-d) shift;; *) U=$1;; esac; shift; done
IFS='|' read -r code wall l3 kind ttfb server <<<"$SCEN"; server=${server:-LiteSpeed}
case "$U" in */shop/) code=${SHOP_CODE:-200}; wall=; l3=; kind=page; server=${SHOP_SERVER:-$server};; esac
[ "$code" = 000 ] && exit 7
{ printf 'HTTP/1.1 %s X\r\n' "$code"; [ "$server" != - ] && printf 'Server: %s\r\n' "$server"; [ -n "$wall" ] && printf 'X-Aureo-Wall: %s\r\n' "$wall"
  [ -n "$l3" ] && printf 'X-Aureo-L3: %s\r\n' "$l3"; [ -n "${LOC:-}" ] && printf 'Location: %s\r\n' "$LOC"; } >"$D"
case "$kind" in chal) printf '<script>document.cookie="aureo_fv=1";location.reload()</script>%0900s' x >"$o";;
  page) { echo '<html>'; head -c 2500 /dev/zero | tr '\0' a; echo '</html>'; } >"$o";; deny) echo '<h1>503</h1>' >"$o";;
  wsc) { echo '<html><head><title>One moment</title></head><body><script>setTimeout(function(){location.reload()},1500)</script>'; head -c 11800 /dev/zero | tr '\0' b; echo '</body></html>'; } >"$o";;
  wp) { echo '<html><link href="/wp-content/themes/x.css">'; head -c 2500 /dev/zero | tr '\0' a; echo '</html>'; } >"$o";;
  *) : >"$o";; esac
printf '%s %s 0.2' "$code" "${ttfb:-0.1}"
STUB
chmod +x "$T/curl"; export PATH="$T:$PATH"
export NTFY_BASE=x HB_PATH=/hb DRILL_MON_BASE=t MONITOR_LIB=1 CANARY_PATH=/shop/?filter_color=black
# shellcheck disable=SC1090
. "$M"
P=0; F=0; t() { local n=$1 want=$2; shift 2; local got; got=$("$@"); if [ "$got" = "$want" ]; then P=$((P+1)); else F=$((F+1)); echo "FAIL $n: want [$want] got [$got]"; fi; }
sc() { SCEN=$1; export SCEN; }
B0_EXPECT=present
sc '503|deny-expensive||deny|0.1'; t present-ok "" c_b0
sc '200|||page'; t present-b0-missing "b0_not_denying_200" c_b0
B0_EXPECT=absent
sc '200|||page|0.2';                    t absent-200-ok "" c_b0
sc '429|shed-F||deny|0.1';              t absent-429-shedF-ok "" c_b0
sc '429||T-checkout-O|deny';            t absent-429-l3-ok "" c_b0
sc '429|||deny';                        t absent-429-unrecognised "filtered_429_unrecognised" c_b0
sc '503|deny-expensive||deny';          t absent-b0-back "b0_reappeared_deny_expensive" c_b0
sc '503|||deny';                        t absent-503-plain "b0_reappeared_503" c_b0
sc '503|shed-F||deny';                  t absent-503-shed "b0_reappeared_503_shed-F" c_b0
sc '200|||chal';                        t absent-challenge "filter_challenge_page_served" c_b0
sc '200|deny-expensive||page';          t absent-200-with-wall "b0_reappeared_deny_expensive" c_b0
sc '200|other||page';                   t absent-200-other-wall "filtered_200_wall_other" c_b0
sc '200|||deny';                        t absent-200-tiny "filtered_200_small_13B" c_b0
sc '500|||deny';                        t absent-500 "filtered_http_500" c_b0
sc '200|||page|12';                     t absent-slow "filtered_slow" c_b0
sc '200|||page|0.1'; export SHOP_CODE=503; t absent-shop-down "shop_503" c_b0; export SHOP_CODE=200
unset B0_EXPECT; sc '503|deny-expensive||deny'; t default-is-present "" c_b0
# shed/notes survive the $(...) subshell of run()
SIDE=$(mktemp); B0_EXPECT=absent; sc "429|shed-F||deny"; r=$(c_b0); t side-shed "S F429:shed-F" grep -x "S F429:shed-F" "$SIDE"; rm -f "$SIDE"
# response classes + fingerprint (incident #154: a hosting challenge page must never pass an application check)
fp() { fetch "$1"; sed -n "s/.*$2=\([^ ]*\).*/\1/p" "$LASTF"; }
sc '200|||page|0.1';               t class-origin-server origin fp /cart/ class
sc '200|||wp|0.1|-';               t class-origin-body-marker origin fp /cart/ class
sc '200|||wsc|0.1|openresty';      t class-challenge-200 challenge fp /cart/ class
sc '403|||deny|0.1|openresty';     t class-challenge-403 challenge fp /cart/ class
sc '502|||deny|0.1|openresty';     t class-proxy-5xx proxy_5xx fp /cart/ class
sc '000';                          t class-transport transport fp /cart/ class
sc '200|||page|0.1|nginx';         t class-unknown unknown fp /cart/ class
sc '200||r6|wsc|0.1|openresty';    t class-aureo-header-is-origin origin fp /cart/ class
sc '200|||wsc|0.1|openresty';      t fp-server openresty fp /cart/ server
sc '200|||page|0.1|Apache 2 x';    t fp-server-no-spaces Apache_2_x fp /cart/ server
LOC=https://aureo-collection.com/cart/; export LOC; sc '302|||deny';  t fp-loc-cart cart fp /checkout/ loc
LOC=/it/negozio/; sc '302|||deny';                                    t fp-loc-same-host same-host fp /checkout/ loc
LOC=https://evil.example/x?k=v; sc '302|||deny';                      t fp-loc-external external fp /checkout/ loc; unset LOC
sc '200|||wsc|0.1|openresty'; fetch '/secret-canary-path/?tok=SECRET123'
t fp-no-path-no-query 0 grep -c -E 'secret-canary|SECRET123|tok=' "$LASTF"
t fp-fields 1 grep -c -E '^http=200 server=openresty origin=0 class=challenge loc=none bytes=[0-9]+ sha8=[0-9a-f]{8} ttfb=0.1$' "$LASTF"
# application checks against a hosting challenge page (all were blind to it before, or passed it)
sc '200|||wsc|0.1|openresty'; t cart-challenge "cart_marker_missing" c_cart /cart/
LOC=; sc '200|||wsc|0.1|openresty'; t checkout-challenge "checkout_http_200" c_chk /checkout/
B0_EXPECT=absent; sc '200|||wsc|0.1|openresty'; t absent-200-challenge "filtered_200_not_origin" c_b0
B0_EXPECT=absent; sc '200|||page|0.1|nginx';    t absent-200-unknown "filtered_200_not_origin" c_b0
B0_EXPECT=absent; sc '200|||page|0.1'; export SHOP_SERVER=openresty; t absent-shop-challenge "shop_200_not_origin" c_b0
B0_EXPECT=present; sc '503|deny-expensive||deny|0.1'; t present-shop-challenge "shop_200_not_origin" c_b0; unset SHOP_SERVER
B0_EXPECT=absent; sc '200|||wp|0.1|-'; export SHOP_SERVER=LiteSpeed; t absent-200-origin-by-body "" c_b0; unset SHOP_SERVER
# G5a receipt drill: whole script, own stub curl (logs every call) and stub jq; no checks, exactly two publishes, no -mon
G=$(mktemp -d); LOG="$G/calls"; export LOG
cat >"$G/curl" <<'STUB'
#!/usr/bin/env bash
w=; U=; d=; p=; while [ $# -gt 0 ]; do case "$1" in -w) w=$2; shift;; -d) d=$2; shift;; -H) case "$2" in Priority:*) p=${2#Priority: };; esac; shift;; -o|-m|-A) shift;; -*) ;; *) U=$1;; esac; shift; done
printf '%s|%s|%s\n' "$U" "$p" "$d" >>"$LOG"; [ -n "$w" ] && printf 200; exit 0
STUB
printf '#!/usr/bin/env bash\ncat >/dev/null\n' >"$G/jq"; chmod +x "$G/curl" "$G/jq"
g5a() { : >"$LOG"; ( unset MONITOR_LIB; PATH="$G:$PATH" NTFY_BASE=x HB_PATH=/hb DRILL_MON_BASE=drill G5A_DRILL=1 G5A_NONCE=$1 G5A_GAP=0 G5A_SETTLE=0 bash "$M" >/dev/null 2>&1 ); echo $?; }
t g5a-exit-0 0 g5a N0nce-1
t g5a-two-publishes 2 grep -c '^https://ntfy.sh/x-alert|default|AUREO G5a DRILL .* N0nce-1 — test, no action needed (' "$LOG"
t g5a-no-alert-or-recovered-prefix 0 grep -c -E '\|(ALERT|RECOVERED) ' "$LOG"
t g5a-no-mon-no-checks 0 grep -c -E 'x-mon|aureo-collection' "$LOG"
t g5a-bad-nonce-exit-1 1 g5a 'bad nonce;'
t g5a-bad-nonce-no-publish 0 grep -c . "$LOG"
rm -rf "$G"
# Whole-run regression (incident #154): stub storefront by MODE, stub ntfy (publishes logged), stub openssl/jq/ipify; no network.
W=$(mktemp -d); PUBLOG="$W/pub"; export PUBLOG
cat >"$W/curl" <<'STUB'
#!/usr/bin/env bash
o=/dev/null; D=/dev/null; w=; d=; U=; ti=; pr=; ua=
while [ $# -gt 0 ]; do case "$1" in -o) o=$2; shift;; -D) D=$2; shift;; -w) w=$2; shift;; -d) d=$2; shift;;
  -H) case "$2" in Title:*) ti=${2#Title: };; Priority:*) pr=${2#Priority: };; esac; shift;; -m) shift;; -A) ua=$2; shift;; -*) ;; *) U=$1;; esac; shift; done
case "$U" in https://ntfy.sh/*) [ -n "$d" ] && { printf '%s|%s|%s|%s\n' "${U#https://ntfy.sh/}" "$ti" "$pr" "$d" >>"$PUBLOG"; [ -n "$w" ] && printf 200; }
    case "$U" in *-alert/json\?poll=1*) [ -n "${PREV:-}" ] && printf '%s\n' "$PREV";; esac; exit 0;;   # PREV = last "<epoch> <message>"
  https://api.ipify.org*) printf '203.0.113.7'; exit 0;; esac
p=${U#https://aureo-collection.com}; q=${p%%\?*}
code=200 srv=LiteSpeed kind=shop loc= l3=
case "$q" in /cart/|/it/cart-it/) kind=cart;; /checkout/) code=302 kind=empty loc=https://aureo-collection.com/cart/;;
  /it/checkout-it/) code=302 kind=empty loc=https://aureo-collection.com/it/cart-it/;; /kl-secret) code=400 kind=empty l3=r6;;
  /hb-secret.txt) kind=hb;; esac
case "$MODE" in challenge) code=200 srv=openresty kind=wsc loc= l3=;; ambiguous) code=200 srv=nginx kind=park loc= l3=;;
  proxy502) code=502 srv=openresty kind=empty loc= l3=;; transport) exit 7;;
  cartdown) [ "$q" = /cart/ ] && { code=500; kind=empty; };; hbstale) [ "$kind" = hb ] && kind=hbold;;
  uablock) case "$ua" in *AUREO-Synthetic/1.0*) code=200 srv=openresty kind=wsc loc= l3=;; esac;;   # blocks the monitor UA only (per-UA rule)
  mixed) if [ "$q" = /cart/ ]; then code=500 kind=empty; else code=200 srv=openresty kind=wsc loc= l3=; fi;; esac
{ printf 'HTTP/1.1 %s X\r\nServer: %s\r\n' "$code" "$srv"; [ -n "$loc" ] && printf 'Location: %s\r\n' "$loc"; [ -n "$l3" ] && printf 'X-Aureo-L3: %s\r\n' "$l3"
  [ "$kind" = wsc ] && printf 'Content-Type: text/html; charset=UTF-8\r\nDate: Sat, 31 Oct 2026 08:00:37 GMT\r\nSet-Cookie: i360_wsid=SECRETCOOKIEVALUE9; path=/\r\nX-Imunify-Test: SECRETHEADERVALUE7\r\n'; } >"$D"
case "$kind" in cart) { echo '<body class="woocommerce-cart">'; head -c 3000 /dev/zero | tr '\0' a; } >"$o";;
  shop) { echo '<link href="/wp-content/x.css">'; head -c 3000 /dev/zero | tr '\0' a; } >"$o";;
  wsc) { echo '<html><head><title>Please wait... [Imunify360]</title></head><body>imunify360 <script>setTimeout(function(){location.reload()},1500)</script>'; head -c 11900 /dev/zero | tr '\0' b; } >"$o";;
  park) { echo '<html>Parked domain</html>'; head -c 3000 /dev/zero | tr '\0' c; } >"$o";;
  hb) date +%s >"$o";; hbold) echo $(( $(date +%s) - 5000 )) >"$o";; *) : >"$o";; esac
[ -n "$w" ] && printf '%s 0.1 0.2 198.51.100.4 2 0.01 0.04' "$code"; exit 0
STUB
cat >"$W/openssl" <<'STUB'
#!/usr/bin/env bash
cat >/dev/null; case "$1" in s_client) echo "    Verify return code: ${TLSV:-0} (ok)";; x509) echo "notAfter=Dec 31 00:00:00 2030 GMT";; esac
STUB
printf '#!/usr/bin/env bash\ncat\n' >"$W/jq"; chmod +x "$W/curl" "$W/openssl" "$W/jq"   # stub poll output is already "<epoch> <message>"
wr() { : >"$PUBLOG"; : >"$W/sum"; ( unset MONITOR_LIB B0_EXPECT LOC SHOP_CODE SHOP_SERVER SCEN; PATH="$W:$PATH" MODE=$1 TLSV=${2:-0} PREV="${PREV:-}" NTFY_BASE=x DRILL_MON_BASE=t RETRY_GAP=0 GITHUB_STEP_SUMMARY="$W/sum" \
  B0_EXPECT=absent KEYLESS_PATH=/kl-secret CANARY_PATH='/shop/?filter_color=black' HB_PATH=/hb-secret.txt bash "$M" >"$W/out" 2>&1 ); echo $?; }
pubs() { grep -c . "$PUBLOG"; }; pubf() { cut -d'|' -f"$1" "$PUBLOG" | head -1; }
now() { date +%s; }
seq_prev() { PREV="$(now) $(cut -d'|' -f4 "$PUBLOG" | head -1)"; export PREV; }   # last published message becomes the topic state
# mk_prev "<age s> <message>" ... : topic state with one "<epoch> <message>" line per argument, oldest first
mk_prev() { PREV=; local a; for a in "$@"; do PREV+="$(( $(now) - ${a%% *} )) ${a#* }"$'\n'; done; PREV=${PREV%$'\n'}; export PREV; }
SECRETS='SECRETCOOKIEVALUE|SECRETHEADERVALUE|kl-secret|hb-secret|filter_color'

# ---- state 1: HEALTHY -------------------------------------------------------------------------------------------------------------
unset PREV
t healthy-exit-0 0 wr normal;               t healthy-no-publish 0 pubs;     t healthy-no-diag 0 grep -c '^diag ' "$W/out"
t healthy-no-xdiag 0 grep -c '^xdiag ' "$W/out";            t healthy-no-control-probe 0 grep -c '^control ' "$W/out"
t healthy-summary-all-pass 1 grep -c '^result: ALL PASS' "$W/sum"

# ---- state 2: CHALLENGE / INCONCLUSIVE (hosting challenge answered; first run of an episode) -----------------------------------------
t inconclusive-exit-0 0 wr challenge;       t inconclusive-one-publish 1 pubs
t inconclusive-marker-silent "AUREO monitor inconclusive|min" eval 'cut -d"|" -f2,3 "$PUBLOG" | head -1'
t inconclusive-marker-key "INCONCLUSIVE blocked:b0,cart-en,cart-it,checkout-en,checkout-it,collector-dead-man,p06-l3" eval 'pubf 4 | cut -d" " -f1-2'
t inconclusive-no-alert-prefix 0 grep -c -E '\|(ALERT|UNVERIFIED) ' "$PUBLOG"
t inconclusive-runner-ip 1 grep -c 'runner_ip=203.0.113.7' "$PUBLOG"
t inconclusive-summary-not-a-pass 0 grep -c 'ALL PASS' "$W/sum"
t inconclusive-summary-says-unverified 1 grep -c '^result: INCONCLUSIVE - STORE STATUS UNVERIFIED (not a shop failure, not a pass): blocked:' "$W/sum"
t inconclusive-warning-annotation 1 grep -c '^::warning title=AUREO monitor INCONCLUSIVE::' "$W/out"
t inconclusive-no-error-annotation 0 grep -c '^::error' "$W/out"
t inconclusive-diag-lines 7 grep -c '^diag .* verdict=blocked http=200 server=openresty origin=0 class=challenge' "$W/out"
t inconclusive-xdiag-lines 7 grep -c '^xdiag ' "$W/out"
t inconclusive-xdiag-fields 7 grep -c '^xdiag .* rip=198.51.100.4 hv=2 tconn=0.01 ttls=0.04 ctype=text/html_charset=UTF-8 date=Sat,_31_Oct_2026_08:00:37_GMT hdrs=content-type,date,server,set-cookie,x-imunify-test cookies=i360_wsid title=Please_wait..._Imunify360 flags=imunify360,reload,script$' "$W/out"
t inconclusive-no-values-or-paths 0 eval 'cat "$W/out" "$PUBLOG" "$W/sum" | grep -c -E "$SECRETS"'
t inconclusive-control-probes 2 grep -c '^control robots.txt ' "$W/out"
t inconclusive-control-same-for-both-uas 2 grep -c '^control robots.txt \(monitor-ua\|browser-ua\) http=200 server=openresty origin=0 class=challenge' "$W/out"
t inconclusive-summary-has-xdiag-and-control 9 grep -c -E '^- (xdiag|control) ' "$W/sum"
t uablock-exit-0 0 wr uablock
t uablock-browser-control-reaches-shop 1 grep -c '^control robots.txt browser-ua http=200 server=LiteSpeed origin=1 class=origin' "$W/out"
t uablock-monitor-control-blocked 1 grep -c '^control robots.txt monitor-ua .* class=challenge' "$W/out"

# ---- state 3: ORIGIN FAILURE (real shop problem): urgent push + failed run, unchanged --------------------------------------------------
unset PREV
t origin-failure-exit-1 1 wr cartdown;      t origin-failure-title "AUREO SALES/WALL ALERT" pubf 2;  t origin-failure-prio urgent pubf 3
t origin-failure-key "ALERT confirmed:cart-en cart-en:cart_http_500[confirmed];" eval 'pubf 4 | cut -d" " -f1-3'
t origin-failure-no-control-probe 0 grep -c '^control ' "$W/out"
t origin-failure-summary 1 grep -c '^result: confirmed:cart-en' "$W/sum"
t origin-failure-no-warning-annotation 0 grep -c '^::warning' "$W/out"
t run-collector-outage-exit-1 1 wr hbstale; t run-collector-outage-title "AUREO SALES/WALL ALERT" pubf 2
t run-collector-outage-key 1 grep -c '|ALERT confirmed:collector-dead-man collector-dead-man:collector_heartbeat_stale_50[0-9][0-9]s\[confirmed\]' "$PUBLOG"
t run-ambiguous-exit-1 1 wr ambiguous;      t run-ambiguous-title "AUREO MONITOR FAILURE - STORE STATUS UNVERIFIED" pubf 2; t run-ambiguous-prio urgent pubf 3
t run-ambiguous-key 1 grep -c '|ALERT ambiguous:b0,cart-en,cart-it,checkout-en,checkout-it,collector-dead-man,p06-l3 ' "$PUBLOG"
t run-proxy502-confirmed "AUREO SALES/WALL ALERT|urgent" eval 'wr proxy502 >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
t run-transport-confirmed "AUREO SALES/WALL ALERT|urgent" eval 'wr transport >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
t run-mixed-confirmed-wins "AUREO SALES/WALL ALERT|urgent" eval 'wr mixed >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
t run-mixed-detail 1 grep -c 'cart-en:cart_http_500\[confirmed\]; cart-it:cart_marker_missing\[blocked\];' "$PUBLOG"
t run-tls-verify-fail "ALERT confirmed:tls tls:tls_verify_failed_62[confirmed];" eval 'wr normal 62 >/dev/null; pubf 4 | cut -d" " -f1-3'

# ---- alert state machine ---------------------------------------------------------------------------------------------------------------
# confirmed incidents: recovery after every verdict class; the same incident is announced once per hour (one push, one failed run)
unset PREV; wr hbstale >/dev/null; seq_prev
t seq-collector-outage-then-recovered "AUREO RECOVERED|default|RECOVERED all checks pass" eval 'wr normal >/dev/null; cut -d"|" -f2-4 "$PUBLOG" | cut -d" " -f1-5'
unset PREV; wr hbstale >/dev/null; seq_prev
t seq-confirmed-repeat-exit-0 0 wr hbstale;  t seq-confirmed-repeat-no-publish 0 pubs
t seq-confirmed-repeat-logged 1 grep -c '^alert unchanged, not repeated' "$W/out"
t seq-confirmed-repeat-marked-ongoing 1 grep -c '^::error title=AUREO monitor ONGOING incident::confirmed:collector-dead-man' "$W/out"
t seq-confirmed-repeat-summary 1 grep -c '^result: ONGOING (alert sent [0-9]* s ago): confirmed:collector-dead-man' "$W/sum"
mk_prev "4000 ALERT confirmed:collector-dead-man x"
t seq-confirmed-repeats-after-60min-exit-1 1 wr hbstale;  t seq-confirmed-repeats-after-60min-publish 1 pubs
mk_prev "900 ALERT confirmed:cart-en x"
t seq-changed-key-publishes-again 1 eval 'wr hbstale >/dev/null; pubs'
unset PREV; wr ambiguous >/dev/null; seq_prev
t seq-ambiguous-then-recovered "AUREO RECOVERED|default" eval 'wr normal >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
PREV="$(now) ALERT cart-en,cart-it cart-en:cart_marker_missing; cart-it:cart_marker_missing; 2026-10-14T08:32:42Z"; export PREV
t seq-legacy-alert-then-recovered "AUREO RECOVERED|default" eval 'wr normal >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
PREV="$(now) RECOVERED all checks pass 2026-10-14T08:45:50Z"; export PREV
t seq-already-recovered-silent 0 eval 'wr normal >/dev/null; pubs'
# inconclusive episodes: silent markers, one push after 40 min of unbroken blindness, repeated at most every 3 h, cleared silently
mk_prev "900 INCONCLUSIVE blocked:x"
t episode-second-run-exit-0 0 wr challenge;  t episode-second-run-one-silent-marker "AUREO monitor inconclusive|min" eval 'cut -d"|" -f2,3 "$PUBLOG"'
t episode-second-run-logged-age 1 grep -c '^inconclusive recorded (episode 1[5-9] min old, silent, no failed-run mail)' "$W/out"
mk_prev "2700 INCONCLUSIVE blocked:x" "1800 INCONCLUSIVE blocked:x" "900 INCONCLUSIVE blocked:x"
t episode-escalates-exit-0 0 wr challenge;   t episode-escalates-one-push 1 pubs
t episode-escalates-title-prio "AUREO MONITOR ACCESS BLOCKED - STORE STATUS UNVERIFIED|high" eval 'cut -d"|" -f2,3 "$PUBLOG"'
t episode-escalates-message 1 grep -c '|UNVERIFIED blocked:.* unable to reach the shop for 4[5-9] min (hosting challenge layer answers it; not a shop failure, not a pass)' "$PUBLOG"
mk_prev "3600 INCONCLUSIVE blocked:x" "2700 INCONCLUSIVE blocked:x" "1800 UNVERIFIED blocked:x" "900 INCONCLUSIVE blocked:x"
t episode-escalation-not-repeated "AUREO monitor inconclusive|min" eval 'wr challenge >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
args=(); for a in $(seq 12600 -900 900); do k=INCONCLUSIVE; [ "$a" = 11700 ] && k=UNVERIFIED; args+=("$a $k blocked:x"); done; mk_prev "${args[@]}"
t episode-escalation-repeats-after-3h "AUREO MONITOR ACCESS BLOCKED - STORE STATUS UNVERIFIED|high" eval 'wr challenge >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
mk_prev "6000 INCONCLUSIVE blocked:x" "5100 INCONCLUSIVE blocked:x"
t episode-gap-starts-new-episode 1 eval 'wr challenge >/dev/null; grep -c "inconclusive recorded (episode new," "$W/out"'
mk_prev "2700 INCONCLUSIVE blocked:x" "1800 INCONCLUSIVE blocked:x" "900 RECOVERED all checks pass"
t episode-recovered-breaks-chain 1 eval 'wr challenge >/dev/null; grep -c "inconclusive recorded (episode new," "$W/out"'
mk_prev "1800 INCONCLUSIVE blocked:x" "900 INCONCLUSIVE blocked:x"
t episode-cleared-by-healthy-run "AUREO monitor check restored|min" eval 'wr normal >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
mk_prev "1800 INCONCLUSIVE blocked:x" "900 CLEARED all checks pass"
t episode-cleared-then-silent 0 eval 'wr normal >/dev/null; pubs'
mk_prev "1000 ALERT confirmed:cart-en x"
t episode-after-alert-no-false-recovery "AUREO monitor inconclusive|min" eval 'wr challenge >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
mk_prev "1000 ALERT confirmed:cart-en x" "500 INCONCLUSIVE blocked:x"
t episode-alert-still-recovers-after-inconclusive "AUREO RECOVERED|default" eval 'wr normal >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
mk_prev "900 INCONCLUSIVE blocked:x"
t episode-then-real-failure-is-urgent "AUREO SALES/WALL ALERT|urgent" eval 'wr cartdown >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
t episode-then-real-failure-exit-1 1 wr cartdown
unset PREV
wrd() { : >"$PUBLOG"; ( unset MONITOR_LIB B0_EXPECT LOC SHOP_CODE SHOP_SERVER SCEN; PATH="$W:$PATH" MODE=$1 MONITOR_DRY=1 NTFY_BASE=x DRILL_MON_BASE=drill RETRY_GAP=0 \
  B0_EXPECT=absent KEYLESS_PATH=/kl-secret CANARY_PATH='/shop/?filter_color=black' HB_PATH=/hb-secret.txt bash "$M" >"$W/out" 2>&1 ); echo $?; }
t dry-challenge-exit-0 0 wrd challenge;     t dry-challenge-no-publish 0 pubs
t dry-challenge-would-publish 1 grep -c '^dry run, not published: \[min\] AUREO monitor inconclusive | INCONCLUSIVE blocked:' "$W/out"
t dry-challenge-result 1 grep -c '^dry run result: INCONCLUSIVE - STORE STATUS UNVERIFIED' "$W/out"
t dry-normal-exit-0 0 wrd normal;           t dry-normal-result 1 grep -c '^dry run result: ALL PASS' "$W/out"
rm -rf "$W"
echo "pass $P fail $F"; [ "$F" = 0 ]
