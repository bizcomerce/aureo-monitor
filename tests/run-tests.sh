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
o=/dev/null; D=/dev/null; w=; d=; U=; ti=; pr=
while [ $# -gt 0 ]; do case "$1" in -o) o=$2; shift;; -D) D=$2; shift;; -w) w=$2; shift;; -d) d=$2; shift;;
  -H) case "$2" in Title:*) ti=${2#Title: };; Priority:*) pr=${2#Priority: };; esac; shift;; -m|-A) shift;; -*) ;; *) U=$1;; esac; shift; done
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
  mixed) if [ "$q" = /cart/ ]; then code=500 kind=empty; else code=200 srv=openresty kind=wsc loc= l3=; fi;; esac
{ printf 'HTTP/1.1 %s X\r\nServer: %s\r\n' "$code" "$srv"; [ -n "$loc" ] && printf 'Location: %s\r\n' "$loc"; [ -n "$l3" ] && printf 'X-Aureo-L3: %s\r\n' "$l3"; } >"$D"
case "$kind" in cart) { echo '<body class="woocommerce-cart">'; head -c 3000 /dev/zero | tr '\0' a; } >"$o";;
  shop) { echo '<link href="/wp-content/x.css">'; head -c 3000 /dev/zero | tr '\0' a; } >"$o";;
  wsc) { echo '<script>setTimeout(function(){location.reload()},1500)</script>'; head -c 11900 /dev/zero | tr '\0' b; } >"$o";;
  park) { echo '<html>Parked domain</html>'; head -c 3000 /dev/zero | tr '\0' c; } >"$o";;
  hb) date +%s >"$o";; hbold) echo $(( $(date +%s) - 5000 )) >"$o";; *) : >"$o";; esac
[ -n "$w" ] && printf '%s 0.1 0.2' "$code"; exit 0
STUB
cat >"$W/openssl" <<'STUB'
#!/usr/bin/env bash
cat >/dev/null; case "$1" in s_client) echo "    Verify return code: ${TLSV:-0} (ok)";; x509) echo "notAfter=Dec 31 00:00:00 2030 GMT";; esac
STUB
printf '#!/usr/bin/env bash\ncat\n' >"$W/jq"; chmod +x "$W/curl" "$W/openssl" "$W/jq"   # stub poll output is already "<epoch> <message>"
wr() { : >"$PUBLOG"; ( unset MONITOR_LIB B0_EXPECT LOC SHOP_CODE SHOP_SERVER SCEN; PATH="$W:$PATH" MODE=$1 TLSV=${2:-0} PREV="${PREV:-}" NTFY_BASE=x DRILL_MON_BASE=t RETRY_GAP=0 \
  B0_EXPECT=absent KEYLESS_PATH=/kl-secret CANARY_PATH='/shop/?filter_color=black' HB_PATH=/hb-secret.txt bash "$M" >"$W/out" 2>&1 ); echo $?; }
pubs() { grep -c . "$PUBLOG"; }; pubf() { cut -d'|' -f"$1" "$PUBLOG" | head -1; }
t run-normal-exit-0 0 wr normal;            t run-normal-no-publish 0 pubs;  t run-normal-no-diag 0 grep -c '^diag ' "$W/out"
t run-challenge-exit-1 1 wr challenge;      t run-challenge-one-publish 1 pubs
t run-challenge-title "AUREO MONITOR ACCESS BLOCKED - STORE STATUS UNVERIFIED" pubf 2; t run-challenge-prio high pubf 3
t run-challenge-key "ALERT blocked:b0,cart-en,cart-it,checkout-en,checkout-it,collector-dead-man,p06-l3 STORE STATUS UNVERIFIED:" eval 'pubf 4 | cut -d" " -f1-5'
t run-challenge-runner-ip 1 grep -c 'runner_ip=203.0.113.7' "$PUBLOG"
t run-challenge-diag-lines 7 grep -c '^diag .* verdict=blocked http=200 server=openresty origin=0 class=challenge' "$W/out"
t run-challenge-no-secret-paths 0 eval 'cat "$W/out" "$PUBLOG" | grep -c -E "kl-secret|hb-secret|filter_color"'
t run-cartdown-exit-1 1 wr cartdown;        t run-cartdown-title "AUREO SALES/WALL ALERT" pubf 2; t run-cartdown-prio urgent pubf 3
t run-cartdown-key "ALERT confirmed:cart-en cart-en:cart_http_500[confirmed];" eval 'pubf 4 | cut -d" " -f1-3'
t run-collector-outage-exit-1 1 wr hbstale; t run-collector-outage-title "AUREO SALES/WALL ALERT" pubf 2
t run-collector-outage-key 1 grep -c '|ALERT confirmed:collector-dead-man collector-dead-man:collector_heartbeat_stale_50[0-9][0-9]s\[confirmed\]' "$PUBLOG"
t run-ambiguous-exit-1 1 wr ambiguous;      t run-ambiguous-title "AUREO MONITOR FAILURE - STORE STATUS UNVERIFIED" pubf 2; t run-ambiguous-prio urgent pubf 3
t run-ambiguous-key 1 grep -c '|ALERT ambiguous:b0,cart-en,cart-it,checkout-en,checkout-it,collector-dead-man,p06-l3 STORE STATUS UNVERIFIED' "$PUBLOG"
t run-proxy502-confirmed "AUREO SALES/WALL ALERT|urgent" eval 'wr proxy502 >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
t run-transport-confirmed "AUREO SALES/WALL ALERT|urgent" eval 'wr transport >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
t run-mixed-confirmed-wins "AUREO SALES/WALL ALERT|urgent" eval 'wr mixed >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
t run-mixed-detail 1 grep -c 'cart-en:cart_http_500\[confirmed\]; cart-it:cart_marker_missing\[blocked\];' "$PUBLOG"
t run-tls-verify-fail "ALERT confirmed:tls tls:tls_verify_failed_62[confirmed];" eval 'wr normal 62 >/dev/null; pubf 4 | cut -d" " -f1-3'
# Alert state machine (unchanged code path): recovery after every verdict class, no repeat of an unchanged alert, escalation
now() { date +%s; }
seq_prev() { PREV="$(now) $(cut -d'|' -f4 "$PUBLOG" | head -1)"; export PREV; }   # last published message becomes the topic state
unset PREV; wr hbstale >/dev/null; seq_prev
t seq-collector-outage-then-recovered "AUREO RECOVERED|default|RECOVERED all checks pass" eval 'wr normal >/dev/null; cut -d"|" -f2-4 "$PUBLOG" | cut -d" " -f1-5'
unset PREV; wr challenge >/dev/null; seq_prev
t seq-blocked-unchanged-not-repeated 0 eval 'wr challenge >/dev/null; pubs'
t seq-blocked-unchanged-logged 1 grep -c '^alert unchanged, not repeated' "$W/out"
t seq-blocked-escalates-to-confirmed "AUREO SALES/WALL ALERT|urgent" eval 'wr mixed >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
t seq-blocked-then-recovered "AUREO RECOVERED|default" eval 'wr normal >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
unset PREV; wr ambiguous >/dev/null; seq_prev
t seq-ambiguous-then-recovered "AUREO RECOVERED|default" eval 'wr normal >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
PREV="$(now) ALERT cart-en,cart-it cart-en:cart_marker_missing; cart-it:cart_marker_missing; 2026-10-14T08:32:42Z"; export PREV
t seq-legacy-alert-then-recovered "AUREO RECOVERED|default" eval 'wr normal >/dev/null; cut -d"|" -f2,3 "$PUBLOG"'
PREV="$(now) RECOVERED all checks pass 2026-10-14T08:45:50Z"; export PREV
t seq-already-recovered-silent 0 eval 'wr normal >/dev/null; pubs'
PREV="$(( $(now) - 4000 )) ALERT blocked:b0,cart-en,cart-it,checkout-en,checkout-it,collector-dead-man,p06-l3 x"; export PREV
t seq-unchanged-alert-repeats-after-60min 1 eval 'wr challenge >/dev/null; pubs'
unset PREV
wrd() { : >"$PUBLOG"; ( unset MONITOR_LIB B0_EXPECT LOC SHOP_CODE SHOP_SERVER SCEN; PATH="$W:$PATH" MODE=$1 MONITOR_DRY=1 NTFY_BASE=x DRILL_MON_BASE=drill RETRY_GAP=0 \
  B0_EXPECT=absent KEYLESS_PATH=/kl-secret CANARY_PATH='/shop/?filter_color=black' HB_PATH=/hb-secret.txt bash "$M" >"$W/out" 2>&1 ); echo $?; }
t dry-challenge-exit-0 0 wrd challenge;     t dry-challenge-no-publish 0 pubs
t dry-challenge-would-publish 1 grep -c '^dry run, not published: \[high\] AUREO MONITOR ACCESS BLOCKED - STORE STATUS UNVERIFIED | ALERT blocked:' "$W/out"
t dry-normal-exit-0 0 wrd normal;           t dry-normal-result 1 grep -c '^dry run result: ALL PASS' "$W/out"
rm -rf "$W"
echo "pass $P fail $F"; [ "$F" = 0 ]
