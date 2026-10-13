#!/usr/bin/env bash
# Offline tests for the external monitor's B0 checks (plan 21a9d291 G6). A stub curl serves canned responses; no network.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); M="$HERE/../monitor.sh"; T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cat >"$T/curl" <<'STUB'
#!/usr/bin/env bash
# args: ... -o BODY -D HDRS -w FMT ... URL ; scenario in $SCEN: code|wall|l3|bodyfile-kind
o=; D=; U=; while [ $# -gt 0 ]; do case "$1" in -o) o=$2; shift;; -D) D=$2; shift;; -w|-m|-A|-H|-d) shift;; *) U=$1;; esac; shift; done
IFS='|' read -r code wall l3 kind ttfb <<<"$SCEN"
case "$U" in */shop/) code=${SHOP_CODE:-200}; wall=; l3=; kind=page;; esac
{ printf 'HTTP/1.1 %s X\r\n' "$code"; [ -n "$wall" ] && printf 'X-Aureo-Wall: %s\r\n' "$wall"; [ -n "$l3" ] && printf 'X-Aureo-L3: %s\r\n' "$l3"; } >"$D"
case "$kind" in chal) printf '<script>document.cookie="aureo_fv=1";location.reload()</script>%0900s' x >"$o";;
  page) { echo '<html>'; head -c 2500 /dev/zero | tr '\0' a; echo '</html>'; } >"$o";; deny) echo '<h1>503</h1>' >"$o";; *) : >"$o";; esac
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
echo "pass $P fail $F"; [ "$F" = 0 ]
