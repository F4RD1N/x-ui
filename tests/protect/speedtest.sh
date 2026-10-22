#!/bin/bash
# Checks how "x-ui protect" stops speed-test servers and keeps them stopped,
# on throwaway units of its own (the real iperf3 is not touched).
#
#   sudo tests/protect/speedtest.sh [x-ui.sh]
set -euo pipefail

SCRIPT=$(readlink -f "${1:-$(dirname "$0")/../../x-ui.sh}")
[[ $EUID -eq 0 ]] || { echo "speedtest.sh needs root" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "speedtest.sh needs systemd" >&2; exit 1; }

lib=/usr/local/lib/systemd/system
etc=/etc/systemd/system
pkg=xui-speedtest-pkg-$$.service     # a packaged unit, enabled and running
own=xui-speedtest-own-$$.service     # hand-written in /etc/systemd/system: cannot be masked
admin=xui-speedtest-admin-$$.service # masked by the admin before
live=xui-speedtest-live-$$.service   # masked without --now: still running
rt=xui-speedtest-rt-$$.service       # enabled, runtime-masked (gone at boot)
gone=xui-speedtest-gone-$$.service   # not installed
cleanup() {
    for u in $pkg $own $admin $live $rt; do
        systemctl unmask --runtime "$u" >/dev/null 2>&1 || true
        systemctl unmask "$u" >/dev/null 2>&1 || true
        systemctl disable --now "$u" >/dev/null 2>&1 || true
        rm -rf "$lib/$u" "$etc/$u" "$etc/$u.d"
    done
    systemctl daemon-reload
}
trap cleanup EXIT
mkdir -p "$lib"
unit() {
    cat >"$1" <<EOF
[Unit]
Description=throwaway speed-test server for tests/protect/speedtest.sh
[Service]
ExecStart=/bin/sleep 600
[Install]
WantedBy=multi-user.target
EOF
}
unit "$lib/$pkg"; unit "$etc/$own"; unit "$lib/$admin"; unit "$lib/$live"; unit "$lib/$rt"
systemctl daemon-reload
systemctl enable --now "$pkg" "$own" "$rt" >/dev/null 2>&1
systemctl mask "$admin" >/dev/null 2>&1
systemctl start "$live" >/dev/null 2>&1; systemctl mask "$live" >/dev/null 2>&1
systemctl mask --runtime --now "$rt" >/dev/null 2>&1

# The functions under test, from the script itself.
LOGI() { :; }
eval "$(sed -n '/^protect_speedtest_held() {/,/^}/p; /^protect_speedtest_stopped() {/,/^}/p; /^protect_speedtest_stop() {/,/^}/p; /^protect_speedtest_summary() {/,/^}/p' "$SCRIPT")"
eval "$(grep -E '^protect_dropin=' "$SCRIPT")"
check0() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; exit 1; fi; }
check0 "setup: one masked but running ($(systemctl is-enabled $live)/$(systemctl is-active $live))" '[[ $(systemctl is-active $live) == active ]]'
protect_speedtest_units="$live"
check0 "  ...is not reported stopped ($(protect_speedtest_summary))" '[[ $(protect_speedtest_summary) == "${live%.service} held but RUNNING" ]]'
protect_speedtest_units="$pkg $own $admin $live $rt $gone"

rc=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; rc=1; fi; }
state() { echo "$(systemctl is-enabled "$1" 2>/dev/null)/$(systemctl is-active "$1" 2>/dev/null)"; }

protect_speedtest_stop
check "a packaged server is stopped and masked ($(state $pkg))" '[[ $(state $pkg) == masked/inactive ]]'
check "a hand-written one is stopped ($(state $own))" '[[ $(state $own) == */inactive ]]'
check "  ...and held back by a drop-in" '[[ -f $etc/$own.d/$protect_dropin ]]'
systemctl start "$own" >/dev/null 2>&1 || true
check "  ...so starting it again does not run it ($(state $own))" '[[ $(systemctl is-active $own) != active ]]'
check "one the admin masked stays masked ($(state $admin))" '[[ $(state $admin) == masked/inactive ]]'
check "one masked but running is stopped ($(state $live))" '[[ $(state $live) == masked/inactive ]]'
check "a runtime mask becomes a lasting one ($(state $rt))" '[[ $(state $rt) == masked/inactive ]]'
check "the summary says so ($(protect_speedtest_summary))" '[[ $(protect_speedtest_summary) == "${pkg%.service} stopped, ${own%.service} stopped, ${admin%.service} stopped, ${live%.service} stopped, ${rt%.service} stopped" ]]'
before=$(ls -la --time-style=+%s%N "$etc/$own.d/$protect_dropin")
protect_speedtest_stop
check "running it again changes nothing" '[[ $(ls -la --time-style=+%s%N "$etc/$own.d/$protect_dropin") == "$before" && $(state $pkg) == masked/inactive ]]'

protect_speedtest_units="$gone"
check "no speed-test server: \"$(protect_speedtest_summary)\"" '[[ $(protect_speedtest_summary) == "none here" ]]'
exit $rc
