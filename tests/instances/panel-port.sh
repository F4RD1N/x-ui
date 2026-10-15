#!/usr/bin/env bash
# Runs panel_port.py against a throwaway panel in its own network namespace:
# a panel port that connections or another program hold never takes x-ui
# and its cores down, and a new panel port is reserved and freed first.
# Nothing on the host panel is touched.
#
#   sudo tests/instances/panel-port.sh
#
# PANEL is the x-ui binary to test; by default it is built from this tree.
# XUI points at an installed or unpacked panel for xray and the geo files
# (default /usr/local/x-ui). The panel's "x-ui tune nic" runs against an
# empty fake root (XUI_TUNE_ROOT), never the host.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
XUI=${XUI:-/usr/local/x-ui}
NS=xuiexp$$
T=$(mktemp -d /tmp/xuipp.XXXX)
cleanup() { ip netns pids "$NS" 2>/dev/null | xargs -r kill -9; ip netns del "$NS" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
if [ -z "${PANEL:-}" ]; then
    (cd "$HERE/../.." && nice -n 10 go build -p 2 -o "$T/x-ui" .)
    PANEL="$T/x-ui"
fi
ip netns add "$NS"
ip -n "$NS" link set lo up
ip -n "$NS" link add dummy0 type dummy
ip -n "$NS" addr add 1.2.3.4/32 dev dummy0
ip -n "$NS" link set dummy0 up
mkdir -p "$T/bin" "$T/db" "$T/log" "$T/tune-root"
ln -s "$XUI/bin/xray-linux-amd64" "$T/bin/"
for g in geoip.dat geosite.dat; do ln -s "$XUI/bin/$g" "$T/bin/"; done
export XUI_DB_FOLDER="$T/db" XUI_BIN_FOLDER="$T/bin" XUI_LOG_FOLDER="$T/log" XUI_TUNE_ROOT="$T/tune-root"
ip netns exec "$NS" "$PANEL" setting -username t -password t -port 2053 -webBasePath /t/ >/dev/null
cd "$T"
ip netns exec "$NS" env PANEL="$PANEL" T="$T" python3 "$HERE/panel_port.py"
