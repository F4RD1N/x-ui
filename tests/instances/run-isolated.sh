#!/usr/bin/env bash
# Runs e2e.py (and, with UI=1, the browser test ui.js) against a throwaway
# panel in its own network namespace, with its own database and the default
# xray template. Nothing on the host panel is touched.
#
#   sudo tests/instances/run-isolated.sh                 # API, traffic, load
#   UI=1 CHROME=/path/to/chrome sudo -E tests/instances/run-isolated.sh
#
# XUI points at an installed or unpacked panel (default /usr/local/x-ui).
# The browser test needs node with playwright (NODE_PATH).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
XUI=${XUI:-/usr/local/x-ui}
NS=xuit$$
T=$(mktemp -d /tmp/xuit.XXXX)
cleanup() { ip netns pids "$NS" 2>/dev/null | xargs -r kill -9; ip netns del "$NS" 2>/dev/null || true; rm -rf "$T"; }
trap cleanup EXIT
ip netns add "$NS"
ip -n "$NS" link set lo up
ip -n "$NS" link add dummy0 type dummy
ip -n "$NS" addr add 1.2.3.4/32 dev dummy0
ip -n "$NS" link set dummy0 up
mkdir -p "$T/bin" "$T/db" "$T/log"
ln -s "$XUI/bin/xray-linux-amd64" "$T/bin/"
for g in geoip.dat geosite.dat; do ln -s "$XUI/bin/$g" "$T/bin/"; done
export XUI_DB_FOLDER="$T/db" XUI_BIN_FOLDER="$T/bin" XUI_LOG_FOLDER="$T/log"
ip netns exec "$NS" "$XUI/x-ui" setting -username t -password t -port 2053 -webBasePath /t/ >/dev/null
(cd "$T" && ip netns exec "$NS" "$XUI/x-ui" run >"$T/panel.log" 2>&1 &)
for i in $(seq 1 50); do ip netns exec "$NS" curl -s -o /dev/null http://127.0.0.1:2053/t/ && break; sleep 0.2; done
echo "isolated panel up in $NS ($T)"
ip netns exec "$NS" env PANEL=http://127.0.0.1:2053/t XUI_USER=t XUI_PASS=t TARGET=1.2.3.4 \
    XRAY="$T/bin/xray-linux-amd64" BINPREFIX="$T/bin" BASELINE=1 python3 "$HERE/e2e.py"
if [ -n "${UI:-}" ]; then
    SHOTS=${SHOTS:-/tmp/xui-instances-shots}
    mkdir -p "$SHOTS"
    ip netns exec "$NS" env NODE_PATH="${NODE_PATH:-}" CHROME="${CHROME:-}" \
        node "$HERE/ui.js" http://127.0.0.1:2053/t t t "$SHOTS"
    echo "screenshots in $SHOTS"
fi
