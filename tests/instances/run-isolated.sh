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
#
# The panel's "x-ui tune nic" runs against an empty fake root (XUI_TUNE_ROOT),
# never the host. FAKE_TOPO=1 shows the panel a fake CPU topology instead of
# the host's (XUI_HW_ROOT), a miniature of a two-socket server: node 0 the
# even CPUs, node 1 the odd ones, siblings n and n+N/2 (N CPUs, a multiple
# of 4: on 8, cores 0/4, 2/6, 1/5 and 3/7).
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
mkdir -p "$T/bin" "$T/db" "$T/log" "$T/tune-root"
ln -s "$XUI/bin/xray-linux-amd64" "$T/bin/"
for g in geoip.dat geosite.dat; do ln -s "$XUI/bin/$g" "$T/bin/"; done
export XUI_DB_FOLDER="$T/db" XUI_BIN_FOLDER="$T/bin" XUI_LOG_FOLDER="$T/log" XUI_TUNE_ROOT="$T/tune-root"
if [ -n "${FAKE_TOPO:-}" ]; then
    N=$(getconf _NPROCESSORS_ONLN)
    if [ "$(cat /sys/devices/system/cpu/online)" != "0-$((N - 1))" ] || [ $((N % 4)) -ne 0 ]; then
        echo "FAKE_TOPO needs CPUs 0 to N-1 online, N a multiple of 4" >&2
        exit 1
    fi
    H="$T/hw" C="$T/hw/sys/devices/system/cpu" D="$T/hw/sys/devices/system/node"
    mkdir -p "$C" "$D/node0" "$D/node1" "$H/proc"
    echo "0-$((N - 1))" >"$C/online"
    nodes=("" "")
    for c in $(seq 0 $((N - 1))); do
        s=$(((c + N / 2) % N)) n=$((c % 2))
        mkdir -p "$C/cpu$c/topology"
        echo "$((c < s ? c : s)),$((c < s ? s : c))" >"$C/cpu$c/topology/core_cpus_list"
        echo "$n" >"$C/cpu$c/topology/physical_package_id"
        nodes[n]="${nodes[n]}${nodes[n]:+,}$c"
    done
    mem=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
    for n in 0 1; do
        echo "${nodes[n]}" >"$D/node$n/cpulist"
        echo "Node $n MemTotal: $((mem / 2)) kB" >"$D/node$n/meminfo"
    done
    echo "10 21" >"$D/node0/distance"
    echo "21 10" >"$D/node1/distance"
    cp /proc/meminfo "$H/proc/meminfo"
    export XUI_HW_ROOT="$H"
fi
ip netns exec "$NS" "$XUI/x-ui" setting -username t -password t -port 2053 -webBasePath /t/ >/dev/null
(cd "$T" && ip netns exec "$NS" "$XUI/x-ui" run >"$T/panel.log" 2>&1 &)
for i in $(seq 1 50); do ip netns exec "$NS" curl -s -o /dev/null http://127.0.0.1:2053/t/ && break; sleep 0.2; done
echo "isolated panel up in $NS ($T)"
ip netns exec "$NS" env PANEL=http://127.0.0.1:2053/t XUI_USER=t XUI_PASS=t TARGET=1.2.3.4 \
    XRAY="$T/bin/xray-linux-amd64" BINPREFIX="$T/bin" BASELINE=1 FAKE_TOPO="${FAKE_TOPO:-}" python3 "$HERE/e2e.py"
if [ -n "${UI:-}" ]; then
    SHOTS=${SHOTS:-/tmp/xui-instances-shots}
    mkdir -p "$SHOTS"
    ip netns exec "$NS" env NODE_PATH="${NODE_PATH:-}" CHROME="${CHROME:-}" \
        node "$HERE/ui.js" http://127.0.0.1:2053/t t t "$SHOTS"
    echo "screenshots in $SHOTS"
fi
