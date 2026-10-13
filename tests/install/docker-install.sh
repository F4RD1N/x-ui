#!/bin/bash
# Fresh-install test of install.sh in throwaway systemd containers.
#
#   tests/install/docker-install.sh <x-ui-linux-amd64.tar.gz> [debian12] [ubuntu2404]
#
# For each distribution it builds a small image with systemd (from the stock
# base image, which is kept), boots it as an unprivileged container with its
# own cgroup namespace, and runs the repository's install.sh against the
# given release tarball (XUI_LOCAL_TARBALL). Then it checks:
#
#   - the panel answers on :60000/hetzner/ and fardin/fardin logs in;
#   - x-ui.service is active with TasksMax=infinity and KillMode=mixed, and
#     the panel and every core run with the expected open-file limit;
#   - the tuning drop-in exists with its header and the GOMEMLIMIT computed
#     for the container's 1 GiB cgroup (not the host's RAM), and no sysctl
#     file is written, the container's /proc/sys being read-only -- which is
#     reported, not fatal;
#   - a second install changes nothing; "x-ui update" (through x-ui.sh, with
#     GitHub replaced by a local shim) keeps a changed login, port and path;
#   - "x-ui tune revert" removes the tuning and keeps it off through an
#     update, "x-ui tune apply" brings it back;
#   - a broken tarball in update mode leaves the running panel untouched;
#     bad arguments and an unsupported CPU are refused before anything changes;
#   - the install ends with the "Detected:/Configured:" summary, which says
#     the container's NIC is left to the host; "x-ui diag" and its --json run
#     (the JSON parses), no NIC unit or irqbalance drop-in is written, and
#     "x-ui tune queues --now" says so too and exits 0;
#   - a restart takes well under TimeoutStopSec and logs no core crash;
#   - uninstall leaves no tuning files behind.
#
# Containers are never privileged and never see the host's cgroups; every
# container and test image is removed at the end.
set -uo pipefail

TARBALL=$(readlink -f "${1:?usage: docker-install.sh <tarball> [debian12] [ubuntu2404]}")
shift
DISTROS=("$@")
(( ${#DISTROS[@]} )) || DISTROS=(debian12 ubuntu2404)
REPO=$(cd "$(dirname "$0")/../.." && pwd)
RAND=$RANDOM
CONTAINERS=() IMAGES=()
PASS=0 FAILS=()

cleanup() {
    for c in "${CONTAINERS[@]}"; do docker rm -f "$c" >/dev/null 2>&1; done
    for i in "${IMAGES[@]}"; do docker rmi -f "$i" >/dev/null 2>&1; done
}
trap cleanup EXIT

ok()   { PASS=$((PASS + 1)); echo "  ok   $*"; }
not()  { ! "$@"; }
bad()  { FAILS+=("$DISTRO: $*"); echo "  FAIL $*"; }
check() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
in_c() { docker exec "$C" bash -c "$1"; }

base_image() {
    case "$1" in
        debian12)   echo debian:bookworm-slim ;;
        ubuntu2404) echo ubuntu:24.04 ;;
        *) echo "unknown distribution $1" >&2; return 1 ;;
    esac
}

build_image() {
    local base=$1 tag=$2
    # Only systemd and what a minimal VPS has; curl, tzdata and certificates
    # are left for install.sh to install.
    docker build -q -t "$tag" - >/dev/null <<EOF
FROM $base
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv procps iproute2 kmod >/dev/null && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
}

login() { # port path user pass -> 0 when the panel accepts the login
    in_c "curl -fsS -m 10 -d 'username=$3&password=$4' http://127.0.0.1:$1/$2/login" 2>/dev/null | grep -q '"success":true'
}

wait_active() {
    local i
    for i in $(seq 1 20); do
        in_c "systemctl is-active --quiet x-ui" && return 0
        sleep 1
    done
    return 1
}

# add_inbound creates a VLESS inbound on 8443 through the panel's API, so
# that a core runs.
add_inbound() {
    docker exec -i "$C" bash -s <<'SH'
set -e
B=http://127.0.0.1:60000/hetzner
curl -fsS -m 10 -c /root/jar -d 'username=fardin&password=fardin' $B/login >/dev/null
curl -fsS -m 30 -b /root/jar $B/panel/api/inbounds/add \
  -d up=0 -d down=0 -d total=0 -d remark=t1 -d enable=true -d expiryTime=0 \
  -d trafficReset=never -d lastTrafficResetTime=0 -d xrayInstance= -d xrayCores=0 \
  -d listen= -d port=8443 -d protocol=vless \
  --data-urlencode 'settings={"clients":[{"id":"0b0b7a5e-8c7a-4e0f-9a51-6c0a3f1f7d10","email":"t1","flow":"","limitIp":0,"totalGB":0,"expiryTime":0,"enable":true,"tgId":"","subId":"abcd1234abcd1234","reset":0}],"decryption":"none","fallbacks":[]}' \
  --data-urlencode 'streamSettings={"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}' \
  --data-urlencode 'sniffing={"enabled":false}' | grep -q '"success":true'
for _ in $(seq 1 20); do ss -ltn | grep -q ':8443 ' && exit 0; sleep 1; done
exit 1
SH
}

# diag_json: "x-ui diag --json" parses (with the host's python3; the test
# images have none).
diag_json() {
    in_c 'x-ui diag --json --seconds 1' | python3 -m json.tool >/dev/null
}

wait_panel() { # port path
    local i
    for i in $(seq 1 20); do
        in_c "curl -fsS -m 3 -o /dev/null http://127.0.0.1:$1/$2/" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

run_distro() {
    DISTRO=$1
    local base tag
    base=$(base_image "$DISTRO") || return 1
    tag="xui-install-test-$DISTRO:$RAND"
    echo "== $DISTRO ($base)"
    if ! build_image "$base" "$tag"; then bad "image build"; return; fi
    IMAGES+=("$tag")
    C="xui-install-$DISTRO-$RAND"
    CONTAINERS+=("$C")
    docker run -d --name "$C" --cgroupns=private --security-opt writable-cgroups=true \
        --tmpfs /run --tmpfs /run/lock --tmpfs /tmp --memory 1g --cpus 1 \
        -v "$TARBALL:/x-ui.tar.gz:ro" -v "$REPO/install.sh:/install.sh:ro" \
        "$tag" >/dev/null || { bad "container start"; return; }
    # Wait for the boot to finish (running, or degraded: some units cannot
    # start in a container), so nothing mounts over /tmp mid-test.
    in_c 'for _ in $(seq 1 60); do s=$(systemctl is-system-running 2>/dev/null); [[ $s == running || $s == degraded ]] && exit 0; sleep 1; done; exit 0'
    check "systemd booted as PID 1" in_c '[[ $(cat /proc/1/comm) == systemd ]] && [[ -d /run/systemd/system ]]'

    # ---- refused before anything changes ------------------------------------
    check "port=70000 refused" in_c '! XUI_LOCAL_TARBALL=/x-ui.tar.gz bash /install.sh port=70000 >/root/o 2>&1 && grep -q "1 to 65535" /root/o && [[ ! -e /usr/local/x-ui ]]'
    check "empty user refused" in_c '! XUI_LOCAL_TARBALL=/x-ui.tar.gz bash /install.sh user= >/dev/null 2>&1 && [[ ! -e /usr/local/x-ui ]]'
    check "update without an install refused" in_c '! XUI_MODE=update XUI_LOCAL_TARBALL=/x-ui.tar.gz bash /install.sh >/root/o 2>&1 && grep -q "Nothing to update" /root/o'
    check "unsupported CPU refused" in_c 'mkdir -p /root/shim && printf "#!/bin/sh\necho armv7l\n" >/root/shim/uname && chmod +x /root/shim/uname &&
        ! PATH=/root/shim:$PATH XUI_LOCAL_TARBALL=/x-ui.tar.gz bash /install.sh >/root/o 2>&1 && grep -q "Unsupported architecture: armv7l" /root/o && [[ ! -e /usr/local/x-ui ]]'

    # ---- fresh install -------------------------------------------------------
    if ! in_c 'XUI_LOCAL_TARBALL=/x-ui.tar.gz bash /install.sh >/root/install1.log 2>&1'; then
        bad "fresh install (rc != 0)"; in_c 'tail -30 /root/install1.log'; return
    fi
    ok "fresh install"
    check "x-ui.service active" wait_active
    check "panel answers on :60000/hetzner/" wait_panel 60000 hetzner
    check "login fardin/fardin" login 60000 hetzner fardin fardin
    check "wrong password refused" not login 60000 hetzner fardin nope
    check "inbound added, its core listens on 8443" add_inbound
    check "x-ui diag runs and finds the core" in_c 'x-ui diag --seconds 1 >/root/diag.txt 2>&1 && grep -q "^Hardware" /root/diag.txt && grep -q "^  xray-1 " /root/diag.txt'
    check "x-ui diag --json parses" diag_json
    check "read-only sysctls reported, not fatal" in_c 'grep -q "kernel settings are read-only" /root/install1.log'
    check "summary has a tuning line" in_c 'grep -q "Tuning:   applied" /root/install1.log'
    check "install prints Detected: and Configured:" in_c 'grep -q "^  Detected:" /root/install1.log && grep -q "^  Configured:" /root/install1.log'
    check "summary leaves the NIC to the host" in_c 'grep -q "NIC: left to the host (container)" /root/install1.log'
    check "no NIC unit, no irqbalance drop-in" in_c '[[ ! -e /etc/systemd/system/x-ui-nic.service && ! -e /etc/systemd/system/irqbalance.service.d/90-x-ui.conf ]]'
    check "'tune queues --now' leaves the NIC to the host, exit 0" in_c 'x-ui tune queues --now >/root/q 2>&1 && grep -q "skipped: NIC: left to the host (container)" /root/q && ! grep -q "bus" /root/q'
    check "deps installed by install.sh" in_c 'command -v curl >/dev/null && [[ -e /usr/share/zoneinfo/UTC ]]'

    local props
    props=$(in_c 'systemctl show x-ui -p TasksMax -p KillMode -p LimitNOFILE -p Restart -p After')
    check "TasksMax=infinity" grep -q '^TasksMax=infinity' <<<"$props"
    check "KillMode=mixed" grep -q '^KillMode=mixed' <<<"$props"
    check "Restart=always" grep -q '^Restart=always' <<<"$props"
    check "After=network-online.target" grep -q 'network-online.target' <<<"$props"

    # Open files: the unit asks for 1048576; in a container systemd caps it at
    # PID 1's hard limit. The panel and every core must have that.
    local want
    want=$(in_c "awk '/Max open files/{print \$5}' /proc/1/limits")
    (( want > 1048576 )) && want=1048576
    check "open-file limit $want for the panel and its cores" in_c "
        pids=\$(cat /sys/fs/cgroup\$(systemctl show -p ControlGroup --value x-ui)/cgroup.procs)
        n=0; for p in \$pids; do
            l=\$(awk '/Max open files/{print \$5}' /proc/\$p/limits); [[ \$l == $want ]] || exit 1; n=\$((n+1))
        done; (( n >= 2 ))"
    check "cores run with oom_score_adj 0" in_c '
        for p in $(pgrep -f xray-linux); do [[ $(cat /proc/$p/oom_score_adj) == 0 ]] || exit 1; done; pgrep -f xray-linux >/dev/null'

    local drop=/etc/systemd/system/x-ui.service.d/20-x-ui-tuning.conf
    check "tuning drop-in with header" in_c "head -1 $drop | grep -q '^# Written by x-ui tune'"
    check "GOMEMLIMIT sized for the 1 GiB cgroup (504MiB), no GOGC" in_c "grep -qx 'Environment=GOMEMLIMIT=504MiB' $drop && ! grep -q GOGC $drop"
    check "ExecStartPre re-applies at start" in_c "grep -qx 'ExecStartPre=-/usr/local/x-ui/x-ui tune apply --boot' $drop"
    check "no sysctl file (all read-only here)" in_c '[[ ! -e /etc/sysctl.d/51-x-ui.conf ]]'
    check "status --json: every key read-only or missing" in_c '
        x-ui tune status --json > /root/st.json && grep -q "\"sysctl\"" /root/st.json &&
        ! grep -o "\"state\": \"[^\"]*\"" /root/st.json | grep -v "\"read-only\"\|\"missing\"\|\"applied\""'
    check "host services skipped in a container" in_c '[[ ! -e /var/lib/x-ui/swapfile ]] && ! grep -q "\"enabled\"\|\"ntp_via" /var/lib/x-ui/tune/state.json'

    # ---- idempotent second run ----------------------------------------------
    local m1 m2
    m1=$(in_c "stat -c %Y $drop")
    sleep 1
    check "second install succeeds" in_c 'XUI_LOCAL_TARBALL=/x-ui.tar.gz bash /install.sh >/root/install2.log 2>&1'
    m2=$(in_c "stat -c %Y $drop")
    check "second install leaves the drop-in alone" test "$m1" = "$m2"
    check "second run: tuning has nothing to change" in_c 'grep -q "nothing to change" /root/install2.log'
    check "x-ui tune apply is idempotent" in_c 'x-ui tune apply | grep -q "nothing to change"'

    # ---- update keeps a changed login (through x-ui.sh, GitHub shimmed) -------
    in_c '/usr/local/x-ui/x-ui setting -username bob -password S3cret -port 61000 -webBasePath secretpath >/dev/null && systemctl restart x-ui'
    wait_panel 61000 secretpath
    in_c 'cat > /usr/local/bin/curl <<"SH"
#!/bin/bash
out=""; url=""
while (( $# )); do case "$1" in -o) out=$2; shift 2;; http*) url=$1; shift;; *) shift;; esac; done
case "$url" in
  *raw.githubusercontent.com*/install.sh) cp /install.sh "$out";;
  *api.github.com*) echo "{\"tag_name\": \"v9.9.9-test\"}";;
  *) exit 22;;
esac
SH
chmod +x /usr/local/bin/curl'
    check "x-ui update (CLI) succeeds" in_c 'echo y | XUI_LOCAL_TARBALL=/x-ui.tar.gz x-ui update >/root/update.log 2>&1'
    in_c 'rm -f /usr/local/bin/curl'
    check "update ran install.sh in update mode" in_c 'grep -q "keeping the existing username" /root/update.log'
    check "panel back on :61000/secretpath/" wait_panel 61000 secretpath
    check "changed login kept by the update" login 61000 secretpath bob S3cret
    check "defaults not re-applied" not login 61000 secretpath fardin fardin
    check "the inbound's core runs again after the update" in_c 'for _ in $(seq 1 20); do ss -ltn | grep -q ":8443 " && exit 0; sleep 1; done; exit 1'

    # ---- a dropped geo download leaves the live files alone ------------------
    in_c 'cat > /usr/local/bin/curl <<"SH"
#!/bin/bash
out=""; while (( $# )); do case "$1" in -o) out=$2; shift 2;; *) shift;; esac; done
[[ -n "$out" ]] && head -c 300000 /dev/zero > "$out"
exit 18
SH
chmod +x /usr/local/bin/curl'
    local g1 g2 gpid1 gpid2
    g1=$(in_c 'sha256sum /usr/local/x-ui/bin/geoip.dat')
    gpid1=$(in_c 'systemctl show -p MainPID --value x-ui')
    check "failed geo update reports failure" in_c '! x-ui update-all-geofiles >/root/geo.log 2>&1 && grep -q "current file is kept" /root/geo.log'
    in_c 'rm -f /usr/local/bin/curl'
    g2=$(in_c 'sha256sum /usr/local/x-ui/bin/geoip.dat')
    gpid2=$(in_c 'systemctl show -p MainPID --value x-ui')
    check "geo files intact, no partial file, no restart" test "$g1" = "$g2" -a "$gpid1" = "$gpid2"
    check "no leftover download" in_c '! ls /usr/local/x-ui/bin/*.download >/dev/null 2>&1'

    # ---- a broken release in update mode changes nothing ---------------------
    in_c 'head -c 4000000 /x-ui.tar.gz > /root/broken.tar.gz'
    local pid1 pid2
    pid1=$(in_c 'systemctl show -p MainPID --value x-ui')
    check "broken tarball refused" in_c '! XUI_MODE=update XUI_LOCAL_TARBALL=/root/broken.tar.gz bash /install.sh >/root/o 2>&1'
    pid2=$(in_c 'systemctl show -p MainPID --value x-ui')
    check "running panel untouched by the failed update" test "$pid1" = "$pid2"
    check "installed files intact" in_c '[[ -x /usr/local/x-ui/x-ui && -x /usr/local/x-ui/bin/xray-linux-amd64 && ! -e /usr/local/x-ui.old ]] && ! ls -d /usr/local/.x-ui-stage.* >/dev/null 2>&1'

    # ---- restart is quick and clean -----------------------------------------
    local t0 t1
    t0=$(in_c 'date +%s'); in_c 'sleep 1; systemctl restart x-ui'; t1=$(in_c 'date +%s')
    check "restart in under 35 s ($((t1 - t0)) s)" test $((t1 - t0)) -lt 35
    wait_panel 61000 secretpath
    check "no core crash logged by the restart" in_c "! journalctl -u x-ui --since @$t0 --no-pager | grep -q 'Failure in running xray-core'"

    # ---- revert keeps tuning off through an update; apply turns it back on ---
    check "x-ui tune revert" in_c 'x-ui tune revert >/dev/null'
    check "drop-in removed, flag set" in_c "[[ ! -e $drop ]] && grep -q '\"disabled\": true' /var/lib/x-ui/tune/state.json"
    check "update after revert does not re-tune" in_c "XUI_MODE=update XUI_LOCAL_TARBALL=/x-ui.tar.gz bash /install.sh >/root/install3.log 2>&1 && [[ ! -e $drop ]] && grep -q 'Tuning:   off' /root/install3.log"
    check "x-ui tune apply turns it back on" in_c "x-ui tune apply >/dev/null && [[ -e $drop ]] && ! grep -q '\"disabled\": true' /var/lib/x-ui/tune/state.json"
    check "x-ui setting passes through to the binary" in_c 'x-ui setting -show true | grep -q "port: 61000"'
    check "firewall keeps the panel and inbound ports" in_c 'xui_folder=/usr/local/x-ui; source <(sed -n "/^panel_ports() {/,/^}/p" /usr/bin/x-ui);
        p=$(panel_ports | tr "\n" " "); echo "    ports: $p"; [[ " $p " == *" 61000 "* && " $p " == *" 8443 "* ]]'
    check "x-ui help prints the usage" in_c 'x-ui help | grep -q "x-ui tune" && x-ui help | grep -q "x-ui diag"'

    # ---- uninstall leaves nothing behind ------------------------------------
    check "uninstall" in_c 'echo y | x-ui uninstall >/root/uninstall.log 2>&1; true'
    check "no tuning files left" in_c '[[ ! -e /etc/sysctl.d/51-x-ui.conf && ! -e /etc/systemd/system/x-ui.service.d && ! -e /var/lib/x-ui && ! -e /etc/modules-load.d/x-ui.conf && ! -e /usr/local/x-ui ]]'

    docker rm -f "$C" >/dev/null 2>&1
}

for d in "${DISTROS[@]}"; do
    run_distro "$d"
done

echo
echo "$PASS passed, ${#FAILS[@]} failed"
for f in "${FAILS[@]}"; do echo "  FAIL $f"; done
(( ${#FAILS[@]} == 0 ))
