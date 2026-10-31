#!/bin/bash
# Install test of install.sh in throwaway systemd containers.
#
#   tests/install/docker-install.sh <x-ui-linux-amd64.tar.gz> [ubuntu2404] [debian12]
#
# Each distribution gets a small image with systemd, sshd and nothing else
# (a minimal VPS). The container has its own network namespace and may load
# nftables rules, mark sockets and replace /etc/resolv.conf there, like a VM
# (NET_ADMIN, SYS_ADMIN, writable /proc/sys of its own namespace). Ubuntu is
# set up as a cloud image is: systemd-resolved and the stub resolv.conf link;
# Debian with a plain resolv.conf file. Then:
#
#   - a fresh install: the panel answers and fardin/fardin logs in; the core
#     runs the allow-list template with the direct mark; the direct guard,
#     anti-abuse (nft table, dead-host timer, fail2ban's SSH jail with
#     maxretry 2) and the DNS cache (unbound at 127.0.0.1, resolv.conf ours)
#     are on; the panel's ports are reserved; swap is skipped in a container;
#   - through a VLESS inbound: an allowed site loads and its name is in
#     unbound's cache; a site not on the allow-list and a speed test do not;
#   - a WebSocket inbound with path "*" takes clients with any path, early
#     data (?ed=) included;
#   - the core's memory limit (GOMEMLIMIT) is sized for the container's 1 GiB;
#   - BBR replaces cubic (host setup forced on in the container);
#   - "x-ui update" keeps a changed login; anti-abuse and the DNS cache turned
#     off stay off through an update and come back with "on";
#   - a panel from before this version (no saved template) keeps its old
#     template through an update run as the old menus run it (no "update");
#   - a snapshot booted with more memory: GOMEMLIMIT=449MiB and GOGC=off left
#     in the unit, the container restarted with 2 GiB; the core gets the
#     2 GiB limit and no GOGC=off;
#   - uninstall puts resolv.conf back as it was and removes the rest.
#
# Every container and test image is removed at the end.
set -uo pipefail

TARBALL=$(readlink -f "${1:?usage: docker-install.sh <tarball> [ubuntu2404] [debian12]}")
shift
DISTROS=("$@")
((${#DISTROS[@]})) || DISTROS=(ubuntu2404 debian12)
REPO=$(cd "$(dirname "$0")/../.." && pwd)
RAND=$RANDOM
CONTAINERS=() IMAGES=()
PASS=0 FAILS=()

NET="xui-install-net-$RAND"
cleanup() {
    for c in "${CONTAINERS[@]}"; do docker rm -f "$c" >/dev/null 2>&1; done
    for i in "${IMAGES[@]}"; do docker rmi -f "$i" >/dev/null 2>&1; done
    docker network rm "$NET" >/dev/null 2>&1
}
trap cleanup EXIT
# A network of its own (TEST_SUBNET), so the containers never get an address
# that something on this machine remembers from before.
docker network create --subnet "${TEST_SUBNET:-10.213.78.0/24}" "$NET" >/dev/null || exit 1

ok() { PASS=$((PASS + 1)); echo "  ok   $*"; }
not() { ! "$@"; }
bad() { FAILS+=("$DISTRO: $*"); echo "  FAIL $*"; }
check() { local what=$1; shift; if "$@"; then ok "$what"; else bad "$what"; fi; }
in_c() { docker exec "$C" bash -c "$1"; }

base_image() {
    case "$1" in
    debian12) echo debian:bookworm-slim ;;
    ubuntu2404) echo ubuntu:24.04 ;;
    *) echo "unknown distribution $1" >&2; return 1 ;;
    esac
}

build_image() {
    local base=$1 tag=$2 extra=""
    [[ $base == ubuntu:* ]] && extra="systemd-resolved"
    docker build --network host -q -t "$tag" - >/dev/null <<EOF
FROM $base
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      systemd systemd-sysv procps iproute2 kmod openssh-server ca-certificates curl python3 $extra >/dev/null; \
    rm -rf /var/lib/apt/lists/*; true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
}

login() { # port path user pass -> 0 when the panel accepts the login
    in_c "curl -fsS -m 10 -d 'username=$3&password=$4' http://127.0.0.1:$1/$2/login" 2>/dev/null | grep -q '"success":true'
}

wait_panel() { # port path
    local i
    for i in $(seq 1 30); do
        in_c "curl -fsS -m 3 -o /dev/null http://127.0.0.1:$1/$2/" 2>/dev/null && return 0
        sleep 1
    done
    return 1
}

# add_inbound creates a VLESS inbound on 8443 through the panel's API.
add_inbound() {
    docker exec -i "$C" bash -s <<'SH'
set -e
B=http://127.0.0.1:60000/hetzner
curl -fsS -m 10 -c /root/jar -d 'username=fardin&password=fardin' $B/login >/dev/null
curl -fsS -m 30 -b /root/jar $B/panel/api/inbounds/add \
  -d up=0 -d down=0 -d total=0 -d remark=t1 -d enable=true -d expiryTime=0 \
  -d listen= -d port=8443 -d protocol=vless \
  --data-urlencode 'settings={"clients":[{"id":"0b0b7a5e-8c7a-4e0f-9a51-6c0a3f1f7d10","email":"t1","flow":"","limitIp":0,"totalGB":0,"expiryTime":0,"enable":true,"tgId":"","subId":"abcd1234abcd1234","reset":0}],"decryption":"none","fallbacks":[]}' \
  --data-urlencode 'streamSettings={"network":"tcp","security":"none","tcpSettings":{"header":{"type":"none"}}}' \
  --data-urlencode 'sniffing={"enabled":false}' | grep -q '"success":true'
for _ in $(seq 1 20); do ss -ltn | grep -q ':8443 ' && exit 0; sleep 1; done
exit 1
SH
}

# start_client runs the release's core as a client inside the container:
# socks on 127.0.0.1:10808 through the VLESS inbound.
start_client() {
    docker exec -i "$C" bash -s <<'SH'
cat >/root/client.json <<'J'
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"udp":true}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":8443,
   "users":[{"id":"0b0b7a5e-8c7a-4e0f-9a51-6c0a3f1f7d10","encryption":"none"}]}]}}]}
J
nohup /usr/local/x-ui/bin/xray-linux-amd64 run -c /root/client.json >/root/client.log 2>&1 &
for _ in $(seq 1 10); do ss -ltn | grep -q ':10808 ' && exit 0; sleep 1; done
exit 1
SH
}

# add_ws_any_inbound creates a VLESS+WebSocket inbound on 8444 with path "*"
# (every path is taken) through the panel's API.
add_ws_any_inbound() {
    docker exec -i "$C" bash -s <<'SH'
set -e
B=http://127.0.0.1:60000/hetzner
curl -fsS -m 10 -c /root/jar -d 'username=fardin&password=fardin' $B/login >/dev/null
curl -fsS -m 30 -b /root/jar $B/panel/api/inbounds/add \
  -d up=0 -d down=0 -d total=0 -d remark=ws-any -d enable=true -d expiryTime=0 \
  -d listen= -d port=8444 -d protocol=vless \
  --data-urlencode 'settings={"clients":[{"id":"6c0f6f3e-2b1d-4f4e-9d55-0d2f6a9b7e21","email":"ws1","flow":"","limitIp":0,"totalGB":0,"expiryTime":0,"enable":true,"tgId":"","subId":"wsany0000wsany00","reset":0}],"decryption":"none","fallbacks":[]}' \
  --data-urlencode 'streamSettings={"network":"ws","security":"none","wsSettings":{"acceptProxyProtocol":false,"path":"*","host":"","headers":{},"heartbeatPeriod":0}}' \
  --data-urlencode 'sniffing={"enabled":false}' | grep -q '"success":true'
for _ in $(seq 1 20); do ss -ltn | grep -q ':8444 ' && exit 0; sleep 1; done
exit 1
SH
}

# ws_any_via <socks port> <client path>: a client core with that WebSocket
# path on 127.0.0.1:<socks port>, then the HTTP code of google's 204 through it.
ws_any_via() {
    docker exec -i "$C" bash -s "$1" "$2" <<'SH'
port=$1 path=$2
cat >/root/client-$port.json <<J
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"127.0.0.1","port":$port,"protocol":"socks","settings":{"udp":true}}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":8444,
   "users":[{"id":"6c0f6f3e-2b1d-4f4e-9d55-0d2f6a9b7e21","encryption":"none"}]}]},
   "streamSettings":{"network":"ws","wsSettings":{"path":"$path"}}}]}
J
nohup /usr/local/x-ui/bin/xray-linux-amd64 run -c /root/client-$port.json >/root/client-$port.log 2>&1 &
for _ in $(seq 1 10); do ss -ltn | grep -q ":$port " && break; sleep 1; done
curl -s -o /dev/null -m 15 -w '%{http_code}' --socks5-hostname 127.0.0.1:$port https://www.google.com/generate_204
SH
}

# core_limit prints the GOMEMLIMIT entries of the panel's core (not the test
# client, which runs the same binary).
core_limit() {
    in_c 'for p in /proc/[0-9]*; do
        tr "\0" " " <$p/cmdline 2>/dev/null | grep -q "xray-linux-[a-z0-9]* -c bin/config.json" || continue
        tr "\0" "\n" <$p/environ | grep "^GOMEMLIMIT="
    done'
}

# core_limit_is waits up to 30 s for the core to run with this GOMEMLIMIT
# (the panel answers before it starts the core).
core_limit_is() {
    local i
    for i in $(seq 1 30); do
        [[ $(core_limit) == "$1" ]] && return 0
        sleep 1
    done
    echo "    core: $(core_limit)"
    return 1
}

via_vpn() { # url -> the HTTP code through the VPN (000 when refused)
    in_c "curl -s -o /dev/null -m 15 -w '%{http_code}' --socks5-hostname 127.0.0.1:10808 '$1'"
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
    docker run -d --name "$C" --network "$NET" --cgroupns=private --security-opt writable-cgroups=true \
        --cap-add NET_ADMIN --cap-add SYS_ADMIN --security-opt apparmor=unconfined \
        --security-opt seccomp=unconfined --security-opt systempaths=unconfined \
        --tmpfs /run --tmpfs /run/lock --tmpfs /tmp --memory 1g --cpus 1 \
        -v "$TARBALL:/x-ui.tar.gz:ro" -v "$REPO/install.sh:/install.sh:ro" \
        "$tag" >/dev/null || { bad "container start"; return; }
    in_c 'for _ in $(seq 1 60); do s=$(systemctl is-system-running 2>/dev/null); [[ $s == running || $s == degraded ]] && exit 0; sleep 1; done; exit 0'
    check "systemd booted as PID 1" in_c '[[ $(cat /proc/1/comm) == systemd ]]'
    # resolv.conf as on a VM: Docker's bind mount goes; Ubuntu gets resolved's
    # stub link, Debian a plain file.
    # A VPS's resolver, not Docker's 127.0.0.11 (a local DNS server, which
    # x-ui rightly leaves alone): this machine's own upstream.
    local up
    up=$(awk '$1 == "nameserver" && $2 ~ /^[0-9.]+$/ && $2 !~ /^127\./ { print $2; exit }' /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null)
    up=${up:-8.8.8.8}
    if [[ $DISTRO == ubuntu* ]]; then
        in_c "umount /etc/resolv.conf; mkdir -p /etc/systemd/resolved.conf.d &&
            printf '[Resolve]\nDNS=%s\n' '$up' >/etc/systemd/resolved.conf.d/test.conf &&
            systemctl restart systemd-resolved && ln -sf ../run/systemd/resolve/stub-resolv.conf /etc/resolv.conf"
        check "resolv.conf is resolved's stub link" in_c '[[ $(readlink /etc/resolv.conf) == ../run/systemd/resolve/stub-resolv.conf ]] && getent hosts github.com >/dev/null'
    else
        in_c "umount /etc/resolv.conf; printf 'nameserver %s\nnameserver 8.8.8.8\n' '$up' >/etc/resolv.conf"
        check "resolv.conf is a plain file" in_c '[[ -f /etc/resolv.conf && ! -L /etc/resolv.conf ]] && getent hosts github.com >/dev/null'
    fi
    in_c 'sysctl -qw net.ipv4.tcp_congestion_control=cubic; systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null; true'
    in_c 'cp -P /etc/resolv.conf /root/resolv.conf.before'

    # ---- fresh install -------------------------------------------------------
    if ! in_c 'XUI_LOCAL_TARBALL=/x-ui.tar.gz bash /install.sh >/root/install1.log 2>&1'; then
        bad "fresh install (rc != 0)"; in_c 'tail -40 /root/install1.log'; return
    fi
    ok "fresh install"
    check "panel answers on :60000/hetzner/" wait_panel 60000 hetzner
    check "login fardin/fardin" login 60000 hetzner fardin fardin
    check "core runs the allow-list template" in_c 'grep -q "\"ruleTag\": *\"speedtest-block\"" /usr/local/x-ui/bin/config.json || grep -q "speedtest-block" /usr/local/x-ui/bin/config.json'
    check "direct outbound carries mark 4242" in_c 'tr -d " \n" </usr/local/x-ui/bin/config.json | grep -q "\"mark\":4242"'
    check "direct guard loaded" in_c 'systemctl is-active --quiet x-ui-direct-guard && nft list table inet xui_direct_guard >/dev/null'
    check "anti-abuse loaded" in_c 'systemctl is-active --quiet x-ui-anti-abuse && nft list table inet xui_anti_abuse >/dev/null'
    check "dead-host timer on" in_c 'systemctl is-active --quiet x-ui-anti-abuse-check.timer'
    check "fail2ban SSH jail, maxretry 2" in_c '[[ $(fail2ban-client get sshd maxretry 2>/dev/null) == 2 ]]'
    check "summary: anti-abuse on" in_c 'grep -q "Anti-abuse: on" /root/install1.log'
    check "unbound answers at 127.0.0.1" in_c 'systemctl is-active --quiet unbound && x-ui dns status | grep -q "on"'
    check "resolv.conf: 127.0.0.1 first, then fallbacks" in_c '[[ ! -L /etc/resolv.conf ]] && awk "\$1==\"nameserver\"{print \$2}" /etc/resolv.conf | head -1 | grep -qx 127.0.0.1 && [[ $(grep -c ^nameserver /etc/resolv.conf) -ge 2 ]]'
    check "names resolve through the cache" in_c 'getent hosts www.wikipedia.org >/dev/null && getent hosts github.com >/dev/null'
    check "resolvers were timed" in_c 'grep -q " ms$" /root/install1.log'
    # (a link is compared by its target: Ubuntu's is relative)
    check "the previous resolv.conf is kept" in_c 'if [[ -L /root/resolv.conf.before ]]; then [[ $(readlink /etc/x-ui/dns/resolv.conf) == $(readlink /root/resolv.conf.before) ]]; else cmp -s /etc/x-ui/dns/resolv.conf /root/resolv.conf.before; fi'
    check "swap skipped in a container" in_c 'grep -q "skipped in a container" /root/install1.log && [[ ! -e /swapfile ]]'
    check "panel ports reserved (60000, 62789, 11111)" in_c 'p=$(cat /proc/sys/net/ipv4/ip_local_reserved_ports); for x in 60000 62789 11111; do echo ",$p," | grep -q ",$x," || exit 1; done'
    check "core's GOMEMLIMIT sized for the 1 GiB container (504MiB)" core_limit_is GOMEMLIMIT=504MiB
    check "the panel logs the same limit" in_c 'journalctl -b -u x-ui --no-pager | grep -q "Memory limit: GOMEMLIMIT=504MiB for the panel and Xray (memory limit 1.0 GiB of "'

    # ---- through the VPN -----------------------------------------------------
    check "inbound added, the core listens on 8443" add_inbound
    check "8443 reserved within 35 s (added while the core runs)" in_c 'for _ in $(seq 1 35); do grep -q 8443 /proc/sys/net/ipv4/ip_local_reserved_ports && exit 0; sleep 1; done; exit 1'
    if start_client; then
        check "allowed site loads through the VPN (google 204)" test "$(via_vpn https://www.google.com/generate_204)" = 204
        check "its name came from unbound's cache" in_c 'unbound-control dump_cache 2>/dev/null | grep -q "^www.google.com\."'
        check "a site off the allow-list does not" test "$(via_vpn http://example.com/)" = 000
        check "a speed test does not" test "$(via_vpn https://www.speedtest.net/)" = 000
    else
        bad "client core did not start"; in_c 'tail -5 /root/client.log'
    fi
    check "WebSocket inbound with path \"*\" added, the core listens on 8444" add_ws_any_inbound
    check "  a client with path /feed/966695/assets/recent/media gets through" test "$(ws_any_via 10811 /feed/966695/assets/recent/media)" = 204
    check "  a client with another path and early data (?ed=2560) too" test "$(ws_any_via 10812 '/x/y/z?ed=2560')" = 204

    # ---- BBR (host setup forced on in the container) -------------------------
    check "BBR replaces cubic" in_c 'XUI_HOST_SETUP_IN_CONTAINER=1 x-ui host-setup update | grep -q "BBR: on (was cubic)" && [[ $(sysctl -n net.ipv4.tcp_congestion_control) == bbr ]] && grep -q "tcp_congestion_control = bbr" /etc/sysctl.d/60-x-ui.conf'
    check "BBR left alone the second time" in_c 'XUI_HOST_SETUP_IN_CONTAINER=1 x-ui host-setup update | grep -q "BBR: already on"'
    check "swap fails cleanly where it cannot be turned on" in_c 'out=$(XUI_HOST_SETUP_IN_CONTAINER=1 x-ui host-setup install); echo "$out" | grep -q "^Swap: "; [[ ! -e /swapfile ]] || swapon --show | grep -q /swapfile'

    # ---- update keeps the login; off stays off -------------------------------
    in_c '/usr/local/x-ui/x-ui setting -username bob -password S3cret -port 61000 -webBasePath secretpath >/dev/null && systemctl restart x-ui'
    wait_panel 61000 secretpath
    in_c 'x-ui anti-abuse off >/dev/null; x-ui dns off >/dev/null'
    check "anti-abuse off: table gone" in_c '! nft list table inet xui_anti_abuse >/dev/null 2>&1 && [[ ! -e /etc/fail2ban/jail.d/x-ui-anti-abuse.conf ]]'
    check "dns off: resolv.conf back as it was" in_c 'diff <(readlink /etc/resolv.conf; cat /etc/resolv.conf) <(readlink /root/resolv.conf.before; cat /root/resolv.conf.before) >/dev/null && ! systemctl is-active --quiet unbound'
    in_c 'cat > /usr/local/bin/curl <<"SH"
#!/bin/bash
args=("$@"); out=""; url=""
while (( $# )); do case "$1" in -o) out=$2; shift 2;; http*) url=$1; shift;; *) shift;; esac; done
case "$url" in
  *raw.githubusercontent.com*/install.sh) cp /install.sh "$out";;
  *api.github.com*) echo "{\"tag_name\": \"v9.9.9-test\"}";;
  *) exec /usr/bin/curl "${args[@]}";;
esac
SH
chmod +x /usr/local/bin/curl'
    check "x-ui update succeeds" in_c 'echo y | XUI_LOCAL_TARBALL=/x-ui.tar.gz x-ui update >/root/update.log 2>&1'
    in_c 'rm -f /usr/local/bin/curl'
    check "update ran in update mode" in_c 'grep -q "keeping the existing username" /root/update.log'
    check "changed login kept" login 61000 secretpath bob S3cret
    check "anti-abuse kept off by the update" in_c '! nft list table inet xui_anti_abuse >/dev/null 2>&1 && grep -q "kept off" /root/update.log'
    check "dns kept off by the update" in_c '! systemctl is-active --quiet unbound && grep -q "DNS cache: kept off" /root/update.log'
    check "x-ui anti-abuse on brings it back" in_c 'x-ui anti-abuse on >/dev/null && nft list table inet xui_anti_abuse >/dev/null && [[ ! -e /etc/x-ui/anti-abuse.off ]]'
    check "x-ui dns on brings it back" in_c 'x-ui dns on >/dev/null && awk "\$1==\"nameserver\"{print \$2; exit}" /etc/resolv.conf | grep -qx 127.0.0.1'

    # ---- a panel from before this version keeps its template -----------------
    in_c "python3 -c \"
import sqlite3; c = sqlite3.connect('/etc/x-ui/x-ui.db'); c.execute(\\\"delete from settings where key = 'xrayTemplateConfig'\\\"); c.commit()\""
    check "re-run without 'update' (as old menus do) is an update" in_c 'XUI_LOCAL_TARBALL=/x-ui.tar.gz bash /install.sh >/root/install2.log 2>&1 && grep -q "A panel is installed here: updating it" /root/install2.log'
    check "old panel keeps the old template" in_c 'grep -q "Kept the xray template" /root/install2.log && ! grep -q speedtest-block /usr/local/x-ui/bin/config.json'
    check "login still kept" login 61000 secretpath bob S3cret

    # ---- a snapshot of this server booted with more memory -------------------
    # The 1 GiB server's unit carries GOMEMLIMIT=449MiB (as a hand-made
    # drop-in did), here with GOGC=off; the copy boots with 2 GiB.
    in_c 'mkdir -p /etc/systemd/system/x-ui.service.d &&
        printf "[Service]\nEnvironment=GOMEMLIMIT=449MiB GOGC=off\n" >/etc/systemd/system/x-ui.service.d/60-host.conf && systemctl daemon-reload'
    if docker update --memory 2g --memory-swap 2g "$C" >/dev/null && docker restart -t 30 "$C" >/dev/null; then
        in_c 'for _ in $(seq 1 60); do s=$(systemctl is-system-running 2>/dev/null); [[ $s == running || $s == degraded ]] && exit 0; sleep 1; done; exit 0'
        in_c 'umount /etc/resolv.conf 2>/dev/null; true' # Docker's bind mount is back
        check "panel back after the reboot" wait_panel 61000 secretpath
        check "core's GOMEMLIMIT now for 2 GiB (1200MiB), not 449MiB" core_limit_is GOMEMLIMIT=1200MiB
        check "  and no GOGC=off" in_c 'for p in /proc/[0-9]*; do tr "\0" " " <$p/cmdline 2>/dev/null | grep -q "xray-linux-[a-z0-9]* -c bin/config.json" || continue; ! tr "\0" "\n" <$p/environ | grep -q "^GOGC="; exit; done; exit 1'
        check "the panel says the old values are not used" in_c 'j=$(journalctl -b -u x-ui --no-pager); grep -q "Memory limit: GOMEMLIMIT=1200MiB for the panel and Xray (memory limit 2.0 GiB of " <<<"$j" && grep -q "GOMEMLIMIT=449MiB from the service environment is not used" <<<"$j" && grep -q "GOGC=off from the service environment is not used" <<<"$j"'
    else
        bad "container restart with 2 GiB"
    fi
    in_c 'rm -f /etc/systemd/system/x-ui.service.d/60-host.conf; rmdir /etc/systemd/system/x-ui.service.d 2>/dev/null; systemctl daemon-reload'

    # ---- uninstall -------------------------------------------------------------
    check "uninstall" in_c 'echo y | x-ui uninstall >/root/uninstall.log 2>&1; true'
    check "resolv.conf as before the install" in_c 'diff <(readlink /etc/resolv.conf; cat /etc/resolv.conf) <(readlink /root/resolv.conf.before; cat /root/resolv.conf.before) >/dev/null'
    check "nothing of x-ui left" in_c '! nft list table inet xui_anti_abuse >/dev/null 2>&1 && ! nft list table inet xui_direct_guard >/dev/null 2>&1 &&
        [[ ! -e /etc/sysctl.d/60-x-ui.conf && ! -e /etc/x-ui && ! -e /usr/local/x-ui && ! -e /etc/systemd/system/unbound.service.d/90-x-ui.conf ]] &&
        ! ls /etc/unbound/unbound.conf.d/x-ui.conf >/dev/null 2>&1 && ! systemctl is-active --quiet unbound'

    docker rm -f "$C" >/dev/null 2>&1
}

for d in "${DISTROS[@]}"; do
    run_distro "$d"
done

echo
echo "$PASS passed, ${#FAILS[@]} failed"
for f in "${FAILS[@]}"; do echo "  FAIL $f"; done
((${#FAILS[@]} == 0))
