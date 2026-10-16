#!/bin/bash
# Loads "x-ui protect rules" (the direct guard) into a throwaway network
# namespace, alone and then next to "x-ui anti-abuse rules", and checks what
# the cores' marked connections can reach. This machine's own firewall is not
# touched.
#
#   sudo tests/protect/netns.sh [x-ui.sh]
#
# Namespace "srv" is the server: uplink up0 with the public 11.0.0.2/24 and a
# private 10.5.0.2/24, default route via 11.0.0.1. Namespace "net" answers on
# 11.0.0.1 and 10.5.0.1, TCP 443.
set -euo pipefail

SCRIPT=$(readlink -f "${1:-$(dirname "$0")/../../x-ui.sh}")
[[ $EUID -eq 0 ]] || { echo "netns.sh needs root" >&2; exit 1; }
for c in ip nft python3; do command -v $c >/dev/null || { echo "netns.sh needs $c" >&2; exit 1; }; done

id=pg$$
srv=srv-$id net=net-$id
work=$(mktemp -d)
cleanup() {
    [[ -n ${listener:-} ]] && kill "$listener" 2>/dev/null
    ip netns del "$srv" 2>/dev/null
    ip netns del "$net" 2>/dev/null
    rm -rf "$work"
}
trap cleanup EXIT
host_before=$(nft list tables 2>/dev/null | sort | sha256sum)

ip netns add "$srv"
ip netns add "$net"
ip link add up0 netns "$srv" type veth peer name up1 netns "$net"
in_srv() { ip netns exec "$srv" "$@"; }
in_net() { ip netns exec "$net" "$@"; }
in_srv ip link set lo up
in_srv ip link set up0 up
in_srv ip addr add 11.0.0.2/24 dev up0
in_srv ip addr add 10.5.0.2/24 dev up0
in_srv ip route add default via 11.0.0.1
in_net ip link set lo up
in_net ip link set up1 up
in_net ip addr add 11.0.0.1/24 dev up1
in_net ip addr add 10.5.0.1/24 dev up1
in_net python3 - >"$work/listener.log" 2>&1 <<'P' &
import socket, selectors
sel = selectors.DefaultSelector()
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 443)); s.listen(64); s.setblocking(False); sel.register(s, selectors.EVENT_READ)
print("ready", flush=True)
while True:
    for k, _ in sel.select():
        try: c, _ = k.fileobj.accept(); c.close()
        except OSError: pass
P
listener=$!
for _ in $(seq 1 50); do grep -q ready "$work/listener.log" 2>/dev/null && break; sleep 0.1; done

XUI_LOG_FOLDER=$work in_srv bash "$SCRIPT" protect rules >"$work/protect.nft"
XUI_LOG_FOLDER=$work in_srv bash "$SCRIPT" anti-abuse rules >"$work/anti-abuse.nft"

# What a core does: connect with socket mark 4242 (or another, or none).
cat >"$work/check.py" <<'P'
import socket, subprocess, sys, threading
fails = []
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name); ok or fails.append(name)
def conn(fam, addr, kind="tcp", mark=4242):
    s = socket.socket(fam, socket.SOCK_STREAM if kind == "tcp" else socket.SOCK_DGRAM); s.settimeout(2)
    if mark: s.setsockopt(socket.SOL_SOCKET, 36, mark)  # SO_MARK
    try:
        s.connect(addr)
        if kind == "udp":
            s.send(b"x"); s.recv(10)
        return "open"
    except ConnectionRefusedError: return "refused"
    except OSError as e: return "error %d" % e.errno
    finally: s.close()
def counter(name):
    out = subprocess.run(["nft", "list", "counter", "inet", "xui_direct_guard", name], capture_output=True, text=True).stdout
    return int(out.split("packets")[1].split()[0])
keep = []
for a in [("127.0.0.1", 3000), ("0.0.0.0", 3001), ("11.0.0.2", 3500)]:
    s = socket.socket(); s.bind(a); s.listen(); keep.append(s)
echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); echo.bind(("127.0.0.1", 3600)); keep.append(echo)
def answer():
    while True:
        try: d, a = echo.recvfrom(10); echo.sendto(d, a)
        except OSError: return
threading.Thread(target=answer, daemon=True).start()
tag = sys.argv[1]
local0, private0 = counter("local"), counter("private")
check(tag + "direct to 127.0.0.1 (a listening port) is refused", conn(socket.AF_INET, ("127.0.0.1", 3000)) == "refused")
check(tag + "  ...unmarked, it opens (the panel's calls to the cores' API)", conn(socket.AF_INET, ("127.0.0.1", 3000), mark=0) == "open")
check(tag + "  ...and with another mark", conn(socket.AF_INET, ("127.0.0.1", 3000), mark=4243) == "open")
check(tag + "direct to 127.0.0.2 is refused", conn(socket.AF_INET, ("127.0.0.2", 3001)) == "refused")
check(tag + "  ...unmarked, it opens", conn(socket.AF_INET, ("127.0.0.2", 3001), mark=0) == "open")
check(tag + "direct to 0.0.0.0 (this host) is refused", conn(socket.AF_INET, ("0.0.0.0", 3001)) == "refused")
check(tag + "direct UDP to 127.0.0.1 gets no answer", conn(socket.AF_INET, ("127.0.0.1", 3600), "udp") != "open")
check(tag + "  ...unmarked, it answers", conn(socket.AF_INET, ("127.0.0.1", 3600), "udp", 0) == "open")
check(tag + "direct to a private network is refused", conn(socket.AF_INET, ("10.5.0.1", 443)) != "open")
check(tag + "  ...unmarked, it opens (it is the uplink's own subnet)", conn(socket.AF_INET, ("10.5.0.1", 443), mark=0) == "open")
check(tag + "direct to this server's public address stays open", conn(socket.AF_INET, ("11.0.0.2", 3500)) == "open")
check(tag + "direct to the internet stays open", conn(socket.AF_INET, ("11.0.0.1", 443)) == "open")
try:
    v6 = socket.socket(socket.AF_INET6); v6.bind(("::1", 3700)); v6.listen(); keep.append(v6)
    check(tag + "direct to ::1 is refused", conn(socket.AF_INET6, ("::1", 3700)) == "refused")
    v4m = socket.socket(socket.AF_INET6); v4m.settimeout(2); v4m.setsockopt(socket.SOL_SOCKET, 36, 4242)
    try: v4m.connect(("::ffff:127.0.0.1", 3000)); r = "open"
    except OSError: r = "refused"
    v4m.close()
    check(tag + "direct to ::ffff:127.0.0.1 is refused", r == "refused")
except OSError as e:
    print("skip IPv6 loopback (%s)" % e)
check(tag + "refusals are counted (local %d, private %d)" % (counter("local") - local0, counter("private") - private0),
      counter("local") - local0 >= 5 and counter("private") - private0 >= 1)  # 0.0.0.0 is sent to 127.0.0.1
sys.exit(1 if fails else 0)
P

rc=0
in_srv nft -f "$work/protect.nft"
in_srv nft -f "$work/protect.nft" # loading twice must work (the unit's reload)
in_srv python3 "$work/check.py" "[guard alone] " || rc=1
in_srv nft -f "$work/anti-abuse.nft"
in_srv python3 "$work/check.py" "[with anti-abuse] " || rc=1

host_after=$(nft list tables 2>/dev/null | sort | sha256sum)
if [[ $host_before == "$host_after" ]]; then echo "ok   the host's own nftables tables are unchanged"; else echo "FAIL the host's nftables tables changed"; rc=1; fi
exit $rc
