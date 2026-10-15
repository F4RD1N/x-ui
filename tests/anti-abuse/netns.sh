#!/bin/bash
# Loads "x-ui anti-abuse rules" into a throwaway network namespace and checks
# what it refuses, without touching this machine's own firewall.
#
#   sudo tests/anti-abuse/netns.sh [x-ui.sh]
#
# Namespace "srv" is the server: uplink up0 (11.0.0.2/24, default route via
# 11.0.0.1), a connected private subnet 10.5.0.0/24 and a static private route
# 10.9.0.0/16. Namespace "net" is the internet behind it: it answers on every
# address of 11.0.0.0/16, on 10.5.0.1, 10.9.9.9 and 192.168.77.7.
set -euo pipefail

SCRIPT=$(readlink -f "${1:-$(dirname "$0")/../../x-ui.sh}")
[[ $EUID -eq 0 ]] || { echo "netns.sh needs root" >&2; exit 1; }
for c in ip nft python3; do command -v $c >/dev/null || { echo "netns.sh needs $c" >&2; exit 1; }; done

id=aa$$
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
in_srv ip route add 10.9.0.0/16 via 11.0.0.1
in_net ip link set lo up
in_net ip link set up1 up
in_net ip addr add 11.0.0.1/24 dev up1
in_net ip addr add 10.5.0.1/24 dev up1
in_net ip route add local 11.0.0.0/16 dev lo
in_net ip route add local 10.9.9.9/32 dev lo
in_net ip route add local 192.168.77.7/32 dev lo
in_net ip route add 11.0.0.2/32 dev up1

# The internet: TCP on 22, 443, 8080 and 2000-2199, UDP on 53 and 443.
in_net python3 - >"$work/listener.log" 2>&1 <<'P' &
import socket, selectors
sel = selectors.DefaultSelector()
for p in [22, 443, 8080] + list(range(2000, 2200)):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_IP, 19, 1)  # IP_TRANSPARENT: answer for every local address
    s.bind(("0.0.0.0", p)); s.listen(4096); s.setblocking(False); sel.register(s, selectors.EVENT_READ, "tcp")
for p in (53, 443):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("0.0.0.0", p)); u.setblocking(False); sel.register(u, selectors.EVENT_READ, "udp")
print("ready", flush=True)
while True:
    for k, _ in sel.select():
        try:
            if k.data == "tcp": c, _ = k.fileobj.accept(); c.close()
            else: d, a = k.fileobj.recvfrom(100); k.fileobj.sendto(d, a)
        except OSError: pass
P
listener=$!
for _ in $(seq 1 50); do grep -q ready "$work/listener.log" 2>/dev/null && break; sleep 0.1; done

XUI_LOG_FOLDER=$work in_srv bash "$SCRIPT" anti-abuse rules >"$work/rules.nft"
allowed=$(grep -A4 "set allowed4" "$work/rules.nft" | grep elements)
for want in 255.255.255.255 10.5.0.0/24 10.9.0.0/16; do
    [[ $allowed == *"$want"* ]] || { echo "FAIL allowed4 lacks $want: $allowed"; exit 1; }
done
[[ $allowed == *11.0.0.* ]] && { echo "FAIL allowed4 lists public addresses: $allowed"; exit 1; }
echo "ok   allowed4 = the private subnet and route only: $allowed"
in_srv nft -f "$work/rules.nft"
in_srv nft -f "$work/rules.nft" # loading twice must work (the unit's reload)

in_srv python3 - "$work" <<'P'
import socket, subprocess, sys, time
fails = []
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name); ok or fails.append(name)
def tcp(ip, port, timeout=2):
    s = socket.socket(); s.settimeout(timeout)
    try: s.connect((ip, port)); return "open"
    except ConnectionRefusedError: return "refused"
    except OSError as e: return "error %d" % e.errno
    finally: s.close()
def udp(ip, port):
    # Not connected: the internet's socket answers from its main address.
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(1)
    try: u.sendto(b"x", (ip, port))
    except OSError: u.close(); return "refused"
    try: u.recvfrom(10); return "answer"
    except OSError: return "no answer"
    finally: u.close()
def counter(name):
    out = subprocess.run(["nft", "list", "counter", "inet", "xui_anti_abuse", name], capture_output=True, text=True).stdout
    return int(out.split("packets")[1].split()[0])

check("tcp 443 on the internet is open", tcp("11.0.0.1", 443) == "open")
check("tcp 22 (SSH) is refused", tcp("11.0.0.1", 22) == "refused")
check("a private address through the uplink is refused", tcp("192.168.77.7", 443).startswith(("refused", "error")))
check("  ...and counted", counter("private_nets") >= 1)
check("the uplink's own private subnet stays open", tcp("10.5.0.1", 443) == "open")
check("a static private route stays open", tcp("10.9.9.9", 443) == "open")

# Horizontal scan: 600 new hosts on port 8080, as fast as possible.
t = time.time(); res = [tcp("11.0.%d.%d" % (1 + i // 250, 1 + i % 250), 8080) for i in range(600)]
el = time.time() - t; opened = res.count("open")
check("wide scan: about 400 + 20/s get through (%d of 600 in %.1fs)" % (opened, el), 400 <= opened <= 400 + 20 * el + 25)
check("  ...the rest is refused and counted (%d)" % counter("scan_wide"), counter("scan_wide") == 600 - opened)
check("a host already seen still opens during the scan", tcp("11.0.1.1", 8080) == "open")
check("web ports are never limited", all(tcp("11.0.%d.%d" % (5 + i // 250, 1 + i % 250), 443) == "open" for i in range(500)))

# Vertical scan: 200 ports on one host.
t = time.time(); res = [tcp("11.0.9.9", p) for p in range(2000, 2200)]
el = time.time() - t; opened = res.count("open")
check("deep scan: about 100 + 10/s get through (%d of 200 in %.1fs)" % (opened, el), 100 <= opened <= 100 + 10 * el + 15)
check("  ...the rest is counted (%d)" % counter("scan_deep"), counter("scan_deep") == 200 - opened)

# DNS servers count like any other port: 500 new ones.
t = time.time(); res = [udp("11.0.%d.%d" % (20 + i // 250, 1 + i % 250), 53) for i in range(500)]
el = time.time() - t; answered = res.count("answer")
check("UDP 53: about 400 + 20/s new servers answer (%d of 500 in %.1fs)" % (answered, el), 400 <= answered <= 400 + 20 * el + 25)
check("  ...a server already used still answers", udp("11.0.20.1", 53) == "answer")
check("QUIC (udp 443) is never limited", all(udp("11.0.30.%d" % (i + 1), 443) == "answer" for i in range(200)))

# Loopback: the panel talks to every core's API port.
ls = []
for p in range(3000, 3300):
    s = socket.socket(); s.bind(("127.0.0.1", p)); s.listen(); ls.append(s)
before = counter("scan_deep")
check("300 loopback ports are never limited", all(tcp("127.0.0.1", p) == "open" for p in range(3000, 3300)) and counter("scan_deep") == before)
sys.exit(1 if fails else 0)
P
rc=$?
host_after=$(nft list tables 2>/dev/null | sort | sha256sum)
if [[ $host_before == "$host_after" ]]; then echo "ok   the host's own nftables tables are unchanged"; else echo "FAIL the host's nftables tables changed"; rc=1; fi
exit $rc
