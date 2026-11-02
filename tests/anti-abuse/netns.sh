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
# 11.1.0.9 never answers (not local to "net", nothing routes it); 11.1.0.10
# answers on 7001 but drops SYNs to 7000: busy, not dead.
in_net ip route add local 11.1.0.10/32 dev lo
in_net nft -f - <<'N'
table inet t {
	chain in {
		type filter hook input priority 0; policy accept;
		tcp dport 7000 drop
	}
}
N

# The internet: TCP on 22, 443, 8080 and 6000-6399, UDP on 53 and 443.
in_net python3 - >"$work/listener.log" 2>&1 <<'P' &
import socket, selectors
sel = selectors.DefaultSelector()
for p in [22, 443, 587, 993, 3306, 8080, 7001] + list(range(6000, 6400)):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.SOL_IP, 19, 1)  # IP_TRANSPARENT: answer for every local address
    s.bind(("0.0.0.0", p)); s.listen(4096); s.setblocking(False); sel.register(s, selectors.EVENT_READ, "tcp")
for p in (53, 443, 5060):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind(("0.0.0.0", p)); u.setblocking(False); sel.register(u, selectors.EVENT_READ, "udp")
print("ready", flush=True)
keep = []
while True:
    for k, _ in sel.select():
        try:
            if k.data == "tcp":
                c, _ = k.fileobj.accept()
                keep.append(c) if c.getsockname()[1] == 7001 else c.close()  # 7001 stays connected
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

rc=0
# Hosts that do not answer: 120 attempts waiting at 11.1.0.9 (dead), 120 at
# 11.1.0.10:7000 while one connection to 11.1.0.10:7001 works (busy), 50 at
# 11.1.0.11 (below the threshold). "anti-abuse check" refuses only the dead.
XUI_LOG_FOLDER=$work SCRIPT=$SCRIPT in_srv python3 - <<'P3' || rc=1
import os, socket, subprocess, time
fails = []
def check(name, ok):
    print(("ok   " if ok else "FAIL ") + name); ok or fails.append(name)
held = []
def pending(ip, port, n):
    for _ in range(n):
        s = socket.socket(); s.setblocking(False); s.connect_ex((ip, port)); held.append(s)
live = socket.create_connection(("11.1.0.10", 7001), 3); held.append(live)
pending("11.1.0.9", 7000, 120); pending("11.1.0.10", 7000, 120); pending("11.1.0.11", 7000, 50)
time.sleep(0.5)
subprocess.run(["bash", os.environ["SCRIPT"], "anti-abuse", "check"], check=True)
dead = subprocess.run(["nft", "list", "set", "inet", "xui_anti_abuse", "dead4"], capture_output=True, text=True).stdout
check("dead host refused for a while: 11.1.0.9 listed", "11.1.0.9" in dead)
check("busy host (a working connection) not listed: 11.1.0.10", "11.1.0.10" not in dead)
check("below the threshold not listed: 11.1.0.11", "11.1.0.11" not in dead)
s = socket.socket(); s.settimeout(3); t = time.time()
try: s.connect(("11.1.0.9", 7000)); r = "open"
except ConnectionRefusedError: r = "refused"
except OSError as e: r = "error %s" % e
check("a new attempt at the dead host fails at once (%s, %.0f ms)" % (r, (time.time() - t) * 1000), r == "refused" and time.time() - t < 0.5)
out = subprocess.run(["nft", "list", "counter", "inet", "xui_anti_abuse", "dead_hosts"], capture_output=True, text=True).stdout
check("  ...and is counted", "packets 0 " not in out)
for x in held: x.close()
raise SystemExit(1 if fails else 0)
P3
in_srv python3 - "$work" <<'P' || rc=1
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
check("tcp 587 (mail submission) is refused", tcp("11.0.0.1", 587) == "refused")
check("a private address through the uplink is refused", tcp("192.168.77.7", 443).startswith(("refused", "error")))
check("  ...and counted", counter("private_nets") >= 1)
check("the uplink's own private subnet stays open", tcp("10.5.0.1", 443) == "open")
check("a static private route stays open", tcp("10.9.9.9", 443) == "open")

# Horizontal scan: 1200 new hosts on port 8080, as fast as possible.
t = time.time(); res = [tcp("11.0.%d.%d" % (1 + i // 250, 1 + i % 250), 8080) for i in range(1200)]
el = time.time() - t; opened = res.count("open")
check("wide scan: about 1000 + 50/s get through (%d of 1200 in %.1fs)" % (opened, el), 1000 <= opened <= 1000 + 50 * el + 25)
check("  ...the rest is refused and counted (%d)" % counter("scan_wide"), counter("scan_wide") == 1200 - opened)
check("a host already seen still opens during the scan", tcp("11.0.1.1", 8080) == "open")
check("web ports are never limited", all(tcp("11.0.%d.%d" % (6 + i // 250, 1 + i % 250), 443) == "open" for i in range(1200)))

# Vertical scan: 400 ports on one host.
t = time.time(); res = [tcp("11.0.19.9", p) for p in range(6000, 6400)]
el = time.time() - t; opened = res.count("open")
check("deep scan: about 300 + 30/s get through (%d of 400 in %.1fs)" % (opened, el), 300 <= opened <= 300 + 30 * el + 15)
check("  ...the rest is counted (%d)" % counter("scan_deep"), counter("scan_deep") == 400 - opened)

# DNS servers count like any other port: 1200 new ones.
t = time.time(); res = [udp("11.0.%d.%d" % (20 + i // 250, 1 + i % 250), 53) for i in range(1200)]
el = time.time() - t; answered = res.count("answer")
check("UDP 53: about 1000 + 50/s new servers answer (%d of 1200 in %.1fs)" % (answered, el), 1000 <= answered <= 1000 + 50 * el + 25)
check("  ...a server already used still answers", udp("11.0.20.1", 53) == "answer")
check("QUIC (udp 443) is never limited", all(udp("11.0.%d.%d" % (30 + i // 250, 1 + i % 250), 443) == "answer" for i in range(1200)))

# Brute force: 45 logins to one database server, as fast as possible. About
# 30 get through, then that server's port is refused for an hour; other
# servers are not affected.
res = [tcp("11.0.40.1", 3306) for i in range(45)]; opened = res.count("open")
check("database brute force: about 30 get through (%d of 45)" % opened, 30 <= opened <= 32)
time.sleep(2.5)
check("  ...then the server's port stays refused", tcp("11.0.40.1", 3306) == "refused")
check("  ...and is listed and counted", "11.0.40.1 . 3306" in subprocess.run(["nft", "list", "set", "inet", "xui_anti_abuse", "barred4"], capture_output=True, text=True).stdout and counter("brute_force") >= 13)
check("  ...another database server still opens", tcp("11.0.40.2", 3306) == "open")
check("  ...a developer's pool of 20 at once to a third opens", [tcp("11.0.40.3", 3306) for i in range(20)].count("open") == 20)
# Mail logins: about 120 at once, then 1 a second; never refused for long.
res = [tcp("11.0.41.1", 993) for i in range(150)]; opened = res.count("open")
check("IMAP brute force: about 120 get through (%d of 150)" % opened, 120 <= opened <= 123)
time.sleep(1.2)
check("  ...a second later a login opens again", tcp("11.0.41.1", 993) == "open")
# SIP over UDP: 400 packets at one server, then it is refused.
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(400):
    try: u.sendto(b"REGISTER", ("11.0.42.1", 5060))
    except OSError: pass
u.close()
check("SIP flood over UDP: the server is refused", "11.0.42.1 . 5060" in subprocess.run(["nft", "list", "set", "inet", "xui_anti_abuse", "barred4"], capture_output=True, text=True).stdout and udp("11.0.42.1", 5060) != "answer")
check("  ...a phone's few packets to another SIP server get answers", all(udp("11.0.42.2", 5060) == "answer" for i in range(5)))

# Loopback: the panel talks to every core's API port.
ls = []
for p in range(3000, 3300):
    s = socket.socket(); s.bind(("127.0.0.1", p)); s.listen(); ls.append(s)
before = counter("scan_deep")
check("300 loopback ports are never limited", all(tcp("127.0.0.1", p) == "open" for p in range(3000, 3300)) and counter("scan_deep") == before)
sys.exit(1 if fails else 0)
P

# What a VPN app does: 100 users each test 30 configs (30 ports) at once.
# Connections users open to the server are never counted or refused.
in_srv python3 - >"$work/srv.log" 2>&1 <<'P2' &
import socket, selectors
sel = selectors.DefaultSelector()
for p in range(20821, 20851):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", p)); s.listen(4096); s.setblocking(False); sel.register(s, selectors.EVENT_READ)
print("ready", flush=True)
conns = []
while True:
    for k, _ in sel.select():
        try: c, _ = k.fileobj.accept(); conns.append(c)
        except OSError: pass
P2
srv_listener=$!
for _ in $(seq 1 50); do grep -q ready "$work/srv.log" 2>/dev/null && break; sleep 0.1; done
counters() { in_srv nft list table inet xui_anti_abuse | grep -oE 'packets [0-9]+' | md5sum; }
before=$(counters)
ok=$(in_net python3 - <<'P2' || true
import socket, selectors, time
sel = selectors.DefaultSelector(); socks = []
for u in range(100):
    for port in range(20821, 20851):
        s = socket.socket(); s.setsockopt(socket.SOL_IP, 19, 1); s.bind(("11.0.200.%d" % (u + 1), 0)); s.setblocking(False)
        s.connect_ex(("11.0.0.2", port)); socks.append(s); sel.register(s, selectors.EVENT_WRITE)
done, end = 0, time.time() + 10
while done < len(socks) and time.time() < end:
    for k, _ in sel.select(1):
        sel.unregister(k.fileobj)
        if k.fileobj.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0: done += 1
print(done)
P2
)
kill "$srv_listener" 2>/dev/null
if [[ $ok == 3000 && $(counters) == "$before" ]]; then
    echo "ok   100 users testing 30 configs at once: 3000 of 3000 connect, nothing counted"
else
    echo "FAIL 100 users testing 30 configs at once: $ok of 3000 connect, counters $( [[ $(counters) == "$before" ]] && echo unchanged || echo changed)"; rc=1
fi
# Threat lists, from local copies of the sources. 10.0.0.0/8 (private) and
# 11.0.0.0/4 (too wide) are left out; 11.0.50.9 lies inside 11.0.50.0/24.
mkdir -p "$work/feeds" "$work/bin"
cat >"$work/feeds/drop4.json" <<'J'
{"cidr":"11.0.50.0/24","sblid":"SBL1","rir":"ripencc"}
{"cidr":"10.0.0.0/8","sblid":"SBL2","rir":"ripencc"}
{"cidr":"11.0.0.0/4","sblid":"SBL3","rir":"ripencc"}
{"type":"metadata","timestamp":1,"size":1,"records":3}
J
printf '{"cidr":"2001:db9::/32","sblid":"SBL4","rir":"ripencc"}\n{"type":"metadata"}\n' >"$work/feeds/drop6.json"
printf '# Feodo Tracker\r\n11.0.51.7\r\n11.0.50.9\r\n' >"$work/feeds/feodo.txt"
sources() { printf 'drop4 %s 1\ndrop6 file://%s/feeds/drop6.json 0\nfeodo file://%s/feeds/feodo.txt 0\n' "$1" "$work" "$work"; }
lists() { XUI_LOG_FOLDER=$work XUI_THREAT_DIR=$work/lists XUI_THREAT_SOURCES=$1 in_srv bash "$SCRIPT" anti-abuse lists "${2:-fetch}"; }
threat_checks() {
    in_srv python3 - "$1" <<'P4'
import socket, subprocess, sys
def tcp(ip, port):
    s = socket.socket(); s.settimeout(2)
    try: s.connect((ip, port)); return "open"
    except ConnectionRefusedError: return "refused"
    except OSError as e: return "error %d" % e.errno
    finally: s.close()
def udp(ip, port):
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.settimeout(1)
    try: u.sendto(b"x", (ip, port))
    except OSError: u.close(); return "refused"
    try: u.recvfrom(10); return "answer"
    except OSError: return "no answer"
    finally: u.close()
# 11.0.50.20 is only in drop4, 11.0.51.7 only in feodo
got = (tcp("11.0.50.9", 443), tcp("11.0.50.20", 443), tcp("11.0.51.7", 443), tcp("11.0.51.8", 443), tcp("11.0.60.1", 443),
       udp("11.0.50.20", 443) != "answer", udp("11.0.51.8", 443))
ok = got == ("refused", "refused", "refused", "open", "open", True, "answer")
print(("ok   " if ok else "FAIL ") + sys.argv[1] + ": listed refused, others open %s" % (got,))
sys.exit(0 if ok else 1)
P4
}
lists "$(sources "file://$work/feeds/drop4.json")" || { echo "FAIL anti-abuse lists"; rc=1; }
threat_checks "threat lists loaded" || rc=1
set4=$(in_srv nft list set inet xui_anti_abuse threats4)
set6=$(in_srv nft list set inet xui_anti_abuse threats6)
if [[ $set4 != *10.0.0.0* && $set4 != *11.0.0.0/4* && $set6 == *2001:db9::/32* && $(grep -c . <<<"$(grep '^# networks: 4$' "$work/lists/threats.nft")") == 1 ]]; then
    echo "ok   private and too-wide entries left out; 4 networks"
else
    echo "FAIL threat sets: $set4 $set6 $(grep '^# networks' "$work/lists/threats.nft")"; rc=1
fi
# Only connections the server opens are refused: a user on a listed network
# still reaches the server.
in_srv python3 - >"$work/in.log" 2>&1 <<'P5' &
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); s.bind(("0.0.0.0", 20900)); s.listen(8)
print("ready", flush=True)
while True: s.accept()[0].close()
P5
in_listener=$!
for _ in $(seq 1 50); do grep -q ready "$work/in.log" 2>/dev/null && break; sleep 0.1; done
if in_net python3 -c '
import socket; s = socket.socket(); s.setsockopt(socket.SOL_IP, 19, 1); s.bind(("11.0.50.20", 0)); s.settimeout(3); s.connect(("11.0.0.2", 20900))'; then
    echo "ok   a user on a listed network still connects to the server"
else
    echo "FAIL a user on a listed network cannot connect to the server"; rc=1
fi
kill "$in_listener" 2>/dev/null
threats=$(in_srv nft list counter inet xui_anti_abuse threats | grep -oE 'packets [0-9]+' | cut -d' ' -f2)
if ((threats >= 2)); then echo "ok   refused attempts counted ($threats)"; else echo "FAIL threats counter $threats"; rc=1; fi
lists "$(sources file:///nonexistent/drop4.json)" || { echo "FAIL anti-abuse lists (a source down)"; rc=1; }
threat_checks "a source that cannot be fetched keeps its last copy" || rc=1
printf '{"cidr":"11.0.60.0/24"}\n' >"$work/feeds/short.json"
lists "$(sources "file://$work/feeds/short.json" | sed '1s/ 1$/ 500/')" || { echo "FAIL anti-abuse lists (a short copy)"; rc=1; }
threat_checks "a copy with too few entries is not taken" || rc=1
in_srv nft -f "$work/rules.nft"
in_srv sh -c "[ ! -f $work/lists/threats.nft ] || nft -f $work/lists/threats.nft"
threat_checks "reloading the rules (the unit's ExecReload) loads them again" || rc=1

# Spamhaus: a dig that lists 11.0.0.2 on XBL; 10.5.0.2 is private, not asked.
cat >"$work/bin/dig" <<'D'
#!/bin/sh
echo "$*" >>"$(dirname "$0")/asked"
case "$*" in *2.0.0.11.zen.spamhaus.org*@a.gns.spamhaus.org*) echo 127.0.0.4 ;; esac
D
chmod +x "$work/bin/dig"
got=$(in_srv env PATH="$work/bin:$PATH" bash -c 'eval "$(sed -n "/^anti_abuse_entries() {/,/^}/p; /^anti_abuse_spamhaus() {/,/^}/p" "$1")"; anti_abuse_spamhaus' _ "$SCRIPT")
if [[ $got == "11.0.0.2 XBL" ]] && ! grep -q 2.5.10 "$work/bin/asked"; then
    echo "ok   Spamhaus: 11.0.0.2 XBL found, the private address not asked"
else
    echo "FAIL Spamhaus check: '$got'; asked: $(cat "$work/bin/asked" 2>/dev/null)"; rc=1
fi

host_after=$(nft list tables 2>/dev/null | sort | sha256sum)
if [[ $host_before == "$host_after" ]]; then echo "ok   the host's own nftables tables are unchanged"; else echo "FAIL the host's nftables tables changed"; rc=1; fi
exit $rc
