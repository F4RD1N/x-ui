#!/bin/bash
# End-to-end check of sendThrough pools in a throwaway netns: TCP and UDP leave
# from a pool address, the same one per client, and an address the machine
# does not have is skipped. usage: e2e.sh /path/to/xray
set -u
XRAY=$1; NS=xpool$$; D=$(mktemp -d); fail=0
cleanup(){ ip netns pids $NS 2>/dev/null | xargs -r kill 2>/dev/null; ip netns del $NS 2>/dev/null; rm -rf $D; }
trap cleanup EXIT
ip netns add $NS; X="ip netns exec $NS"
$X ip link set lo up; $X ip link add d0 type dummy; $X ip link set d0 up
for a in 1 2 3 10 $(seq 50 57); do $X ip addr add 10.10.0.$a/24 dev d0; done
cat > $D/echo.py <<'P'
import socket,threading
def tcp():
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(("10.10.0.10",7000)); s.listen(64)
    while True:
        c,a=s.accept(); c.sendall(a[0].encode()); c.close()
def udp():
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.10.0.10",7000))
    while True:
        d,a=s.recvfrom(100); s.sendto(a[0].encode(),a)
threading.Thread(target=tcp,daemon=True).start(); udp()
P
cat > $D/x.json <<'J'
{"log":{"loglevel":"warning"},
 "inbounds":[{"listen":"10.10.0.10","port":5300,"protocol":"dokodemo-door","settings":{"address":"10.10.0.10","port":7000,"network":"tcp,udp"}}],
 "outbounds":[{"protocol":"freedom","sendThrough":"10.10.0.1, 10.10.0.2,10.10.0.3,192.0.2.99"}]}
J
$X python3 -I $D/echo.py & sleep 0.5
$X $XRAY run -c $D/x.json > $D/xray.log 2>&1 & sleep 1.5
cat > $D/client.py <<'P'
import socket,sys,collections
res=collections.defaultdict(set); per=collections.Counter()
for src in [f"10.10.0.{i}" for i in range(50,58)]:
    for rnd in range(3):
        t=socket.create_connection(("10.10.0.10",5300),timeout=3,source_address=(src,0)); a=t.recv(100).decode(); t.close()
        u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.bind((src,0)); u.settimeout(3); u.sendto(b"x",("10.10.0.10",5300)); b=u.recvfrom(100)[0].decode(); u.close()
        res[src].add(("tcp",a)); res[src].add(("udp",b))
ok=True
for src,s in sorted(res.items()):
    ips={ip for _,ip in s}
    print(src,"->",sorted(s))
    if len(ips)!=1: print("  NOT STICKY"); ok=False
    for ip in ips:
        per[ip]+=1
        if ip not in ("10.10.0.1","10.10.0.2","10.10.0.3"): print("  NOT A POOL ADDRESS",ip); ok=False
print("clients per exit IP:",dict(per))
if len(per)<2: print("  ALL ON ONE IP"); ok=False
print("PASS" if ok else "FAIL"); sys.exit(0 if ok else 1)
P
$X python3 -I $D/client.py || fail=1
grep -i -E "pool|warn" $D/xray.log | head -3
exit $fail
