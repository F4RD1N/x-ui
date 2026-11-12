#!/bin/bash
# Port capacity: with the namespace's ephemeral range cut to 100 ports, 240
# UDP flows fit through a 3-address pool but not through one address.
# usage: ports.sh /path/to/xray
set -u
XRAY=$1; rc=0
run(){ # $1 = sendThrough
  local NS=xports$$; D=$(mktemp -d)
  ip netns add $NS; local X="ip netns exec $NS"
  $X ip link set lo up; $X ip link add d0 type dummy; $X ip link set d0 up
  for a in 1 2 3 10 $(seq 50 57); do $X ip addr add 10.10.0.$a/24 dev d0; done
  $X sysctl -q -w net.ipv4.ip_local_port_range="60000 60099"
  cat > $D/echo.py <<'P'
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("10.10.0.10",7000))
while True:
    d,a=s.recvfrom(100); s.sendto(b"ok",a)
P
  printf '{"log":{"loglevel":"none"},"inbounds":[{"listen":"10.10.0.10","port":5300,"protocol":"dokodemo-door","settings":{"address":"10.10.0.10","port":7000,"network":"udp"}}],"outbounds":[{"protocol":"freedom","sendThrough":"%s"}]}' "$1" > $D/x.json
  $X python3 -I $D/echo.py & sleep 0.4; $X $XRAY run -c $D/x.json >/dev/null 2>&1 & sleep 1.5
  cat > $D/c.py <<'P'
import socket
socks=[];ok=0
for i in range(240):
    src=f"10.10.0.{50+i%8}"
    u=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); u.bind((src,0)); u.settimeout(1.5)
    u.sendto(b"x",("10.10.0.10",5300)); socks.append(u)
for u in socks:
    try: u.recvfrom(10); ok+=1
    except Exception: pass
print(ok)
P
  local n; n=$($X python3 -I $D/c.py)
  ip netns pids $NS | xargs -r kill 2>/dev/null; sleep 0.3; ip netns del $NS; rm -rf $D
  echo "$n"
}
one=$(run "10.10.0.1"); pool=$(run "10.10.0.1,10.10.0.2,10.10.0.3")
echo "240 UDP flows, 100 ports per IP: one IP -> $one answered, 3-IP pool -> $pool answered"
[ "$one" -le 100 ] && [ "$pool" -eq 240 ] && echo PASS || { echo FAIL; rc=1; }
exit $rc
