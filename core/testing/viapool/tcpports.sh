#!/bin/bash
# TCP ports through a sendThrough address: with the namespace's ephemeral
# range cut to 100 ports, 270 connections from one address to 3 destinations
# (90 each) fit only if the port is chosen at connect() and shared between
# destinations (IP_BIND_ADDRESS_NO_PORT); a port taken at bind() caps them at
# 100 in all. Every connection must still leave from the sendThrough address.
# usage: tcpports.sh /path/to/xray   (prints "<reached the server> <from the sendThrough address>")
set -u
XRAY=$1; NS=xtcp$$; D=$(mktemp -d)
ip netns add $NS; X="ip netns exec $NS"
$X ip link set lo up; $X ip link add d0 type dummy; $X ip link set d0 up
for a in 1 10 20 21 22; do $X ip addr add 10.10.0.$a/24 dev d0; done
$X sysctl -q -w net.ipv4.ip_local_port_range="60000 60099"
cat > $D/srv.py <<'P'
import socket,threading,sys
peers=[]
def serve(ip):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind((ip,7000)); s.listen(512)
    while True:
        c,a=s.accept(); peers.append(c); c.sendall((a[0]+"\n").encode())
for ip in ("10.10.0.20","10.10.0.21","10.10.0.22"): threading.Thread(target=serve,args=(ip,),daemon=True).start()
threading.Event().wait()
P
cat > $D/x.json <<J
{"log":{"loglevel":"none"},"inbounds":[
 {"listen":"10.10.0.10","port":5000,"protocol":"dokodemo-door","settings":{"address":"10.10.0.20","port":7000,"network":"tcp"}},
 {"listen":"10.10.0.10","port":5001,"protocol":"dokodemo-door","settings":{"address":"10.10.0.21","port":7000,"network":"tcp"}},
 {"listen":"10.10.0.10","port":5002,"protocol":"dokodemo-door","settings":{"address":"10.10.0.22","port":7000,"network":"tcp"}}],
 "outbounds":[{"protocol":"freedom","sendThrough":"10.10.0.1"}]}
J
$X python3 -I $D/srv.py & sleep 0.4; $X $XRAY run -c $D/x.json >/dev/null 2>&1 & sleep 1.5
cat > $D/c.py <<'P'
import socket
conns=[];ok=0;right=0
for i in range(270):
    c=socket.socket(); c.settimeout(3)
    try:
        c.connect(("10.10.0.10",5000+i%3)); conns.append(c)
    except Exception: pass
for c in conns:
    try:
        line=c.recv(64).decode().strip()
        if line: ok+=1; right+= line=="10.10.0.1"
    except Exception: pass
print(ok,right)
P
$X python3 -I $D/c.py
ip netns pids $NS | xargs -r kill 2>/dev/null; sleep 0.3; ip netns del $NS; rm -rf $D
