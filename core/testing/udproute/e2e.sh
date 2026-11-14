#!/bin/bash
# usage: e2e.sh /path/to/xray [/path/to/old-xray]
#
# End-to-end check of freedom's udpRouteEachDestination in throwaway network
# namespaces (client, server, remote). The server Xray runs the allow-list
# routing template (blocked first, no catch-all; TEMPLATE, default the owner's
# final-xray-slim.json, else a small built-in one of the same shape) with test
# inbounds VLESS (mux allowed), socks (UDP) and shadowsocks (aes-128-gcm), all
# sniffing like the real inbounds. A client Xray carries UDP over VLESS
# mux+XUDP, VLESS XUDP without mux, socks and shadowsocks. The remote ns owns
# the public addresses and records every datagram that reaches them.
#
# Variants: new xray with the setting on, with it off, and (if given) the old
# xray. Checks per UDP path: a session that starts with DNS and then goes to a
# non-whitelisted IP:554 / :15555 is dropped with the setting on and arrives
# otherwise; whitelisted destinations keep arriving; QUIC to an IP on no list
# passes through its sniffed SNI; the stats counters and one Info log line.
#
# LOAD=1 also runs the CPU load (LOAD_SECS, default 20; LOAD_RATE pps, 0 =
# as fast as the sender goes; LOAD_PATH socks or mux): one UDP session spraying 1, 64 and 1000
# destinations (all apps-ip), setting off vs on, server CPU from /proc.
# LOAD_ONLY=1 skips the checks and runs the load only.
# Needs root (ip netns), python3 with cryptography, nft.
set -u
[ $# -ge 1 ] || { sed -n 2p "$0"; exit 2; }
XRAY=$(readlink -f "$1"); OLD=${2:+$(readlink -f "$2")}
HERE=$(dirname "$(readlink -f "$0")"); H="python3 -I $HERE/helper.py"
TEMPLATE=${TEMPLATE:-/root/xui-d1112/whitelist-2ndvpn/final-xray-slim.json}
ASSETS=${XRAY_LOCATION_ASSET:-$(dirname "$TEMPLATE")/assets}
[ -f "$TEMPLATE" ] || echo "note: $TEMPLATE not found, using the built-in allow-list routing"
ID=$$; C=xurc$ID; S=xurs$ID; R=xurr$ID; D=$(mktemp -d /tmp/udproute.XXXXXX)
pass=0; fail=0
ok(){ echo "ok   $*"; pass=$((pass+1)); }
bad(){ echo "FAIL $*"; fail=$((fail+1)); }
cleanup(){
    for n in $C $S $R; do ip netns pids $n 2>/dev/null | xargs -r kill 2>/dev/null; done
    sleep 0.3
    for n in $C $S $R; do ip netns pids $n 2>/dev/null | xargs -r kill -9 2>/dev/null; ip netns del $n 2>/dev/null; done
    rm -rf "/etc/netns/$S" "$D"; rmdir /etc/netns 2>/dev/null
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# --- namespaces: client 10.201.0.2 <-> 10.201.0.1 server 10.202.0.1 <-> 10.202.0.2 remote
for n in $C $S $R; do ip netns add $n; ip -n $n link set lo up; done
ip link add uc$ID netns $C type veth peer name us$ID netns $S
ip link add ur$ID netns $S type veth peer name rr$ID netns $R
ip -n $C addr add 10.201.0.2/24 dev uc$ID; ip -n $C link set uc$ID up
ip -n $S addr add 10.201.0.1/24 dev us$ID; ip -n $S link set us$ID up
ip -n $S addr add 10.202.0.1/24 dev ur$ID; ip -n $S link set ur$ID up
ip -n $R addr add 10.202.0.2/24 dev rr$ID; ip -n $R link set rr$ID up
ip -n $S route add default via 10.202.0.2
# The remote ns answers for every public prefix the checks use.
for p in 45.33.0.0/16 8.8.8.0/24 8.8.4.0/24 5.42.160.0/24 23.89.0.0/20 17.253.0.0/16; do ip -n $R route add local $p dev lo; done
ip netns exec $R nft -f - <<'N'
table inet udproute {
    chain in {
        type filter hook input priority 0;
        udp dport 9000 counter drop
    }
}
N
# The server resolves the sniffed QUIC domain through its own /etc/hosts.
mkdir -p "/etc/netns/$S"
printf '127.0.0.1 localhost\n45.33.2.2 i.instagram.com\n' > "/etc/netns/$S/hosts"
printf 'nameserver 10.202.0.2\n' > "/etc/netns/$S/resolv.conf"
XC="ip netns exec $C"; XS="ip netns exec $S"; XR="ip netns exec $R"

UUID=$(cat /proc/sys/kernel/random/uuid); SSPW=$(head -c 12 /dev/urandom | base64)
$H gen-client $D/c.json $UUID "$SSPW"
$XR $H recorder $D/rec.log 53 443 554 3478 5000 5353 7777 9999 15555 15556 &
$XC "$XRAY" run -c $D/c.json > $D/c.log 2>&1 &

SPID=
start_server(){ # bin setting mode
    $H gen-server "$TEMPLATE" $D/s.json $2 $3 $UUID "$SSPW" || return 1
    $XS env XRAY_LOCATION_ASSET="$ASSETS" "$1" run -c $D/s.json > $D/s.log 2>&1 &
    SPID=$!
    for _ in $(seq 100); do $XS ss -ltn | grep -q 10.201.0.1:10003 && return 0; sleep 0.2; done
    echo "server did not start:"; tail -5 $D/s.log; return 1
}
nftpk(){ $XR nft list chain inet udproute in | grep -o 'packets [0-9]*' | cut -d' ' -f2; }
stop_server(){ [ -n "$SPID" ] && kill $SPID 2>/dev/null; wait $SPID 2>/dev/null; SPID=; }
stat_value(){ # name
    $XS "$XRAY" api statsquery --server=127.0.0.1:62789 -pattern "$1" 2>/dev/null |
        python3 -I -c 'import json,sys
try: d=json.load(sys.stdin)
except Exception: print(-1); sys.exit()
v=[int(s.get("value",0)) for s in d.get("stat",[]) if s["name"].endswith(sys.argv[1])]
print(v[0] if v else -1)' "$1"
}

run_variant(){ # name bin setting
    local v=$1
    echo "== $v: $(basename "$2"), udpRouteEachDestination=$3"
    start_server "$2" $3 e2e || { bad "$v server start"; return; }
    local guarded=0
    for p in mux xudp socks ss; do
        case $p in mux) port=20001;; xudp) port=20002;; socks) port=20003;; ss) port=20004;; esac  # helper.PATHS
        while read -r line; do
            case "$line" in ok*) pass=$((pass+1));; FAIL*) fail=$((fail+1));; esac; echo "$line"
            # each "then" datagram is sent twice; plain-dns is not full-cone (nothing to guard)
            case "$line" in *" then "*"(expected drop)"*) case "$line" in *plain-dns*) ;; *) guarded=$((guarded+1));; esac;; esac
        done < <($XC $H cases $port $p $v $D/rec.log 2>&1)
    done
    local pk ds n w
    pk=$(stat_value "udp>>>dropped_packets"); ds=$(stat_value "udp>>>dropped_destinations")
    n=$(grep -c "udpRouteEachDestination dropped" $D/s.log); w=$(grep -E "\[(Warning|Error)\]" $D/s.log | grep -ci "udproute\|udpRouteEach")
    if [ "$3" = on ] && [ "$v" != old ]; then
        [ "$pk" = $((2*guarded)) ] && ok "$v stats outbound>>>direct>>>udp>>>dropped_packets = $pk (expected $((2*guarded)))" || bad "$v stats dropped_packets = $pk (expected $((2*guarded)))"
        [ "$ds" = $guarded ] && ok "$v stats outbound>>>direct>>>udp>>>dropped_destinations = $ds (expected $guarded)" || bad "$v stats dropped_destinations = $ds (expected $guarded)"
        [ "$n" -ge 1 ] && [ "$n" -le 2 ] && ok "$v Info log lines about drops: $n" || bad "$v Info log lines about drops: $n"
        grep -m1 "udpRouteEachDestination dropped" $D/s.log | sed 's/^/     /'
    else
        [ "$pk" = -1 ] && [ "$n" = 0 ] && ok "$v no drop counters, no drop log" || bad "$v drop counters $pk / log lines $n"
    fi
    [ "$w" = 0 ] && ok "$v no Warning/Error lines about it" || bad "$v $w Warning/Error lines about it"
    stop_server
}

sleep 1
if [ "${LOAD_ONLY:-0}" != 1 ]; then
    run_variant new-on "$XRAY" on
    run_variant new-off "$XRAY" off
    [ -n "$OLD" ] && run_variant old "$OLD" on
fi

if [ "${LOAD:-0}" = 1 ]; then
    secs=${LOAD_SECS:-20}; rate=${LOAD_RATE:-0}; hz=$(getconf CLK_TCK)
    lpath=${LOAD_PATH:-socks}  # socks: straight to the server's socks inbound; mux: through the client Xray's VLESS mux+XUDP
    if [ "$lpath" = mux ]; then lhost=127.0.0.1; lport=20001; else lhost=10.201.0.1; lport=10002; fi
    echo "== load: one $lpath UDP session, ${secs}s, rate=${rate:-0} (0 = max), 200-byte datagrams to apps-ip:9000"
    printf '%-6s %-4s %10s %10s %9s %12s\n' dests set sent/s recv/s cpu% cpu-us/pkt
    for nd in 1 64 1000; do for st in off on; do
        start_server "$XRAY" $st load || { bad "load server start"; continue; }
        c0=$(nftpk)
        t0=$(awk '{print $14+$15}' /proc/$SPID/stat); w0=$(date +%s.%N)
        sent=$($XC $H load $lhost $lport $nd $secs $rate)
        sleep 0.5
        t1=$(awk '{print $14+$15}' /proc/$SPID/stat); w1=$(date +%s.%N)
        c1=$(nftpk)
        python3 -I -c "
s,r,t,w,hz,secs=$sent,$c1-$c0,$t1-$t0,$w1-$w0,$hz,$secs
cpu=t/hz
print('%-6s %-4s %10.0f %10.0f %9.1f %12.2f' % ('$nd','$st',s/secs,r/secs,100*cpu/w,1e6*cpu/max(r,1)))"
        stop_server
    done; done
fi

echo "passed $pass, failed $fail"
[ $fail = 0 ]
