#!/bin/bash
# validate-real-client.sh [case...]
#
# Checks the interop harness with the real OpenVPN client (/usr/sbin/openvpn)
# before anything else relies on it. For every case in cases.json (or the
# ones named) it runs the client with the case's .ovpn inside a throwaway
# namespace "ovpnreal" (veth ovr0 in ovpntest, 10.215.0.1/24 <-> ovr1,
# 10.215.0.2/24; the tun device and its routes live only there), with
# --route-nopull, and then checks through the tunnel:
#
#   - GET /hello is "hello from ovpntest", GET /ip is the client's tunnel IP
#   - a 1 MB /blob matches the same blob fetched inside ovpntest
#   - UDP echo on :5353; HTTP and UDP over IPv6 for the case that has it
#   - the server log names the expected data cipher and TLS version
#   - compression cases: the server log shows the compression in use, and
#     the client's statistics (SIGUSR2) show it decompressed a 2 MB /text
#     to more than twice its wire size (so the server really compressed)
#   - the stub case: the server log shows compression 'stub'
#   - udp-reneg: at least two renegotiations while traffic keeps flowing
#   - one wrong password is answered with AUTH_FAILED
#
# The namespace is removed afterwards. Brings the harness up if needed and
# leaves it as it was found otherwise. Exit status 0 only when every case
# passed.
set -euo pipefail

for fd in /proc/$$/fd/*; do
	fd=${fd##*/}
	if [[ $fd =~ ^[0-9]+$ ]] && ((fd > 2 && fd != 255)); then
		eval "exec $fd>&-" 2>/dev/null || true
	fi
done

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
HARNESS=$HERE/harness.sh
DIR=${OVPN_INTEROP_DIR:-/tmp/ovpn-interop}
OPENVPN=${OPENVPN:-/usr/sbin/openvpn}
NS=ovpntest
RNS=ovpnreal
PEER_IF=ovr0
RNS_IF=ovr1
GW=10.215.0.1
CLI=10.215.0.2
GW6=fd00:215::1
CLI6=fd00:215::2
TUN=ovreal
PIDFILE=$DIR/run/real-client.pid

say() { printf '%s\n' "$*"; }
die() {
	say "validate: error: $*" >&2
	exit 1
}
[ "$(id -u)" = 0 ] || die "must run as root"

cases_tsv() {
	if command -v jq >/dev/null 2>&1; then
		jq -r '.[] | [.name, .ovpn, .proto, (.port|tostring), .tunnelServerIP, (.tunnelServerIPv6 // ""), (.cipher // ""), (.tlsVersion // ""), (.compression // ""), .serverLog, (.username // ""), (.password // "")] | map(if . == "" then "-" else . end) | @tsv' "$DIR/cases.json"
	else
		python3 -c '
import json, sys
for c in json.load(open(sys.argv[1])):
    f = [c["name"], c["ovpn"], c["proto"], str(c["port"]), c["tunnelServerIP"], c.get("tunnelServerIPv6", ""), c.get("cipher", ""), c.get("tlsVersion", ""), c.get("compression", ""), c["serverLog"], c.get("username", ""), c.get("password", "")]
    print("\t".join(x if x else "-" for x in f))' "$DIR/cases.json"
	fi
}

stop_client() {
	local pid
	[ -f "$PIDFILE" ] || return 0
	pid=$(cat "$PIDFILE" 2>/dev/null || true)
	if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		for _ in $(seq 50); do
			kill -0 "$pid" 2>/dev/null || break
			sleep 0.1
		done
		kill -9 "$pid" 2>/dev/null || true
	fi
	rm -f "$PIDFILE"
	# The tun device goes with the process; wait for it so the next client
	# can take the name.
	for _ in $(seq 50); do
		ip -n "$RNS" link show "$TUN" >/dev/null 2>&1 || return 0
		sleep 0.1
	done
}

cleanup() {
	stop_client || true
	if ip netns list | grep -qw "^$RNS"; then
		local pids
		pids=$(ip netns pids "$RNS" 2>/dev/null || true)
		if [ -n "$pids" ]; then
			kill $pids 2>/dev/null || true
			sleep 1
			pids=$(ip netns pids "$RNS" 2>/dev/null || true)
			[ -z "$pids" ] || kill -9 $pids 2>/dev/null || true
			sleep 0.2
		fi
		ip netns del "$RNS" 2>/dev/null || true
	fi
	ip -n "$NS" link del "$PEER_IF" 2>/dev/null || true
}

ns_up() {
	cleanup
	ip netns add "$RNS"
	ip -n "$RNS" link set lo up
	ip -n "$NS" link add "$PEER_IF" type veth peer name "$RNS_IF" netns "$RNS"
	ip -n "$NS" addr add "$GW/24" dev "$PEER_IF"
	ip -n "$NS" -6 addr add "$GW6/64" dev "$PEER_IF" nodad
	ip -n "$NS" link set "$PEER_IF" up
	ip -n "$RNS" addr add "$CLI/24" dev "$RNS_IF"
	ip -n "$RNS" -6 addr add "$CLI6/64" dev "$RNS_IF" nodad
	ip -n "$RNS" link set "$RNS_IF" up
	ip -n "$RNS" route add 10.213.0.0/24 via "$GW"
	ip -n "$RNS" -6 route add fd00:213::/64 via "$GW6"
}

in_rns() { ip netns exec "$RNS" "$@"; }

# start_client name ovpn log [extra openvpn args...]
start_client() {
	local name=$1 ovpn=$2 log=$3
	shift 3
	rm -f "$log"
	in_rns "$OPENVPN" --config "$ovpn" --route-nopull --disable-dco --dev-type tun --dev "$TUN" \
		--verb 4 --log "$log" --writepid "$PIDFILE" --daemon "ovpnreal-$name" "$@" </dev/null >/dev/null 2>&1 9>&-
}

# wait_client log -> 0 connected, 1 AUTH_FAILED, 2 died or timed out
wait_client() {
	local log=$1
	for _ in $(seq 300); do
		grep -q 'Initialization Sequence Completed' "$log" 2>/dev/null && return 0
		grep -q 'AUTH_FAILED' "$log" 2>/dev/null && return 1
		if grep -qE 'Exiting due to fatal error|SIGTERM\[soft,|process exiting' "$log" 2>/dev/null; then
			return 2
		fi
		sleep 0.1
	done
	return 2
}

since() { tail -c +"$(($2 + 1))" "$1"; } # file offset

elapsed() { awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", b - a }'; }

FAILS=()
fail() {
	CASE_OK=no
	say "    FAIL: $*"
}
ok() { say "    ok: $*"; }

http_get() { in_rns curl -sS -g --max-time "${2:-15}" "$1"; }

udp_echo() { # host port payload [udp|udp6]
	local proto=${4:-UDP} host=$1
	[ "$proto" = UDP6 ] && host="[$host]"
	printf '%s' "$3" | in_rns timeout 6 socat -t3 - "$proto:$host:$2" 2>/dev/null || true
}

check_traffic() { # label serverip clientip family
	local label=$1 sip=$2 cip=$3 fam=$4 url body got
	if [ "$fam" = 6 ]; then url="http://[$sip]:8080"; else url="http://$sip:8080"; fi
	body=$(http_get "$url/hello" 2>&1 || true)
	if [ "$body" = "hello from ovpntest" ]; then ok "$label GET /hello"; else fail "$label GET /hello: '$body'"; fi
	got=$(http_get "$url/ip" 2>&1 || true)
	if [ "$got" = "$cip" ]; then ok "$label GET /ip = $cip"; else fail "$label GET /ip: '$got', want $cip"; fi
	got=$(http_get "$url/blob?size=1000000&seed=7" 30 | sha256sum | cut -d' ' -f1)
	if [ "$got" = "$BLOB_SHA" ]; then ok "$label 1 MB /blob sha256"; else fail "$label /blob sha256 $got, want $BLOB_SHA"; fi
	local proto=UDP
	[ "$fam" = 6 ] && proto=UDP6
	got=$(udp_echo "$sip" 5353 "echo-$label-$$" "$proto")
	if [ "$got" = "echo-$label-$$" ]; then ok "$label UDP echo"; else fail "$label UDP echo: '$got'"; fi
}

run_case() {
	local name=$1 ovpn=$2 proto=$3 port=$4 sip=$5 sip6=$6 cipher=$7 tlsv=$8 comp=$9 slog=${10}
	local log=$DIR/logs/real-$name.log off t0 t1 cip cip6 slogtxt
	CASE_OK=yes
	say "== $name ($proto/$port)"
	off=$(stat -c %s "$slog")
	t0=$(date +%s.%N)
	start_client "$name" "$ovpn" "$log"
	if ! wait_client "$log"; then
		fail "client did not connect (see $log)"
		grep -E 'error|ERROR|fail|FAIL' "$log" | tail -5 | sed 's/^/      /' || true
		stop_client
		FAILS+=("$name")
		return
	fi
	t1=$(date +%s.%N)
	ok "connected in $(elapsed "$t0" "$t1") s"
	cip=$(ip -n "$RNS" -4 -o addr show dev "$TUN" | awk '{print $4}' | head -1)
	cip=${cip%/*}
	# --route-nopull: reach the server's tunnel address over the tun
	# (net30 has no on-link route to it).
	ip -n "$RNS" route replace "${sip%.*}.0/24" dev "$TUN"
	check_traffic "IPv4" "$sip" "$cip" 4
	if [ "$sip6" != - ]; then
		cip6=$(ip -n "$RNS" -6 -o addr show dev "$TUN" scope global | awk '{print $4}' | head -1)
		cip6=${cip6%/*}
		if [ -z "$cip6" ]; then
			fail "no IPv6 address on the tunnel"
		else
			check_traffic "IPv6" "$sip6" "$cip6" 6
		fi
	fi

	slogtxt=$(since "$slog" "$off")
	if grep -q "Data Channel: cipher '$cipher'" <<<"$slogtxt"; then ok "server: data cipher $cipher"; else fail "server log does not show data cipher $cipher"; fi
	local tlsre="Control Channel: TLSv${tlsv#TLS }"
	if grep -q "$tlsre" <<<"$slogtxt"; then ok "server: ${tlsv}"; else fail "server log does not show $tlsre"; fi

	case $comp in
	lz4-v2 | lzo)
		local want=lz4v2
		[ "$comp" = lzo ] && want=lzo
		if grep -q "compression: '$want'" <<<"$slogtxt"; then ok "server: compression '$want' in use"; else fail "server log does not show compression '$want'"; fi
		local got pre post
		got=$(http_get "http://$sip:8080/text?size=2000000" 30 | sha256sum | cut -d' ' -f1)
		[ "$got" = "$TEXT_SHA" ] && ok "2 MB /text sha256" || fail "/text sha256 $got, want $TEXT_SHA"
		kill -USR2 "$(cat "$PIDFILE")"
		sleep 1
		pre=$(grep 'pre-decompress bytes,' "$log" | tail -1 | cut -d, -f2)
		post=$(grep 'post-decompress bytes,' "$log" | tail -1 | cut -d, -f2)
		if [ -n "$pre" ] && [ "${pre:-0}" -gt 0 ] && [ "${post:-0}" -gt $((2 * pre)) ]; then
			ok "server compressed: client decompressed $pre -> $post bytes"
		else
			fail "no real compression from the server: pre-decompress ${pre:-?}, post-decompress ${post:-?}"
		fi
		;;
	stub)
		if grep -q "compression: 'stub'" <<<"$slogtxt"; then ok "server: compression 'stub' framing"; else fail "server log does not show compression 'stub'"; fi
		;;
	esac

	if [ "$name" = udp-reneg ]; then
		# Keep traffic flowing and wait for two soft resets (reneg-sec 15,
		# randomised down to 70% on the server).
		local n=0 end=$((SECONDS + 45))
		while [ $SECONDS -lt $end ]; do
			n=$(since "$slog" "$off" | grep -c 'Control Channel: TLSv' || true)
			[ "$n" -ge 3 ] && break
			http_get "http://$sip:8080/blob?size=100000&seed=$SECONDS" 10 >/dev/null || true
			sleep 1
		done
		if [ "$n" -ge 3 ]; then ok "renegotiated $((n - 1)) times"; else fail "only $((n - 1)) renegotiations in 45 s"; fi
		body=$(http_get "http://$sip:8080/hello" 2>&1 || true)
		[ "$body" = "hello from ovpntest" ] && ok "traffic after renegotiation" || fail "GET /hello after renegotiation: '$body'"
	fi

	stop_client
	if [ $CASE_OK = yes ]; then say "   PASS $name"; else
		say "   FAIL $name"
		FAILS+=("$name")
	fi
}

wrong_password() { # name ovpn
	local name=$1 ovpn=$2 log=$DIR/logs/real-$1-wrongpass.log creds rc t0 t1
	CASE_OK=yes
	say "== $name with a wrong password"
	creds=$(mktemp "$DIR/tmp/creds.XXXXXX")
	printf 'ovpnuser\nnot-the-password\n' >"$creds"
	t0=$(date +%s.%N)
	start_client "$name-wrongpass" "$ovpn" "$log" --auth-user-pass "$creds" --auth-retry none
	rc=0
	wait_client "$log" || rc=$?
	t1=$(date +%s.%N)
	rm -f "$creds"
	if [ $rc = 1 ]; then
		ok "AUTH_FAILED after $(elapsed "$t0" "$t1") s"
	else
		fail "expected AUTH_FAILED (wait status $rc, see $log)"
	fi
	stop_client
	if [ $CASE_OK = yes ]; then say "   PASS $name wrong password"; else
		say "   FAIL $name wrong password"
		FAILS+=("$name-wrongpass")
	fi
}

main() {
	trap cleanup EXIT
	trap 'exit 130' INT TERM
	command -v socat >/dev/null || die "socat is needed"
	bash "$HARNESS" status >/dev/null 2>&1 || bash "$HARNESS" up
	ns_up
	BLOB_SHA=$(ip netns exec "$NS" curl -s "http://127.0.0.1:8080/blob?size=1000000&seed=7" | sha256sum | cut -d' ' -f1)
	TEXT_SHA=$(ip netns exec "$NS" curl -s "http://127.0.0.1:8080/text?size=2000000" | sha256sum | cut -d' ' -f1)
	local total=0 want=("$@") name
	while IFS=$'\t' read -r name ovpn proto port sip sip6 cipher tlsv comp slog user pass; do
		if [ ${#want[@]} -gt 0 ] && [[ " ${want[*]} " != *" $name "* ]]; then continue; fi
		total=$((total + 1))
		run_case "$name" "$ovpn" "$proto" "$port" "$sip" "$sip6" "$cipher" "$tlsv" "$comp" "$slog"
		if [ "$user" != - ]; then wrong_password "$name" "$ovpn"; fi
	done < <(cases_tsv)
	say ""
	if [ ${#FAILS[@]} -eq 0 ]; then
		say "validate: all $total cases passed with the real OpenVPN client"
	else
		say "validate: ${#FAILS[@]} failed: ${FAILS[*]}"
		exit 1
	fi
}

main "$@"
