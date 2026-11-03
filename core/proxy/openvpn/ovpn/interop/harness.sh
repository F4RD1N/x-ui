#!/bin/bash
# OpenVPN interop harness: stock OpenVPN 2.6 servers in a network namespace.
#
#   harness.sh up      build everything that is missing and start it (idempotent)
#   harness.sh down    stop every process, remove the namespaces and the veth
#   harness.sh status  print the state; exit 0 only when everything is up
#   harness.sh purge   down, then delete $OVPN_INTEROP_DIR
#
# Layout (see DESIGN.md, "Interop harness contract"):
#   namespace ovpntest, veth ovt0 (host, 10.213.0.1/24) <-> ovt1 (namespace,
#   10.213.0.2/24); one OpenVPN server per case listening on all namespace
#   addresses; the test server (testsrv) on :8080 HTTP and :5353 UDP echo,
#   IPv4 and IPv6. A client reaches the test server at the case's server
#   tunnel address (10.8x.0.1, fd81::1 for the IPv6 case).
#
#   Clients connect from namespace ovpncli (veth ovc0 in ovpntest,
#   10.214.0.1/24 + fd00:214::1/64 <-> ovc1, 10.214.0.2/24 + fd00:214::2/64,
#   routes to 10.213.0.0/24 and fd00:213::/64), not from the host: the host's
#   own firewall may drop host traffic to private addresses (this box drops
#   all host IPv4 output to 10.0.0.0/8). The Go helper interop.Dial creates
#   its sockets in ovpncli.
#
#   $OVPN_INTEROP_DIR (default /tmp/ovpn-interop):
#     pki/            easy-rsa PKI (CA, server cert with serverAuth, client cert)
#     keys/           tls-auth, tls-crypt and tls-crypt-v2 keys
#     server/<case>.conf, client/<case>.ovpn (client files have everything inline)
#     logs/<case>.log (verb 4), logs/<case>.status, logs/testsrv.log
#     run/<case>.pid, run/testsrv.pid
#     cases.json
#
# The test server is built with "ovpn-gorun go build" (plain "go build" when
# this script already runs under ovpn-gorun, e.g. from a test; OVPN_GORUN
# overrides the wrapper, OVPN_GORUN=none means plain go).
set -euo pipefail

# Close every inherited descriptor above stderr: a daemon started below must
# not keep a caller's lock (ovpn-gorun's flock) or pipe open. Bash reads this
# script from fd 255, which it marks close-on-exec itself.
for fd in /proc/$$/fd/*; do
	fd=${fd##*/}
	if [[ $fd =~ ^[0-9]+$ ]] && ((fd > 2 && fd != 255)); then
		eval "exec $fd>&-" 2>/dev/null || true
	fi
done

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../../../.." && pwd)
DIR=${OVPN_INTEROP_DIR:-/tmp/ovpn-interop}
NS=ovpntest
CLI_NS=ovpncli # tests dial from here (veth ovc0 in ovpntest <-> ovc1)
CLI_NS_PEER=ovc0
CLI_IF=ovc1
CLI_GW=10.214.0.1
CLI_IP=10.214.0.2
CLI_GW6=fd00:214::1
CLI_IP6=fd00:214::2
REAL_NS=ovpnreal # validate-real-client.sh's namespace
HOST_IF=ovt0
NS_IF=ovt1
HOST_IP=10.213.0.1
SERVER_IP=10.213.0.2
HOST_IP6=fd00:213::1
SERVER_IP6=fd00:213::2
USERNAME=ovpnuser
PASSWORD=s3cret-pass
EASYRSA=${EASYRSA:-/usr/share/easy-rsa/easyrsa}
OPENVPN=${OPENVPN:-/usr/sbin/openvpn}
LOCK=/run/ovpn-interop.lock

# Cases in order: name proto port. The tunnel subnet is 10.(80+n).0.0/24 for
# the n-th case (10.81.0.0/24 .. 10.91.0.0/24).
CASES=(
	"udp-gcm-tlscrypt udp 1194"
	"tcp-gcm-tlsauth tcp 1195"
	"udp-cbc-sha1-net30 udp 1196"
	"udp-chacha-userpass udp 1197"
	"udp-tlscryptv2 udp 1198"
	"udp-lz4v2 udp 1199"
	"udp-complzo udp 1200"
	"udp-reneg udp 1201"
	"tcp-tls12-cbc tcp 1202"
	"udp-compress-stub udp 1203"
	"udp-certpass udp 1204"
)

log() { printf 'harness: %s\n' "$*" >&2; }
die() {
	log "error: $*"
	exit 1
}

need_root() { [ "$(id -u)" = 0 ] || die "must run as root"; }

# inside_gorun reports whether an ancestor process is ovpn-gorun's flock, in
# which case the Go build lock is already ours and a nested ovpn-gorun would
# wait for it forever.
inside_gorun() {
	local pid=$$ ppid
	while [ -n "$pid" ] && [ "$pid" -gt 1 ]; do
		if tr '\0' ' ' <"/proc/$pid/cmdline" 2>/dev/null | grep -q 'ovpn-go\.lock'; then
			return 0
		fi
		ppid=$(awk '/^PPid:/ {print $2}' "/proc/$pid/status" 2>/dev/null || true)
		pid=$ppid
	done
	return 1
}

gorun() {
	local wrap=${OVPN_GORUN:-}
	if [ -z "$wrap" ]; then
		if inside_gorun; then
			wrap=none
		elif command -v ovpn-gorun >/dev/null 2>&1; then
			wrap=ovpn-gorun
		else
			wrap=none
		fi
	fi
	if [ "$wrap" = none ]; then
		"$@"
	else
		"$wrap" "$@"
	fi
}

# write_if_changed FILE: stdin becomes FILE unless FILE already has exactly
# that content. Returns 0 when the file changed.
write_if_changed() {
	local f=$1 tmp
	tmp=$(mktemp "$f.XXXXXX")
	cat >"$tmp"
	if [ -f "$f" ] && cmp -s "$tmp" "$f"; then
		rm -f "$tmp"
		return 1
	fi
	mv -f "$tmp" "$f"
	return 0
}

pem_only() { sed -n '/-----BEGIN/,/-----END/p' "$1"; }

alive() { # pidfile
	local pid
	[ -f "$1" ] || return 1
	pid=$(cat "$1" 2>/dev/null) || return 1
	[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

stop_pidfile() { # pidfile
	local pid i
	[ -f "$1" ] || return 0
	pid=$(cat "$1" 2>/dev/null || true)
	if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || true
		for i in $(seq 50); do
			kill -0 "$pid" 2>/dev/null || break
			sleep 0.1
		done
		kill -9 "$pid" 2>/dev/null || true
	fi
	rm -f "$1"
}

# ---------------------------------------------------------------- network

ns_add() { # name
	if ! ip netns list | grep -qw "^$1"; then
		log "creating namespace $1"
		ip netns add "$1"
	fi
	ip -n "$1" link set lo up
}

net_up() {
	ns_add "$NS"
	if ! ip link show "$HOST_IF" >/dev/null 2>&1; then
		log "creating veth $HOST_IF <-> $NS/$NS_IF"
		ip link add "$HOST_IF" type veth peer name "$NS_IF" netns "$NS"
	fi
	ip addr replace "$HOST_IP/24" dev "$HOST_IF"
	ip -6 addr replace "$HOST_IP6/64" dev "$HOST_IF" nodad 2>/dev/null || true
	ip link set "$HOST_IF" up
	ip -n "$NS" addr replace "$SERVER_IP/24" dev "$NS_IF"
	ip -n "$NS" -6 addr replace "$SERVER_IP6/64" dev "$NS_IF" nodad 2>/dev/null || true
	ip -n "$NS" link set "$NS_IF" up

	# The client namespace: where tests dial from (interop.Dial). The host
	# may filter its own traffic to private addresses; this path never
	# touches the host's network stack.
	ns_add "$CLI_NS"
	if ! ip -n "$NS" link show "$CLI_NS_PEER" >/dev/null 2>&1; then
		log "creating veth $NS/$CLI_NS_PEER <-> $CLI_NS/$CLI_IF"
		ip -n "$CLI_NS" link del "$CLI_IF" 2>/dev/null || true
		ip -n "$NS" link add "$CLI_NS_PEER" type veth peer name "$CLI_IF" netns "$CLI_NS"
	fi
	ip -n "$NS" addr replace "$CLI_GW/24" dev "$CLI_NS_PEER"
	ip -n "$NS" -6 addr replace "$CLI_GW6/64" dev "$CLI_NS_PEER" nodad
	ip -n "$NS" link set "$CLI_NS_PEER" up
	ip -n "$CLI_NS" addr replace "$CLI_IP/24" dev "$CLI_IF"
	ip -n "$CLI_NS" -6 addr replace "$CLI_IP6/64" dev "$CLI_IF" nodad
	ip -n "$CLI_NS" link set "$CLI_IF" up
	ip -n "$CLI_NS" route replace "${SERVER_IP%.*}.0/24" via "$CLI_GW"
	ip -n "$CLI_NS" -6 route replace "${SERVER_IP6%::*}::/64" via "$CLI_GW6"
}

kill_ns_procs() { # namespace
	local pids
	ip netns list | grep -qw "^$1" || return 0
	pids=$(ip netns pids "$1" 2>/dev/null || true)
	[ -n "$pids" ] || return 0
	kill $pids 2>/dev/null || true
	for _ in $(seq 50); do
		pids=$(ip netns pids "$1" 2>/dev/null || true)
		[ -n "$pids" ] || return 0
		sleep 0.1
	done
	kill -9 $pids 2>/dev/null || true
	sleep 0.2
}

net_down() {
	local ns
	for ns in "$REAL_NS" "$CLI_NS" "$NS"; do
		if ip netns list | grep -qw "^$ns"; then
			kill_ns_procs "$ns"
			ip netns del "$ns"
			log "removed namespace $ns"
		fi
	done
	if ip link show "$HOST_IF" >/dev/null 2>&1; then
		ip link del "$HOST_IF"
		log "removed $HOST_IF"
	fi
}

# ---------------------------------------------------------------- keys

pki_up() {
	mkdir -p "$DIR"/{pki,keys,server,client,logs,run,bin,auth,tmp}
	chmod 700 "$DIR/tmp"
	local pki=$DIR/pki
	if [ ! -f "$pki/ca.crt" ] || [ ! -f "$pki/issued/server.crt" ] || [ ! -f "$pki/issued/client.crt" ]; then
		log "generating PKI with easy-rsa in $pki"
		rm -rf "$pki"
		(
			export EASYRSA_PKI=$pki EASYRSA_BATCH=1 EASYRSA_KEY_SIZE=2048
			cd "$DIR"
			"$EASYRSA" init-pki >/dev/null 2>&1
			EASYRSA_REQ_CN="ovpntest CA" "$EASYRSA" build-ca nopass >/dev/null 2>&1
			"$EASYRSA" build-server-full server nopass >/dev/null 2>&1
			"$EASYRSA" build-client-full client nopass >/dev/null 2>&1
		) || die "easy-rsa failed (run it by hand with EASYRSA_PKI=$pki to see why)"
	fi
	local k=$DIR/keys
	[ -s "$k/ta.key" ] || "$OPENVPN" --genkey secret "$k/ta.key" >/dev/null
	[ -s "$k/tc.key" ] || "$OPENVPN" --genkey secret "$k/tc.key" >/dev/null
	if [ ! -s "$k/tcv2-server.key" ]; then
		"$OPENVPN" --genkey tls-crypt-v2-server "$k/tcv2-server.key" >/dev/null
		rm -f "$k/tcv2-client.key"
	fi
	[ -s "$k/tcv2-client.key" ] ||
		"$OPENVPN" --tls-crypt-v2 "$k/tcv2-server.key" --genkey tls-crypt-v2-client "$k/tcv2-client.key" >/dev/null
	# PKCS#1 ("BEGIN RSA PRIVATE KEY") copy of the client key, for the case
	# that pins the traditional key format.
	[ -s "$k/client-pkcs1.key" ] ||
		openssl rsa -in "$pki/private/client.key" -traditional -out "$k/client-pkcs1.key" 2>/dev/null
	chmod 600 "$k"/*

	write_if_changed "$DIR/auth/verify.sh" <<EOF || true
#!/bin/sh
# auth-user-pass-verify via-file: \$1 holds the username and the password.
u=\$(sed -n 1p "\$1")
p=\$(sed -n 2p "\$1")
[ "\$u" = "$USERNAME" ] && [ "\$p" = "$PASSWORD" ] && exit 0
exit 1
EOF
	chmod 755 "$DIR/auth/verify.sh"
}

# ---------------------------------------------------------------- configs

server_conf() { # name proto port n
	local name=$1 proto=$2 port=$3 n=$4 net=10.$((80 + $4)).0.0
	# proto udp6/tcp6: one dual-stack socket on [::], so the server answers
	# on every namespace address, IPv4 (10.213.0.2) and IPv6 (fd00:213::2).
	cat <<EOF
# OpenVPN interop server: $name (generated by harness.sh)
port $port
proto ${proto}6
dev-type tun
dev ovs$port
ca $DIR/pki/ca.crt
cert $DIR/pki/issued/server.crt
key $DIR/pki/private/server.key
dh none
keepalive 10 60
duplicate-cn
persist-key
persist-tun
disable-dco
verb 4
log $DIR/logs/$name.log
writepid $DIR/run/$name.pid
status $DIR/logs/$name.status 5
status-version 2
tmp-dir $DIR/tmp
daemon ovpn-$name
EOF
	if [ "$proto" = udp ]; then
		echo "explicit-exit-notify 1"
		# Answer from the address the client sent to: the namespace has
		# several, and clients use connected sockets.
		echo "multihome"
	fi
	if [ "$name" = udp-cbc-sha1-net30 ]; then
		echo "topology net30"
	else
		echo "topology subnet"
	fi
	echo "server $net 255.255.255.0"
	local userpass="script-security 2
auth-user-pass-verify $DIR/auth/verify.sh via-file"
	case $name in
	udp-gcm-tlscrypt)
		cat <<EOF
tls-crypt $DIR/keys/tc.key
data-ciphers AES-256-GCM
auth SHA256
server-ipv6 fd81::/64
push "dhcp-option DNS 10.81.0.1"
EOF
		;;
	tcp-gcm-tlsauth)
		cat <<EOF
tls-auth $DIR/keys/ta.key 0
data-ciphers AES-256-GCM:AES-128-GCM
auth SHA256
EOF
		;;
	udp-cbc-sha1-net30)
		cat <<EOF
tls-auth $DIR/keys/ta.key 0
data-ciphers AES-256-CBC
data-ciphers-fallback AES-256-CBC
auth SHA1
EOF
		;;
	udp-chacha-userpass)
		cat <<EOF
data-ciphers CHACHA20-POLY1305
verify-client-cert none
username-as-common-name
$userpass
EOF
		;;
	udp-tlscryptv2)
		echo "tls-crypt-v2 $DIR/keys/tcv2-server.key"
		;;
	udp-lz4v2)
		cat <<EOF
allow-compression yes
compress lz4-v2
push "compress lz4-v2"
EOF
		;;
	udp-complzo)
		cat <<EOF
allow-compression yes
comp-lzo yes
push "comp-lzo yes"
EOF
		;;
	udp-reneg)
		cat <<EOF
tls-crypt $DIR/keys/tc.key
reneg-sec 15
EOF
		;;
	tcp-tls12-cbc)
		cat <<EOF
tls-version-max 1.2
data-ciphers AES-128-CBC
auth SHA512
EOF
		;;
	udp-compress-stub)
		cat <<EOF
compress
push "compress"
EOF
		;;
	udp-certpass)
		cat <<EOF
tls-auth $DIR/keys/ta.key 0
data-ciphers AES-128-GCM
$userpass
push "redirect-gateway def1 bypass-dhcp"
EOF
		;;
	esac
}

inline() { # tag file [pem-only]
	echo "<$1>"
	if [ "${3:-}" = pem ]; then pem_only "$2"; else cat "$2"; fi
	echo "</$1>"
}

client_ovpn() { # name proto port
	local name=$1 proto=$2 port=$3
	local cert=$DIR/pki/issued/client.crt key=$DIR/pki/private/client.key certmode=pem
	local cproto=$proto userpass=no withcert=yes
	echo "# OpenVPN interop client: $name (generated by harness.sh, everything inline)"
	echo "client"
	echo "dev tun"
	case $name in
	tcp-gcm-tlsauth) cproto=tcp-client ;;
	esac
	echo "proto $cproto"
	echo "remote $SERVER_IP $port"
	cat <<EOF
nobind
resolv-retry infinite
persist-key
persist-tun
remote-cert-tls server
EOF
	case $name in
	udp-gcm-tlscrypt)
		cat <<EOF
cipher AES-256-GCM
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
auth SHA256
EOF
		;;
	tcp-gcm-tlsauth)
		cat <<EOF
cipher AES-256-GCM
auth SHA256
key-direction 1
EOF
		key=$DIR/keys/client-pkcs1.key
		;;
	udp-cbc-sha1-net30)
		cat <<EOF
cipher AES-256-CBC
data-ciphers AES-256-CBC
auth SHA1
key-direction 1
EOF
		;;
	udp-chacha-userpass)
		echo "data-ciphers CHACHA20-POLY1305:AES-256-GCM"
		userpass=yes
		withcert=no
		;;
	udp-tlscryptv2)
		echo "cipher AES-256-GCM"
		;;
	udp-lz4v2)
		cat <<EOF
compress lz4-v2
allow-compression yes
EOF
		;;
	udp-complzo)
		cat <<EOF
comp-lzo yes
allow-compression yes
EOF
		;;
	udp-reneg)
		echo "cipher AES-256-GCM"
		;;
	tcp-tls12-cbc)
		cat <<EOF
cipher AES-128-CBC
data-ciphers AES-128-CBC
auth SHA512
EOF
		certmode=full
		;;
	udp-compress-stub)
		echo "compress"
		;;
	udp-certpass)
		cat <<EOF
cipher AES-128-GCM
data-ciphers AES-128-GCM
key-direction 1
EOF
		userpass=yes
		;;
	esac
	[ "$proto" = udp ] && echo "explicit-exit-notify 2"
	if [ $userpass = yes ]; then
		echo "auth-user-pass"
		printf '<auth-user-pass>\n%s\n%s\n</auth-user-pass>\n' "$USERNAME" "$PASSWORD"
	fi
	echo "verb 3"
	inline ca "$DIR/pki/ca.crt" pem
	if [ $withcert = yes ]; then
		inline cert "$cert" "$certmode"
		inline key "$key"
	fi
	case $name in
	udp-gcm-tlscrypt | udp-reneg) inline tls-crypt "$DIR/keys/tc.key" ;;
	tcp-gcm-tlsauth | udp-cbc-sha1-net30 | udp-certpass) inline tls-auth "$DIR/keys/ta.key" ;;
	udp-tlscryptv2) inline tls-crypt-v2 "$DIR/keys/tcv2-client.key" ;;
	esac
}

# case_meta name -> "cipher|tlsVersion|compression|ipv6|notes"
case_meta() {
	case $1 in
	udp-gcm-tlscrypt) echo "AES-256-GCM|TLS 1.3||fd81::1|tls-crypt, AES-256-GCM, topology subnet, IPv6 in the tunnel (server-ipv6 fd81::/64), pushes dhcp-option DNS" ;;
	tcp-gcm-tlsauth) echo "AES-256-GCM|TLS 1.3|||TCP, tls-auth (server 0 / client key-direction 1), auth SHA256; the client key is PKCS#1 (BEGIN RSA PRIVATE KEY) and the client says proto tcp-client" ;;
	udp-cbc-sha1-net30) echo "AES-256-CBC|TLS 1.3|||tls-auth, data-ciphers AES-256-CBC, auth SHA1 (CBC+HMAC data channel), topology net30 (client gets ifconfig local remote, server is 10.83.0.1)" ;;
	udp-chacha-userpass) echo "CHACHA20-POLY1305|TLS 1.3|||no control-channel protection, CHACHA20-POLY1305, username/password only (verify-client-cert none, no client certificate)" ;;
	udp-tlscryptv2) echo "AES-256-GCM|TLS 1.3|||tls-crypt-v2 (P_CONTROL_HARD_RESET_CLIENT_V3 with the wrapped client key), default data-ciphers" ;;
	udp-lz4v2) echo "AES-256-GCM|TLS 1.3|lz4-v2||compress lz4-v2 pushed, allow-compression yes: the server sends LZ4-compressed packets" ;;
	udp-complzo) echo "AES-256-GCM|TLS 1.3|lzo||comp-lzo yes pushed, allow-compression yes: the server sends LZO-compressed packets" ;;
	udp-reneg) echo "AES-256-GCM|TLS 1.3|||tls-crypt, reneg-sec 15 on the server: it soft-resets every 13.5-15 s (servers randomise down to 90%; the log says TLS: soft reset sec=15/15)" ;;
	tcp-tls12-cbc) echo "AES-128-CBC|TLS 1.2|||TCP, tls-version-max 1.2, data-ciphers AES-128-CBC, auth SHA512, no control-channel protection; the <cert> block is the full easy-rsa file with its text dump before the PEM" ;;
	udp-compress-stub) echo "AES-256-GCM|TLS 1.3|stub||compress (stub, swap framing) pushed as plain compress; works with the default allow-compression no because DCO is off; the server log says compression: 'stub'" ;;
	udp-certpass) echo "AES-128-GCM|TLS 1.3|||certificate and username/password, tls-auth with the default auth (SHA1 HMAC), AES-128-GCM; pushes redirect-gateway def1" ;;
	esac
}

configs_up() {
	local c name proto port n i=1 json="" sep="" meta cipher tlsv comp v6 notes user pass changed
	for c in "${CASES[@]}"; do
		set -- $c
		name=$1 proto=$2 port=$3 n=$i
		server_conf "$name" "$proto" "$port" "$n" | write_if_changed "$DIR/server/$name.conf" || true
		client_ovpn "$name" "$proto" "$port" | write_if_changed "$DIR/client/$name.ovpn" || true
		chmod 600 "$DIR/client/$name.ovpn"
		IFS='|' read -r cipher tlsv comp v6 notes <<<"$(case_meta "$name")"
		user="" pass=""
		case $name in udp-chacha-userpass | udp-certpass) user=$USERNAME pass=$PASSWORD ;; esac
		json+="$sep  {\"name\": \"$name\", \"ovpn\": \"$DIR/client/$name.ovpn\", \"username\": \"$user\", \"password\": \"$pass\", \"proto\": \"$proto\", \"port\": $port, \"tunnelServerIP\": \"10.$((80 + n)).0.1\", \"tunnelServerIPv6\": \"$v6\", \"cipher\": \"$cipher\", \"tlsVersion\": \"$tlsv\", \"compression\": \"$comp\", \"serverLog\": \"$DIR/logs/$name.log\", \"notes\": \"$notes\"}"
		sep=$',\n'
		i=$((i + 1))
	done
	printf '[\n%s\n]\n' "$json" | write_if_changed "$DIR/cases.json" || true
}

# ---------------------------------------------------------------- processes

testsrv_build() {
	local bin=$DIR/bin/testsrv src
	src=$(find "$HERE" -name '*.go' ! -name '*_test.go' -newer "$bin" 2>/dev/null | head -1 || true)
	if [ ! -x "$bin" ] || [ -n "$src" ]; then
		log "building testsrv"
		(cd "$REPO" && gorun go build -o "$bin.new" ./proxy/openvpn/ovpn/interop/testsrv) || die "building testsrv failed"
		mv -f "$bin.new" "$bin"
	fi
}

testsrv_up() {
	local pf=$DIR/run/testsrv.pid sum
	sum=$(sha256sum "$DIR/bin/testsrv" | cut -d' ' -f1)
	if alive "$pf" && [ "$(cat "$DIR/run/testsrv.sum" 2>/dev/null)" = "$sum" ]; then
		return 0
	fi
	stop_pidfile "$pf"
	log "starting testsrv"
	# 9>&-: the daemon must not inherit the harness lock.
	ip netns exec "$NS" setsid "$DIR/bin/testsrv" -http '[::]:8080' -udpport 5353 -pidfile "$pf" \
		</dev/null >>"$DIR/logs/testsrv.log" 2>&1 9>&- &
	echo "$sum" >"$DIR/run/testsrv.sum"
	for _ in $(seq 100); do
		if ip netns exec "$NS" curl -s --max-time 1 "http://$SERVER_IP:8080/hello" 2>/dev/null | grep -q 'hello from ovpntest'; then
			return 0
		fi
		sleep 0.1
	done
	tail -n 20 "$DIR/logs/testsrv.log" >&2 || true
	die "testsrv did not come up"
}

server_up() { # name
	local name=$1 pf=$DIR/run/$1.pid conf=$DIR/server/$1.conf sum
	sum=$(sha256sum "$conf" | cut -d' ' -f1)
	if alive "$pf" && [ "$(cat "$DIR/run/$name.sum" 2>/dev/null)" = "$sum" ]; then
		return 1
	fi
	stop_pidfile "$pf"
	rm -f "$DIR/logs/$name.log"
	ip netns exec "$NS" "$OPENVPN" --config "$conf" </dev/null >/dev/null 2>&1 9>&- ||
		{
			tail -n 20 "$DIR/logs/$name.log" >&2 || true
			die "openvpn server $name failed to start"
		}
	echo "$sum" >"$DIR/run/$name.sum"
	return 0
}

server_wait() { # name
	local name=$1
	for _ in $(seq 150); do
		if grep -q 'Initialization Sequence Completed' "$DIR/logs/$name.log" 2>/dev/null; then
			alive "$DIR/run/$name.pid" && return 0
		fi
		if [ -f "$DIR/run/$name.pid" ] && ! alive "$DIR/run/$name.pid"; then
			break
		fi
		sleep 0.1
	done
	tail -n 20 "$DIR/logs/$name.log" >&2 || true
	die "openvpn server $name did not initialise"
}

# ---------------------------------------------------------------- commands

cmd_up() {
	need_root
	mkdir -p "$DIR"
	net_up
	pki_up
	configs_up
	testsrv_build
	testsrv_up
	local c started=()
	for c in "${CASES[@]}"; do
		set -- $c
		if server_up "$1"; then started+=("$1"); fi
	done
	for c in "${started[@]}"; do server_wait "$c"; done
	[ ${#started[@]} -eq 0 ] || log "started servers: ${started[*]}"
	cmd_status >/dev/null || {
		cmd_status >&2 || true
		die "harness is not healthy after up"
	}
	log "up: $DIR/cases.json"
}

cmd_down() {
	need_root
	local f
	for f in "$DIR"/run/*.pid; do
		[ -e "$f" ] && stop_pidfile "$f"
	done
	net_down
	rm -f "$DIR"/run/*.sum
	# Anything still running from this directory (e.g. a server whose
	# namespace vanished) goes too: matched by executable, never by a mere
	# mention of the path on some other command line.
	local pids
	pids="$(exe_pids "$(readlink -f "$OPENVPN")" "--config $DIR/server/") $(exe_pids "$DIR/bin/testsrv" "")"
	if [ -n "${pids// /}" ]; then
		kill $pids 2>/dev/null || true
		sleep 1
		kill -9 $pids 2>/dev/null || true
	fi
	log "down"
}

# exe_pids EXE ARG: pids whose executable is EXE and whose command line
# contains ARG.
exe_pids() {
	local p exe
	for p in /proc/[0-9]*; do
		exe=$(readlink "$p/exe" 2>/dev/null) || continue
		exe=${exe% (deleted)}
		[ "$exe" = "$1" ] || continue
		if [ -n "$2" ] && ! tr '\0' ' ' <"$p/cmdline" 2>/dev/null | grep -qF -- "$2"; then
			continue
		fi
		printf '%s ' "${p#/proc/}"
	done
}

cmd_status() {
	local ok=0 c
	if ip netns list | grep -qw "^$NS"; then
		echo "namespace $NS: present"
	else
		echo "namespace $NS: missing"
		ok=1
	fi
	if ip link show "$HOST_IF" >/dev/null 2>&1 && ip -n "$NS" link show "$NS_IF" >/dev/null 2>&1; then
		echo "veth $HOST_IF/$NS_IF: present"
	else
		echo "veth $HOST_IF/$NS_IF: missing"
		ok=1
	fi
	if ip netns list | grep -qw "^$CLI_NS" && ip -n "$CLI_NS" link show "$CLI_IF" >/dev/null 2>&1 &&
		ip netns exec "$CLI_NS" curl -s --max-time 2 "http://$SERVER_IP:8080/hello" 2>/dev/null | grep -q 'hello from ovpntest'; then
		echo "client namespace $CLI_NS: reaches $SERVER_IP"
	else
		echo "client namespace $CLI_NS: missing or cannot reach $SERVER_IP"
		ok=1
	fi
	if [ -f "$DIR/cases.json" ]; then echo "cases: $DIR/cases.json"; else
		echo "cases: missing"
		ok=1
	fi
	if alive "$DIR/run/testsrv.pid" && ip netns exec "$NS" curl -s --max-time 2 "http://$SERVER_IP:8080/hello" 2>/dev/null | grep -q 'hello from ovpntest'; then
		echo "testsrv: running (pid $(cat "$DIR/run/testsrv.pid"))"
	else
		echo "testsrv: down"
		ok=1
	fi
	for c in "${CASES[@]}"; do
		set -- $c
		if alive "$DIR/run/$1.pid"; then
			echo "server $1 ($2/$3): running (pid $(cat "$DIR/run/$1.pid"))"
		else
			echo "server $1 ($2/$3): down"
			ok=1
		fi
	done
	return $ok
}

main() {
	local cmd=${1:-}
	case $cmd in
	up | down | purge)
		need_root
		exec 9>"$LOCK"
		flock 9
		;;
	esac
	case $cmd in
	up) cmd_up ;;
	down) cmd_down ;;
	status) cmd_status ;;
	purge)
		cmd_down
		rm -rf "$DIR"
		log "removed $DIR"
		;;
	*)
		echo "usage: $0 up|down|status|purge" >&2
		exit 2
		;;
	esac
}

main "$@"
