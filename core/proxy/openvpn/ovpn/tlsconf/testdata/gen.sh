#!/bin/bash
# Regenerates the fixtures the tlsconf tests read. Go cannot create SHA-1
# signed certificates or PKCS#12 files, so these come from the openssl CLI
# (OpenSSL 3). Everything is valid for 100 years; all keys are test keys.
#
#   sha1-root.pem          RSA root, self-signed with SHA-1
#   sha1-int.pem           intermediate signed by sha1-root with SHA-1
#   sha1-server.pem/.key   server leaf signed by sha1-int with SHA-1
#   sha1ec-root.pem        ECDSA P-256 root, self-signed with ecdsa-with-SHA1
#   sha1ec-server.pem/.key server leaf signed by sha1ec-root with ecdsa-with-SHA1
#   p12-ca.pem/.key        RSA CA (SHA-256) that issued the PKCS#12 clients
#   p12-int.pem            intermediate under p12-ca that issued p12-client-int
#   client-*.p12           PKCS#12 client certificates, see below
#   enc-pkcs8.key          an "ENCRYPTED PRIVATE KEY"
#   enc-pkcs1.key          a "Proc-Type: 4,ENCRYPTED" PKCS#1 key
#   pw-*                   one EC client key (pw-client.pem, issued by
#                          p12-ca) encrypted in every form keyPassword reads;
#                          see pw_fixtures below
#
# Only the pw-* fixtures: ./gen.sh pw
set -euo pipefail
cd "$(dirname "$0")"
D=36500
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

cat >"$T/ext.cnf" <<'EOF'
[req]
distinguished_name = dn
[dn]
[x_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[x_server]
basicConstraints = CA:FALSE
keyUsage = digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[x_client]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = clientAuth
EOF

# pw_fixtures writes one EC key, its certificate under p12-ca, and the key
# encrypted the ways OpenSSL and its users write it. The password is
# "secret", or "pässwörd" (UTF-8) where the name says utf8.
pw_fixtures() {
	openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$T/pw.key" -out "$T/pw.csr" \
		-subj "/CN=pw-client" -config "$T/ext.cnf" 2>/dev/null
	openssl x509 -req -in "$T/pw.csr" -CA p12-ca.pem -CAkey p12-ca.key -set_serial "0x$(openssl rand -hex 8)" \
		-days $D -sha256 -extfile "$T/ext.cnf" -extensions x_client -out pw-client.pem 2>/dev/null
	# Traditional "EC PRIVATE KEY" with Proc-Type/DEK-Info (OpenSSL, RouterOS 6).
	openssl ec -in "$T/pw.key" -aes256 -passout pass:secret -out pw-legacy-aes256.key 2>/dev/null
	openssl ec -in "$T/pw.key" -des3 -passout pass:secret -out pw-legacy-des3.key 2>/dev/null
	# PKCS#8 "ENCRYPTED PRIVATE KEY": OpenSSL 3's default, PBES2 with 3DES and
	# the SHA-1 PRF, the PKCS#12 3DES PBE, a UTF-8 password.
	openssl pkcs8 -topk8 -in "$T/pw.key" -v2 aes-256-cbc -v2prf hmacWithSHA256 -passout pass:secret -out pw-pkcs8-aes256.key
	openssl pkcs8 -topk8 -in "$T/pw.key" -v2 des3 -v2prf hmacWithSHA1 -passout pass:secret -out pw-pkcs8-des3.key
	openssl pkcs8 -topk8 -in "$T/pw.key" -v1 PBE-SHA1-3DES -passout pass:secret -out pw-pkcs8-pbe3des.key
	# PKCS#5 v1.5 PBE with MD5 and DES (OpenSSL 1.0's -topk8 default).
	openssl pkcs8 -topk8 -provider legacy -provider default -in "$T/pw.key" -v1 PBE-MD5-DES -passout pass:secret -out pw-pkcs8-pbes1.key
	openssl pkcs8 -topk8 -in "$T/pw.key" -v2 aes-256-cbc -passout 'pass:pässwörd' -out pw-pkcs8-utf8.key
	# PKCS#12 with a UTF-8 password, OpenSSL 3 default and -legacy.
	p12 pw-utf8.p12 pw-client.pem "$T/pw.key" -passout 'pass:pässwörd'
	p12 pw-utf8-legacy.p12 pw-client.pem "$T/pw.key" -legacy -passout 'pass:pässwörd'
}

p12() { # out cert key [args...]
	local o=$1 c=$2 k=$3; shift 3
	openssl pkcs12 -export -in "$c" -inkey "$k" -out "$o" "$@"
}

if [ "${1:-}" = pw ]; then
	pw_fixtures
	exit 0
fi

ca() { # name subject [keyopts...]
	local n=$1 s=$2; shift 2
	openssl req -x509 -new -newkey "$@" -nodes -keyout "$n.key" -out "$n.pem" -days $D \
		-subj "$s" -sha1 -extensions x_ca -config "$T/ext.cnf" 2>/dev/null
}
sign() { # name subject issuer ext digest keyopts...
	local n=$1 s=$2 i=$3 e=$4 h=$5; shift 5
	openssl req -new -newkey "$@" -nodes -keyout "$n.key" -out "$T/$(basename "$n").csr" -subj "$s" -config "$T/ext.cnf" 2>/dev/null
	openssl x509 -req -in "$T/$(basename "$n").csr" -CA "$i.pem" -CAkey "$i.key" -set_serial "0x$(openssl rand -hex 8)" \
		-days $D "-$h" -extfile "$T/ext.cnf" -extensions "x_$e" -out "$n.pem" 2>/dev/null
}

ca sha1-root "/C=US/O=Test/CN=SHA1 Root" rsa:2048
sign sha1-int "/C=US/O=Test/CN=SHA1 Intermediate" sha1-root ca sha1 rsa:2048
sign sha1-server "/C=US/O=Test/CN=sha1-server" sha1-int server sha1 rsa:2048

ca sha1ec-root "/CN=SHA1 EC Root" ec -pkeyopt ec_paramgen_curve:P-256
sign sha1ec-server "/CN=sha1ec-server" sha1ec-root server sha1 ec -pkeyopt ec_paramgen_curve:P-256

# The PKCS#12 CA is an ordinary SHA-256 CA.
openssl req -x509 -new -newkey rsa:2048 -nodes -keyout p12-ca.key -out p12-ca.pem -days $D \
	-subj "/CN=P12 CA" -sha256 -extensions x_ca -config "$T/ext.cnf" 2>/dev/null
sign p12-int "/CN=P12 Intermediate" p12-ca ca sha256 rsa:2048
sign "$T/client-rsa" "/CN=p12-client-rsa" p12-ca client sha256 rsa:2048
sign "$T/client-ec" "/CN=p12-client-ec" p12-ca client sha256 ec -pkeyopt ec_paramgen_curve:P-256
sign "$T/client-int" "/CN=p12-client-int" p12-int client sha256 rsa:2048

# OpenSSL 1.x style: RC2-40 certs, 3DES key, SHA-1 MAC.
p12 client-legacy.p12 "$T/client-rsa.pem" "$T/client-rsa.key" -legacy -passout pass:
p12 client-legacy-chain.p12 "$T/client-int.pem" "$T/client-int.key" -legacy -certfile <(cat p12-int.pem p12-ca.pem) -passout pass:
# OpenSSL 3 default: PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC), SHA-256 MAC.
p12 client-modern.p12 "$T/client-rsa.pem" "$T/client-rsa.key" -passout pass:
p12 client-modern-chain.p12 "$T/client-int.pem" "$T/client-int.key" -certfile <(cat p12-int.pem p12-ca.pem) -passout pass:
p12 client-modern-ec.p12 "$T/client-ec.pem" "$T/client-ec.key" -passout pass:
# Unencrypted bags (keyBag, plain certBag), SHA-1 MAC.
p12 client-nopbe.p12 "$T/client-rsa.pem" "$T/client-rsa.key" -keypbe NONE -certpbe NONE -macalg sha1 -passout pass:
# 3DES key with a SHA-512 MAC and AES-128 certs: a mix x/crypto cannot read.
p12 client-mixed.p12 "$T/client-rsa.pem" "$T/client-rsa.key" -keypbe PBE-SHA1-3DES -certpbe AES-128-CBC -macalg sha512 -passout pass:
# No MAC at all.
p12 client-nomac.p12 "$T/client-rsa.pem" "$T/client-rsa.key" -nomac -passout pass:
# A password: unsupported, must be rejected.
p12 client-password.p12 "$T/client-rsa.pem" "$T/client-rsa.key" -passout pass:secret
p12 client-password-legacy.p12 "$T/client-rsa.pem" "$T/client-rsa.key" -legacy -passout pass:secret

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes-256-cbc -pass pass:secret -out enc-pkcs8.key 2>/dev/null
openssl genrsa -traditional -aes128 -passout pass:secret -out enc-pkcs1.key 2048 2>/dev/null
pw_fixtures

# CA keys are only needed while generating, except p12-ca.key: the tests
# issue a server certificate under it.
rm -f sha1-root.key sha1-int.key sha1ec-root.key p12-int.key
