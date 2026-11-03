// Package options reads an OpenVPN client configuration (.ovpn text) and the
// options a server pushes.
//
// Config syntax as OpenVPN reads it: one directive per line, arguments
// separated by whitespace, double or single quotes group an argument
// (backslash escapes inside double quotes), '#' or ';' at the start of a
// token starts a comment, a leading "--" on the directive is allowed.
// Inline blocks "<name>...</name>" hold file contents (ca, cert, key,
// extra-certs, tls-auth, tls-crypt, tls-crypt-v2, auth-user-pass,
// peer-fingerprint, pkcs12 as base64, crl-verify, verify-hash, connection).
// A directive that names a file instead ("ca ca.crt") is read from disk
// relative to Options.BaseDir when that is set, and is an error otherwise;
// "[inline]" as the file name refers to the block. The exceptions are the
// credentials files of auth-user-pass and askpass: without a BaseDir they
// are left to the caller (Options.AuthUserPassFile, Options.KeyPassword).
//
// Directives that change nothing for a userspace client (dev-node, nobind,
// persist-key, persist-tun, resolv-retry, mute-replay-warnings, verb, mute,
// script-security, up, down, route*, redirect-gateway, dhcp-option,
// block-outside-dns, register-dns, sndbuf, rcvbuf, float, setenv, pull,
// tls-client, client, auth-nocache, auth-retry, mssfix, ...) are accepted and
// ignored. "setenv opt X ..." is the directive X, applied when the parser
// knows it, as in OpenVPN. Unknown directives are recorded in
// Options.Ignored and accepted, as are ones listed by
// "ignore-unknown-option". Directives the client cannot honour are errors:
// dev tap / dev-type tap, fragment, secret (static key mode), http-proxy,
// socks-proxy, pkcs11-*, cryptoapicert, management-external-key, tls-verify
// (a script that checks the server) and crl-verify with "dir".
//
// Details of this implementation:
//
//   - As in OpenVPN, a quote groups only at the start of an argument (one
//     inside an unquoted argument is literal) and the closing quote ends the
//     argument, and a backslash outside single quotes also escapes a
//     backslash, a quote, a space or a tab. Any other backslash is kept
//     (OpenVPN rejects it), so Windows paths survive. Directive names are
//     matched case-insensitively.
//   - "remote [2001:db8::1]" loses its brackets; extra arguments after the
//     proto are ignored. peer-fingerprint also takes 64 hex digits without
//     colons.
//   - An inline block is the directive with the block as its content, so
//     "<tls-auth>...</tls-auth>" alone is enough (with "key-direction").
//     When there is no BaseDir, a file reference to something that also has
//     an inline block uses the block.
//   - Remotes outside <connection> blocks take the global proto and port
//     wherever those appear in the file. A <connection> block, as in
//     OpenVPN, starts from the global proto and port set before it, then its
//     own proto, port and remote directives overwrite them in order; it must
//     hold a remote and the last one wins. When there are <connection>
//     blocks, OpenVPN ignores the remotes outside them, and so does Parse.
//     Other directives inside a block apply globally.
//   - "config file" includes another file (BaseDir only).
//   - Also errors (wrapping ErrUnsupported): proto tcp-server, mode server,
//     server, server-bridge, tls-server, key-method 1, tls-remote (removed
//     in OpenVPN 2.4; use verify-x509-name), management-external-cert and
//     <secret> blocks.
//   - tls-auth, tls-crypt and tls-crypt-v2 are mutually exclusive.
//   - Ignored lists each directive name once, in first-seen order, and never
//     its arguments. A name that does not look like an OpenVPN directive
//     (lower-case words joined by '-', or a known plain word such as
//     "client") is listed as "(unrecognized)", so that a password or key
//     line outside its block never reaches a log.
//   - ping-exit sets PingRestart, like ping-restart (OpenVPN keeps one
//     receive timeout for both; the last one given wins): for a client
//     that is rebuilt from outside, exiting and restarting are the same.
//   - reneg-sec defaults to 3600 seconds, as for an OpenVPN client;
//     "reneg-sec 0" leaves renegotiation to the server.
//   - connect-timeout 0 and server-poll-timeout 0 mean the 30 s default;
//     hand-window 0 is an error (no handshake could ever complete).
//   - Server certificate checks are kept for tlsconf, never ignored:
//     crl-verify (PEM, file or block), remote-cert-eku, remote-cert-ku,
//     verify-hash (the line takes one SHA1 digest, or a SHA256 one with
//     "SHA256"; a <verify-hash> block takes SHA256 digests, one per line).
//   - static-challenge is recorded (Options.StaticChallenge) and listed in
//     Ignored, since this client cannot ask for the one-time code.
//
// A PUSH_REPLY is split at commas (quotes do not protect a comma, as in
// OpenVPN) and each option is read with the config syntax. Malformed values
// of options that only inform (route, route-gateway, dhcp-option, dns,
// auth-token-user) are skipped and recorded in Pushed.Ignored; malformed
// values of options that change the session (ifconfig, ifconfig-ipv6,
// peer-id, cipher, ping, tun-mtu, compression, key-derivation, topology) are
// errors. With "dns server" options, DNS lists their addresses by priority
// first, then the dhcp-option ones, without duplicates.
//
// What Pushed keeps is bounded however many PUSH_REPLY parts a server sends:
// at most 1024 routes, 32 DNS addresses from "dns server" options and 32
// from dhcp-option (repeats are not stored again), 256 names in Ignored and
// 32 protocol flags. What does not fit is dropped (route, dns and
// dhcp-option are then listed in Ignored); a dropped protocol flag still
// takes effect. Bounding the number and size of the parts is the caller's
// job.
package options

import (
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/compress"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/wire"
)

// ErrUnsupported is wrapped by the error for a directive the client cannot
// honour; the error text names the directive.
var ErrUnsupported = errors.New("options: unsupported directive")

// Remote is one server to try.
type Remote struct {
	Host string
	Port uint16
	// Network is "udp", "udp4", "udp6", "tcp", "tcp4" or "tcp6" (the
	// "-client" suffix of tcp-client is dropped).
	Network string
}

// IsTCP reports whether r is reached over TCP.
func (r Remote) IsTCP() bool { return strings.HasPrefix(r.Network, "tcp") }

// PullFilter is one --pull-filter rule.
type PullFilter struct {
	Action string // "accept", "ignore" or "reject"
	Prefix string
}

// Options is a parsed client configuration. Defaults are already applied.
type Options struct {
	// Remotes in config order (each <connection> block contributes its own
	// remote with its own proto/port). Port defaults to --port/--rport or
	// 1194, Network to --proto or "udp".
	Remotes      []Remote
	RemoteRandom bool

	// PEM blocks as given (ca, cert, key, extra-certs); PKCS12 is the decoded
	// DER of a <pkcs12> block or file.
	CA         []byte
	Cert       []byte
	Key        []byte
	ExtraCerts []byte
	PKCS12     []byte
	// PeerFingerprints are --peer-fingerprint SHA-256 digests of the server
	// certificate (accepted in place of a CA).
	PeerFingerprints [][32]byte

	// Control-channel protection: at most one of the three is set.
	// TLSAuth is the raw text of the key file/block; KeyDirection is -1 when
	// none was given (bidirectional), else 0 or 1 (from --key-direction or
	// the tls-auth direction argument).
	TLSAuth      []byte
	KeyDirection int
	TLSCrypt     []byte
	TLSCryptV2   []byte

	// Data channel. Cipher is --cipher (canonical upper case, "" if unset);
	// DataCiphers is --data-ciphers / --ncp-ciphers, default
	// AES-256-GCM, AES-128-GCM, CHACHA20-POLY1305; DataCiphersFallback is
	// --data-ciphers-fallback. Auth is --auth, default "SHA1".
	Cipher              string
	DataCiphers         []string
	DataCiphersFallback string
	Auth                string

	// Credentials. AuthUserPass is set by --auth-user-pass; Username and
	// Password come from its inline block or file (first and second line).
	AuthUserPass bool
	Username     string
	Password     string
	// AuthUserPassFile is the file --auth-user-pass names when there was no
	// BaseDir to read it from and no inline block: the credentials must
	// then come from the caller. "" otherwise.
	AuthUserPassFile string
	// StaticChallenge is the text of --static-challenge (the server wants a
	// one-time code with the password, which this client cannot ask for),
	// "" without one; StaticChallengeEcho is its echo flag.
	StaticChallenge     string
	StaticChallengeEcho bool
	// KeyPassword decrypts an encrypted --key or a password-protected
	// --pkcs12. Parse sets it only from an --askpass file read under
	// BaseDir; callers may set it. It is a secret.
	KeyPassword string

	// Server certificate checks.
	RemoteCertTLS  string // "server" or ""
	NsCertType     string // "server" or ""
	VerifyX509Name string
	VerifyX509Type string // "subject" (default), "name" or "name-prefix"
	TLSVersionMin  string // "1.0", "1.1", "1.2", "1.3" or ""
	TLSVersionMax  string
	// CRLVerify is the --crl-verify file or block as given: PEM "X509 CRL"
	// blocks.
	CRLVerify []byte
	// RemoteCertEKU is --remote-cert-eku: an extended key usage the server
	// certificate must list, as a dotted OID or by OpenSSL's long name
	// ("TLS Web Server Authentication"); "" for none.
	RemoteCertEKU string
	// RemoteCertKU is --remote-cert-ku. When RemoteCertKUSet, the server
	// certificate must have a key usage extension and, if the list is not
	// empty, every bit of one of its values, in OpenSSL's bit order (0x80
	// digitalSignature, 0x40 nonRepudiation, 0x20 keyEncipherment, 0x10
	// dataEncipherment, 0x08 keyAgreement, 0x04 keyCertSign, 0x02 cRLSign,
	// 0x01 encipherOnly). As in OpenVPN, the list ends before its first 0,
	// and a first value of 0 means no check.
	RemoteCertKU    []uint16
	RemoteCertKUSet bool
	// VerifyHash is --verify-hash: digests of the level-1 certificate (the
	// one that issued the server's), one of which must match. VerifyHashAlgo
	// is "SHA1" or "SHA256", "" without the directive.
	VerifyHash     [][]byte
	VerifyHashAlgo string

	// Compression framing from comp-lzo / compress; CompressionSet tells
	// whether either directive appeared.
	Compression    compress.Mode
	CompressionSet bool

	TunMTU             int           // --tun-mtu, default 1500
	Ping               time.Duration // --ping, or the first --keepalive argument
	PingRestart        time.Duration // --ping-restart or --ping-exit, or the second --keepalive argument
	RenegSec           time.Duration // --reneg-sec, default 3600s; 0: only the server renegotiates
	HandWindow         time.Duration // --hand-window, default 60s
	ConnectTimeout     time.Duration // --connect-timeout / --server-poll-timeout, default (and for 0) 30s
	ExplicitExitNotify int           // --explicit-exit-notify, default 0 (1 if given without argument)
	// PingRestartSet tells that the profile set PingRestart (ping-restart,
	// ping-exit or keepalive), even to 0: a client then does not apply
	// OpenVPN's 120 s client-mode default.
	PingRestartSet bool

	PullFilters []PullFilter

	// BaseDir is the directory file references were read from
	// (ParseWithBaseDir); "" when they are not allowed.
	BaseDir string
	// Ignored lists directives that were accepted without effect, for logs.
	Ignored []string
}

// Parse reads .ovpn text.
func Parse(text string) (*Options, error) { return parse(text, "") }

// ParseWithBaseDir reads .ovpn text and resolves file references against dir.
func ParseWithBaseDir(text, dir string) (*Options, error) { return parse(text, dir) }

// Pushed is what the server sent in its PUSH_REPLY messages.
type Pushed struct {
	// IPv4 is the address and prefix from "ifconfig local netmask" (subnet
	// topology) or "ifconfig local remote" (net30/p2p: prefix /32 and
	// PeerV4 = remote). IPv6 from "ifconfig-ipv6 addr/bits [gateway]".
	IPv4      netip.Prefix
	PeerV4    netip.Addr
	GatewayV4 netip.Addr // route-gateway
	IPv6      netip.Prefix
	GatewayV6 netip.Addr

	Routes   []netip.Prefix // route / route-ipv6, informational (the first 1024)
	DNS      []netip.Addr   // dhcp-option DNS/DNS6 and "dns server N address A..."
	Topology string

	Cipher        string // canonical, "" if not pushed
	Auth          string
	PeerID        uint32 // wire.NoPeerID (0xFFFFFF) when not pushed
	KeyDerivation string // "tls-ekm" when pushed (key-derivation or protocol-flags)
	ProtocolFlags []string

	Ping        time.Duration
	PingRestart time.Duration
	TunMTU      int

	Compression    compress.Mode
	CompressionSet bool

	AuthToken          string
	AuthTokenUser      string // base64-decoded
	ExplicitExitNotify int

	// Ignored lists pushed options without effect here (redirect-gateway,
	// block-ipv6, ...).
	Ignored []string

	// The last "ifconfig" pair, interpreted once the topology is known.
	ifconfig    [2]netip.Addr
	hasIfconfig bool
	// DNS servers by source, merged into DNS after every message.
	dnsServers []dnsServer
	dhcpDNS    []netip.Addr
	// Sets behind Ignored and ProtocolFlags.
	ignored map[string]bool
	flags   map[string]bool
}

// NewPushed returns an empty Pushed with PeerID set to "none".
func NewPushed() *Pushed { return &Pushed{PeerID: wire.NoPeerID} }

// ApplyPushReply adds one "PUSH_REPLY,opt,opt,..." control message to p,
// applying filters in order (first matching prefix wins; "reject" fails the
// reply). more reports "push-continuation 2" (another PUSH_REPLY follows).
func (p *Pushed) ApplyPushReply(msg string, filters []PullFilter) (more bool, err error) {
	return p.applyPushReply(msg, filters)
}
