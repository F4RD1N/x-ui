package options

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/xray-core/proxy/openvpn/ovpn/compress"
)

const (
	defaultPort = 1194
	// maxFileSize bounds a file read for a file reference.
	maxFileSize = 4 << 20
	// maxIncludeDepth bounds nested "config" includes.
	maxIncludeDepth = 8
	// maxSeconds bounds a duration argument, so that it cannot overflow.
	maxSeconds = 1<<31 - 1
	// defaultRenegSec is an OpenVPN client's --reneg-sec default.
	defaultRenegSec = 3600 * time.Second
	// defaultConnectTimeout is --connect-timeout's default, also used for 0.
	defaultConnectTimeout = 30 * time.Second
)

// unsupportedError is the error for a directive the client cannot honour.
type unsupportedError struct{ what string }

func (e *unsupportedError) Error() string { return "unsupported directive: " + e.what }
func (e *unsupportedError) Unwrap() error { return ErrUnsupported }

func unsupported(what string) error { return &unsupportedError{what} }

// lineError places an error in the config text.
type lineError struct {
	src  string // included file, "" for the text given to Parse
	line int
	err  error
}

func (e *lineError) Error() string {
	if e.src != "" {
		return fmt.Sprintf("options: %s line %d: %v", e.src, e.line, e.err)
	}
	return fmt.Sprintf("options: line %d: %v", e.line, e.err)
}

func (e *lineError) Unwrap() error { return e.err }

// entry is one directive line or one inline block.
type entry struct {
	src  string
	line int
	// args[0] is the directive name, normalised. A block has only the name.
	args    []string
	block   bool
	content []byte
	conn    int // index of the enclosing <connection> block, -1 outside
	// connOpen marks the start of <connection> block conn.
	connOpen bool
}

func (e *entry) name() string { return e.args[0] }

// connBlock is one <connection> block. Like OpenVPN, it starts from the
// global proto and port seen so far, and its directives (remote with a port
// or proto included) then overwrite them in order; the last remote wins.
type connBlock struct {
	line    int
	src     string
	host    string
	network string
	port    uint16
}

// remoteSpec is a global remote before defaults are applied (zero = unset).
type remoteSpec struct {
	host    string
	port    uint16
	network string
}

type parser struct {
	o       *Options
	entries []entry
	blocks  map[string][]byte
	conns   []connBlock
	remotes []remoteSpec
	network string // global --proto
	port    uint16 // global --port / --rport
	devName string
	devType string
	ignored map[string]bool
}

func parse(text, dir string) (*Options, error) {
	p := &parser{
		o: &Options{
			KeyDirection:   -1,
			DataCiphers:    []string{"AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"},
			Auth:           "SHA1",
			TunMTU:         1500,
			RenegSec:       defaultRenegSec,
			HandWindow:     60 * time.Second,
			ConnectTimeout: defaultConnectTimeout,
			BaseDir:        dir,
		},
		blocks:  map[string][]byte{},
		ignored: map[string]bool{},
	}
	if err := p.collect(splitLines(text), 0, "", 0, -1); err != nil {
		return nil, err
	}
	for i := range p.entries {
		e := &p.entries[i]
		if err := p.apply(e); err != nil {
			return nil, &lineError{e.src, e.line, err}
		}
	}
	if err := p.finish(); err != nil {
		return nil, err
	}
	return p.o, nil
}

// collect turns lines into entries; line numbers are base+index+1.
func (p *parser) collect(lines []string, base int, src string, depth, conn int) error {
	for i := 0; i < len(lines); i++ {
		num := base + i + 1
		args, err := splitArgs(lines[i])
		if err != nil {
			return &lineError{src, num, err}
		}
		if len(args) == 0 {
			continue
		}
		if name, ok := openTag(args); ok {
			end, content, err := blockEnd(lines, i+1, name)
			if err != nil {
				return &lineError{src, num, err}
			}
			if name == "connection" {
				if conn >= 0 {
					return &lineError{src, num, errors.New("<connection> inside <connection>")}
				}
				idx := len(p.conns)
				p.conns = append(p.conns, connBlock{line: num, src: src})
				p.entries = append(p.entries, entry{src: src, line: num, args: []string{name}, conn: idx, connOpen: true})
				if err := p.collect(lines[i+1:end], base+i+1, src, depth, idx); err != nil {
					return err
				}
			} else {
				p.entries = append(p.entries, entry{src: src, line: num, args: []string{name}, block: true, content: content, conn: conn})
				p.blocks[name] = content
			}
			i = end
			continue
		}
		args[0] = directiveName(args[0])
		if args[0] == "setenv" && len(args) > 2 && args[1] == "opt" {
			// "setenv opt X ...": the directive X, to be applied when it is
			// known (an unknown X is ignored under its own name). OpenVPN
			// matches "opt" case-sensitively.
			args = args[2:]
			args[0] = directiveName(args[0])
		}
		if args[0] == "config" {
			if err := p.include(args, src, num, depth, conn); err != nil {
				return err
			}
			continue
		}
		p.entries = append(p.entries, entry{src: src, line: num, args: args, conn: conn})
	}
	return nil
}

// blockEnd finds the line closing the block <name> opened just before
// lines[start] and returns its index and the block's content.
func blockEnd(lines []string, start int, name string) (int, []byte, error) {
	closeTag := "</" + name + ">"
	var content []byte
	for j := start; j < len(lines); j++ {
		t := strings.TrimSpace(lines[j])
		if name == "connection" && strings.EqualFold(t, "<connection>") {
			return 0, nil, errors.New("<connection> inside <connection>")
		}
		if len(t) >= len(closeTag) && strings.EqualFold(t[len(t)-len(closeTag):], closeTag) {
			// Tolerate the closing tag at the end of the last content line.
			if rest := strings.TrimRight(t[:len(t)-len(closeTag)], " \t"); rest != "" {
				content = append(content, rest...)
				content = append(content, '\n')
			}
			return j, content, nil
		}
		content = append(content, lines[j]...)
		content = append(content, '\n')
	}
	return 0, nil, fmt.Errorf("<%s> block without %s", name, closeTag)
}

// include reads "config file" in place.
func (p *parser) include(args []string, src string, num, depth, conn int) error {
	if len(args) < 2 {
		return &lineError{src, num, errors.New("config: missing file name")}
	}
	if p.o.BaseDir == "" {
		return &lineError{src, num, fmt.Errorf("config %s: file references need a base directory", args[1])}
	}
	if depth >= maxIncludeDepth {
		return &lineError{src, num, errors.New("config: includes nested too deeply")}
	}
	data, err := readFile(p.o.BaseDir, args[1])
	if err != nil {
		return &lineError{src, num, fmt.Errorf("config: %w", err)}
	}
	return p.collect(splitLines(string(data)), 0, args[1], depth+1, conn)
}

// readFile reads name (relative to dir unless absolute), at most
// maxFileSize bytes.
func readFile(dir, name string) ([]byte, error) {
	path := name
	if !filepath.IsAbs(path) {
		path = filepath.Join(dir, path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(data) > maxFileSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, maxFileSize)
	}
	return data, nil
}

func isInline(file string) bool {
	f := strings.ToLower(file)
	return f == "[inline]" || f == "[[inline]]"
}

// content returns what a file-taking directive refers to: its own block,
// the block named by "[inline]", or the file under BaseDir. fromBlock
// reports an inline block.
func (p *parser) content(e *entry) (data []byte, fromBlock bool, err error) {
	name := e.name()
	if e.block {
		return e.content, true, nil
	}
	if len(e.args) < 2 || e.args[1] == "" {
		return nil, false, fmt.Errorf("%s: missing file name", name)
	}
	file := e.args[1]
	b, hasBlock := p.blocks[name]
	if isInline(file) {
		if !hasBlock {
			return nil, false, fmt.Errorf("%s %s: no <%s> block", name, file, name)
		}
		return b, true, nil
	}
	if p.o.BaseDir == "" {
		if hasBlock {
			return b, true, nil
		}
		return nil, false, fmt.Errorf("%s %s: file references need a base directory (use an inline <%s> block)", name, file, name)
	}
	data, err = readFile(p.o.BaseDir, file)
	if err != nil {
		return nil, false, fmt.Errorf("%s: %w", name, err)
	}
	return data, false, nil
}

func (p *parser) ignore(name string) {
	name = ignoredName(name)
	if !p.ignored[name] {
		p.ignored[name] = true
		p.o.Ignored = append(p.o.Ignored, name)
	}
}

// arg returns args[i] or an error naming the directive.
func arg(e *entry, i int) (string, error) {
	if i >= len(e.args) {
		return "", fmt.Errorf("%s: missing argument", e.name())
	}
	return e.args[i], nil
}

func (p *parser) apply(e *entry) error {
	name := e.name()
	if e.block {
		return p.applyBlock(e)
	}
	if e.connOpen {
		p.conns[e.conn].network, p.conns[e.conn].port = p.network, p.port
		return nil
	}
	o := p.o
	switch name {
	case "remote":
		return p.remote(e)
	case "proto":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		network, err := parseProto(a)
		if err != nil {
			return err
		}
		if e.conn >= 0 {
			p.conns[e.conn].network = network
		} else {
			p.network = network
		}
	case "port", "rport":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		port, err := parsePort(a)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if e.conn >= 0 {
			p.conns[e.conn].port = port
		} else {
			p.port = port
		}
	case "remote-random":
		o.RemoteRandom = true

	case "ca", "cert", "key", "extra-certs", "pkcs12", "tls-auth", "tls-crypt", "tls-crypt-v2", "auth-user-pass", "peer-fingerprint":
		return p.applyBlock(e)
	case "crl-verify":
		if len(e.args) > 2 && strings.ToLower(e.args[2]) == "dir" {
			return unsupported("crl-verify dir")
		}
		return p.applyBlock(e)
	case "askpass":
		return p.askpass(e)
	case "static-challenge":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		o.StaticChallenge = a
		o.StaticChallengeEcho = len(e.args) > 2 && e.args[2] == "1"
		p.ignore(name) // nothing here sends the code
	case "remote-cert-eku":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		if a == "" {
			return errors.New("remote-cert-eku: empty extended key usage")
		}
		o.RemoteCertEKU = a
	case "remote-cert-ku":
		return p.remoteCertKU(e)
	case "verify-hash":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		algo := "SHA1"
		if len(e.args) > 2 {
			algo = strings.ToUpper(e.args[2])
		}
		h, err := parseHash(a, algo)
		if err != nil {
			return fmt.Errorf("verify-hash: %w", err)
		}
		o.VerifyHash, o.VerifyHashAlgo = [][]byte{h}, algo
	case "key-direction":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		d, err := parseDirection(a)
		if err != nil {
			return fmt.Errorf("key-direction: %w", err)
		}
		o.KeyDirection = d

	case "cipher":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		o.Cipher = strings.ToUpper(a)
	case "data-ciphers", "ncp-ciphers":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		var list []string
		for _, c := range strings.Split(a, ":") {
			c = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(c), "?"))
			if c != "" {
				list = append(list, strings.ToUpper(c))
			}
		}
		if len(list) == 0 {
			return fmt.Errorf("%s: empty cipher list", name)
		}
		o.DataCiphers = list
	case "data-ciphers-fallback":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		o.DataCiphersFallback = strings.ToUpper(a)
	case "auth":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		o.Auth = strings.ToUpper(a)

	case "remote-cert-tls", "ns-cert-type":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		if strings.ToLower(a) != "server" {
			return fmt.Errorf("%s %s: only \"server\" makes sense for a client", name, a)
		}
		if name == "remote-cert-tls" {
			o.RemoteCertTLS = "server"
		} else {
			o.NsCertType = "server"
		}
	case "verify-x509-name":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		typ := "subject"
		if len(e.args) > 2 {
			typ = strings.ToLower(e.args[2])
			if typ != "subject" && typ != "name" && typ != "name-prefix" {
				return fmt.Errorf("verify-x509-name: unknown type %q", e.args[2])
			}
		}
		o.VerifyX509Name, o.VerifyX509Type = a, typ
	case "tls-version-min":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		v, ok := tlsVersion(a)
		if !ok {
			if len(e.args) > 2 && strings.ToLower(e.args[2]) == "or-highest" {
				v = "1.3"
			} else {
				return fmt.Errorf("tls-version-min: unknown version %q", a)
			}
		}
		o.TLSVersionMin = v
	case "tls-version-max":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		v, ok := tlsVersion(a)
		if !ok {
			return fmt.Errorf("tls-version-max: unknown version %q", a)
		}
		o.TLSVersionMax = v

	case "comp-lzo", "compress":
		a := ""
		if len(e.args) > 1 {
			a = e.args[1]
		}
		m, err := parseCompression(name, a)
		if err != nil {
			return err
		}
		o.Compression, o.CompressionSet = m, true

	case "tun-mtu":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		mtu, err := parseMTU(a)
		if err != nil {
			return fmt.Errorf("tun-mtu: %w", err)
		}
		o.TunMTU = mtu
	case "ping", "ping-restart", "ping-exit", "reneg-sec", "hand-window", "connect-timeout", "server-poll-timeout":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		d, err := parseSeconds(a)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		switch name {
		case "ping":
			o.Ping = d
		case "ping-restart", "ping-exit":
			// One receive timeout in OpenVPN; the last one given wins.
			o.PingRestart, o.PingRestartSet = d, true
		case "reneg-sec":
			o.RenegSec = d
		case "hand-window":
			if d == 0 {
				return errors.New("hand-window: must be positive (no handshake can complete in 0 seconds)")
			}
			o.HandWindow = d
		default:
			if d == 0 {
				d = defaultConnectTimeout
			}
			o.ConnectTimeout = d
		}
	case "keepalive":
		if len(e.args) < 3 {
			return errors.New("keepalive: needs two arguments")
		}
		ping, err := parseSeconds(e.args[1])
		if err != nil {
			return fmt.Errorf("keepalive: %w", err)
		}
		restart, err := parseSeconds(e.args[2])
		if err != nil {
			return fmt.Errorf("keepalive: %w", err)
		}
		o.Ping, o.PingRestart, o.PingRestartSet = ping, restart, true
	case "explicit-exit-notify":
		n := 1
		if len(e.args) > 1 {
			v, err := strconv.Atoi(e.args[1])
			if err != nil || v < 0 || v > 1000 {
				return fmt.Errorf("explicit-exit-notify: bad count %q", e.args[1])
			}
			n = v
		}
		o.ExplicitExitNotify = n

	case "pull-filter":
		if len(e.args) < 3 {
			return errors.New("pull-filter: needs an action and a text")
		}
		action := strings.ToLower(e.args[1])
		if action != "accept" && action != "ignore" && action != "reject" {
			return fmt.Errorf("pull-filter: unknown action %q", e.args[1])
		}
		o.PullFilters = append(o.PullFilters, PullFilter{Action: action, Prefix: e.args[2]})

	case "dev":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		p.devName = strings.ToLower(a)
		p.ignore(name)
	case "dev-type":
		a, err := arg(e, 1)
		if err != nil {
			return err
		}
		p.devType = strings.ToLower(a)
		p.ignore(name)
	case "mode":
		if len(e.args) > 1 && strings.ToLower(e.args[1]) == "server" {
			return unsupported("mode server")
		}
		p.ignore(name)
	case "key-method":
		if len(e.args) > 1 && e.args[1] != "2" {
			return unsupported("key-method " + e.args[1])
		}
		p.ignore(name)
	case "fragment", "secret", "http-proxy", "socks-proxy", "cryptoapicert",
		"management-external-key", "management-external-cert",
		"server", "server-bridge", "tls-server", "tls-remote", "tls-verify":
		return unsupported(name)

	default:
		if strings.HasPrefix(name, "pkcs11-") {
			return unsupported(name)
		}
		p.ignore(name)
	}
	return nil
}

// applyBlock handles the directives whose argument is file content, given
// as a file or as an inline block.
func (p *parser) applyBlock(e *entry) error {
	o := p.o
	name := e.name()
	switch name {
	case "ca", "cert", "key", "extra-certs", "tls-auth", "tls-crypt", "tls-crypt-v2":
		data, _, err := p.content(e)
		if err != nil {
			return err
		}
		switch name {
		case "ca":
			o.CA = data
		case "cert":
			o.Cert = data
		case "key":
			o.Key = data
		case "extra-certs":
			o.ExtraCerts = data
		case "tls-auth":
			o.TLSAuth = data
			if !e.block && len(e.args) > 2 {
				d, err := parseDirection(e.args[2])
				if err != nil {
					return fmt.Errorf("tls-auth: %w", err)
				}
				o.KeyDirection = d
			}
		case "tls-crypt":
			o.TLSCrypt = data
		case "tls-crypt-v2":
			o.TLSCryptV2 = data
		}
	case "pkcs12":
		data, fromBlock, err := p.content(e)
		if err != nil {
			return err
		}
		if fromBlock {
			if data, err = decodeBase64(string(data)); err != nil {
				return fmt.Errorf("pkcs12: inline block is not base64: %w", err)
			}
		}
		o.PKCS12 = data
	case "crl-verify":
		data, _, err := p.content(e)
		if err != nil {
			return err
		}
		if len(strings.TrimSpace(string(data))) == 0 {
			return errors.New("crl-verify: no CRL")
		}
		o.CRLVerify = data
	case "verify-hash":
		// Only the block comes here; it holds SHA256 digests, one per line.
		var hashes [][]byte
		for _, l := range strings.Split(string(e.content), "\n") {
			l = strings.TrimSpace(l)
			if l == "" || l[0] == '#' || l[0] == ';' {
				continue
			}
			h, err := parseHash(l, "SHA256")
			if err != nil {
				return fmt.Errorf("verify-hash: %w", err)
			}
			hashes = append(hashes, h)
		}
		if len(hashes) == 0 {
			return errors.New("verify-hash: no digest in the block")
		}
		o.VerifyHash, o.VerifyHashAlgo = hashes, "SHA256"
	case "auth-user-pass":
		o.AuthUserPass = true
		o.AuthUserPassFile = ""
		if !e.block && len(e.args) < 2 {
			return nil // credentials come from the caller or a block
		}
		if _, hasBlock := p.blocks[name]; !e.block && p.o.BaseDir == "" && !hasBlock && e.args[1] != "" && !isInline(e.args[1]) {
			// The credentials file cannot be read here; the caller has
			// to give the credentials.
			o.AuthUserPassFile = e.args[1]
			p.ignore(name)
			return nil
		}
		data, _, err := p.content(e)
		if err != nil {
			return err
		}
		o.Username, o.Password = credentials(data)
	case "peer-fingerprint":
		var text string
		if !e.block && len(e.args) > 1 && !isInline(e.args[1]) {
			text = e.args[1] // the fingerprint itself
		} else {
			data, _, err := p.content(e)
			if err != nil {
				return err
			}
			text = string(data)
		}
		n := 0
		for _, l := range strings.Split(text, "\n") {
			l = strings.TrimSpace(l)
			if l == "" || l[0] == '#' || l[0] == ';' {
				continue
			}
			fp, err := parseFingerprint(l)
			if err != nil {
				return fmt.Errorf("peer-fingerprint: %w", err)
			}
			o.PeerFingerprints = append(o.PeerFingerprints, fp)
			n++
		}
		if n == 0 {
			return errors.New("peer-fingerprint: no fingerprint")
		}
	case "secret":
		return unsupported("secret")
	default:
		p.ignore(name)
	}
	return nil
}

// askpass reads "askpass file" into KeyPassword (the file's first line)
// when there is a BaseDir; otherwise the password is the caller's to give,
// as it is for a bare "askpass" (OpenVPN would ask on the console).
func (p *parser) askpass(e *entry) error {
	if len(e.args) < 2 || e.args[1] == "" || isInline(e.args[1]) || p.o.BaseDir == "" {
		p.ignore(e.name())
		return nil
	}
	data, err := readFile(p.o.BaseDir, e.args[1])
	if err != nil {
		return fmt.Errorf("askpass: %w", err)
	}
	line, _, _ := strings.Cut(string(data), "\n")
	p.o.KeyPassword = strings.TrimRight(line, "\r")
	return nil
}

// remoteCertKU reads "remote-cert-ku [hex...]". As OpenVPN does, the list
// ends before its first 0, and a first value of 0 turns the check off.
func (p *parser) remoteCertKU(e *entry) error {
	var list []uint16
	for _, a := range e.args[1:] {
		h := strings.TrimPrefix(strings.TrimPrefix(a, "0x"), "0X")
		v, err := strconv.ParseUint(h, 16, 16)
		if err != nil {
			return fmt.Errorf("remote-cert-ku: %q is not a key usage value in hex (at most ffff)", a)
		}
		list = append(list, uint16(v))
	}
	if i := slices.Index(list, 0); i >= 0 {
		list = list[:i]
	}
	if len(e.args) > 1 && len(list) == 0 {
		p.o.RemoteCertKU, p.o.RemoteCertKUSet = nil, false
		return nil
	}
	p.o.RemoteCertKU, p.o.RemoteCertKUSet = list, true
	return nil
}

// parseHash reads a digest written as colon-separated hex pairs, as
// --verify-hash takes it, and checks its length against algo ("SHA1" or
// "SHA256").
func parseHash(s, algo string) ([]byte, error) {
	var size int
	switch algo {
	case "SHA1":
		size = 20
	case "SHA256":
		size = 32
	default:
		return nil, fmt.Errorf("unknown digest %q (SHA1 or SHA256)", algo)
	}
	parts := strings.Split(s, ":")
	if len(parts) != size {
		return nil, fmt.Errorf("%q is not a %s digest written as %d colon-separated hex pairs", s, algo, size)
	}
	h := make([]byte, size)
	for i, part := range parts {
		if len(part) != 2 {
			return nil, fmt.Errorf("%q is not a %s digest written as colon-separated hex pairs", s, algo)
		}
		if _, err := hex.Decode(h[i:i+1], []byte(part)); err != nil {
			return nil, fmt.Errorf("%q is not a %s digest written as colon-separated hex pairs", s, algo)
		}
	}
	return h, nil
}

func (p *parser) remote(e *entry) error {
	host, err := arg(e, 1)
	if err != nil {
		return err
	}
	if len(host) > 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if host == "" {
		return errors.New("remote: empty host")
	}
	r := remoteSpec{host: host}
	rest := e.args[2:]
	if len(rest) > 0 {
		port, perr := parsePort(rest[0])
		switch {
		case perr == nil:
			r.port = port
			rest = rest[1:]
		case len(rest) == 1 && isProto(rest[0]):
			// "remote host proto": tolerate the missing port.
		default:
			return fmt.Errorf("remote: %w", perr)
		}
	}
	if len(rest) > 0 {
		network, err := parseProto(rest[0])
		if err != nil {
			return fmt.Errorf("remote: %w", err)
		}
		r.network = network
	}
	if e.conn >= 0 {
		c := &p.conns[e.conn]
		c.host = r.host
		if r.port != 0 {
			c.port = r.port
		}
		if r.network != "" {
			c.network = r.network
		}
		return nil
	}
	p.remotes = append(p.remotes, r)
	return nil
}

func (p *parser) finish() error {
	o := p.o
	for _, c := range p.conns {
		if c.host == "" {
			return &lineError{c.src, c.line, errors.New("<connection> block without remote")}
		}
		o.Remotes = append(o.Remotes, makeRemote(c.host, c.port, c.network))
	}
	if len(p.conns) > 0 && len(p.remotes) > 0 {
		// OpenVPN uses only the <connection> blocks then.
		p.ignore("remote")
	} else {
		for _, r := range p.remotes {
			port, network := r.port, r.network
			if port == 0 {
				port = p.port
			}
			if network == "" {
				network = p.network
			}
			o.Remotes = append(o.Remotes, makeRemote(r.host, port, network))
		}
	}
	dev := p.devType
	if dev == "" {
		dev = p.devName
	}
	if strings.HasPrefix(dev, "tap") {
		if p.devType != "" {
			return fmt.Errorf("options: %w", unsupported("dev-type tap"))
		}
		return fmt.Errorf("options: %w", unsupported("dev tap"))
	}
	n := 0
	for _, k := range [][]byte{o.TLSAuth, o.TLSCrypt, o.TLSCryptV2} {
		if k != nil {
			n++
		}
	}
	if n > 1 {
		return errors.New("options: tls-auth, tls-crypt and tls-crypt-v2 are mutually exclusive")
	}
	return nil
}

// makeRemote applies the default port and network.
func makeRemote(host string, port uint16, network string) Remote {
	if port == 0 {
		port = defaultPort
	}
	if network == "" {
		network = "udp"
	}
	return Remote{Host: host, Port: port, Network: network}
}

// parseProto maps a --proto value to a Remote.Network.
func parseProto(s string) (string, error) {
	switch v := strings.ToLower(s); v {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
		return v, nil
	case "tcp-client", "tcp4-client", "tcp6-client":
		return strings.TrimSuffix(v, "-client"), nil
	case "tcp-server", "tcp4-server", "tcp6-server":
		return "", unsupported("proto " + v)
	}
	return "", fmt.Errorf("unknown protocol %q", s)
}

func isProto(s string) bool {
	_, err := parseProto(s)
	return err == nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return uint16(n), nil
}

func parseDirection(s string) (int, error) {
	switch s {
	case "0":
		return 0, nil
	case "1":
		return 1, nil
	}
	return 0, fmt.Errorf("key direction must be 0 or 1, not %q", s)
}

func parseSeconds(s string) (time.Duration, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n > maxSeconds {
		return 0, fmt.Errorf("bad number of seconds %q", s)
	}
	return time.Duration(n) * time.Second, nil
}

func parseMTU(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 68 || n > 65535 {
		return 0, fmt.Errorf("bad MTU %q", s)
	}
	return n, nil
}

func tlsVersion(s string) (string, bool) {
	switch s {
	case "1.0", "1.1", "1.2", "1.3":
		return s, true
	}
	return "", false
}

// parseCompression maps comp-lzo / compress and its argument to a Mode.
func parseCompression(name, a string) (compress.Mode, error) {
	var (
		m   compress.Mode
		err error
	)
	if name == "comp-lzo" {
		m, err = compress.ParseCompLZO(a)
	} else {
		m, err = compress.ParseCompress(a)
	}
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", name, a, err)
	}
	return m, nil
}

// credentials splits an auth-user-pass file into its first two lines.
func credentials(data []byte) (user, pass string) {
	lines := strings.SplitN(string(data), "\n", 3)
	user = strings.TrimRight(lines[0], "\r")
	if len(lines) > 1 {
		pass = strings.TrimRight(lines[1], "\r")
	}
	return user, pass
}

// parseFingerprint reads a SHA-256 digest written as colon-separated hex
// ("AB:CD:...") or as 64 hex digits.
func parseFingerprint(s string) ([32]byte, error) {
	var fp [32]byte
	h := strings.ReplaceAll(s, ":", "")
	if len(h) != 64 {
		return fp, fmt.Errorf("%q is not a SHA-256 fingerprint", s)
	}
	if _, err := hex.Decode(fp[:], []byte(h)); err != nil {
		return fp, fmt.Errorf("%q is not a SHA-256 fingerprint", s)
	}
	return fp, nil
}

// decodeBase64 decodes base64 text that may be wrapped or padded or not.
func decodeBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n', '\v', '\f':
			return -1
		}
		return r
	}, s)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}
