package options

import (
	"errors"
	"strings"
)

var (
	errOpenDoubleQuote = errors.New("no closing double quote")
	errOpenSingleQuote = errors.New("no closing single quote")
)

// splitLines splits text into lines, dropping a UTF-8 byte order mark and
// the CR of CRLF line endings.
func splitLines(text string) []string {
	text = strings.TrimPrefix(text, "\uFEFF")
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSuffix(l, "\r")
	}
	return lines
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\v' || c == '\f' || c == '\r'
}

// isEscaped reports whether a backslash followed by c stands for c alone.
// Other backslashes are kept as they are, so that Windows paths written
// with single backslashes survive.
func isEscaped(c byte) bool {
	return c == '\\' || c == '"' || c == '\'' || c == ' ' || c == '\t'
}

// splitArgs splits one line into its arguments the way OpenVPN does:
// whitespace separates them; a double or single quote at the start of an
// argument groups everything up to the closing quote into one argument
// (which ends there, possibly empty); inside double quotes and outside
// quotes a backslash escapes a backslash, a quote, a space or a tab; a quote
// inside an unquoted argument is literal; a '#' or ';' at the start of an
// argument begins a comment that runs to the end of the line.
func splitArgs(s string) ([]string, error) {
	var (
		args []string
		cur  strings.Builder
		in   bool // inside an unquoted argument
	)
	for i := 0; i < len(s); {
		c := s[i]
		if !in {
			switch {
			case isSpace(c):
				i++
				continue
			case c == '#' || c == ';':
				return args, nil
			case c == '"':
				i++
				closed := false
				for i < len(s) {
					c = s[i]
					if c == '\\' && i+1 < len(s) && isEscaped(s[i+1]) {
						cur.WriteByte(s[i+1])
						i += 2
						continue
					}
					i++
					if c == '"' {
						closed = true
						break
					}
					cur.WriteByte(c)
				}
				if !closed {
					return nil, errOpenDoubleQuote
				}
				args = append(args, cur.String())
				cur.Reset()
				continue
			case c == '\'':
				i++
				end := strings.IndexByte(s[i:], '\'')
				if end < 0 {
					return nil, errOpenSingleQuote
				}
				args = append(args, s[i:i+end])
				i += end + 1
				continue
			}
			in = true
		}
		switch {
		case isSpace(c):
			args = append(args, cur.String())
			cur.Reset()
			in = false
			i++
		case c == '\\' && i+1 < len(s) && isEscaped(s[i+1]):
			cur.WriteByte(s[i+1])
			i += 2
		default:
			cur.WriteByte(c)
			i++
		}
	}
	if in {
		args = append(args, cur.String())
	}
	return args, nil
}

// directiveName normalises the first argument of a line: lower case, without
// a leading "--".
func directiveName(s string) string {
	return strings.ToLower(strings.TrimPrefix(s, "--"))
}

// openTag reports whether args is a lone inline-block opening tag "<name>"
// and returns the name.
func openTag(args []string) (string, bool) {
	if len(args) != 1 {
		return "", false
	}
	t := args[0]
	if len(t) < 3 || t[0] != '<' || t[len(t)-1] != '>' {
		return "", false
	}
	name := t[1 : len(t)-1]
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", false
		}
	}
	return strings.ToLower(name), true
}

// plainNames are OpenVPN directives without a '-' in their name.
var plainNames = map[string]bool{
	"auth": true, "ca": true, "cert": true, "cipher": true, "compress": true,
	"config": true, "connection": true, "fragment": true, "keepalive": true,
	"key": true, "ping": true, "pkcs12": true, "port": true, "proto": true,
	"remote": true, "rport": true, "secret": true, "server": true,
	"askpass": true, "bind": true, "capath": true, "cd": true, "chroot": true,
	"client": true, "daemon": true, "dev": true, "dh": true, "dns": true,
	"down": true, "echo": true, "engine": true, "float": true, "group": true,
	"ifconfig": true, "inactive": true, "inetd": true, "iproute": true,
	"ipchange": true, "keysize": true, "lladdr": true, "local": true,
	"log": true, "lport": true, "management": true, "mark": true,
	"mlock": true, "mode": true, "mssfix": true, "multihome": true,
	"mute": true, "nice": true, "nobind": true, "passtos": true,
	"plugin": true, "prng": true, "providers": true, "pull": true,
	"rcvbuf": true, "route": true, "service": true, "setenv": true,
	"shaper": true, "sndbuf": true, "status": true, "syslog": true,
	"topology": true, "txqueuelen": true, "up": true, "user": true,
	"verb": true, "writepid": true,
}

// unrecognized stands in Ignored for a line that does not look like a
// directive at all.
const unrecognized = "(unrecognized)"

// ignoredName is how a directive is listed in Ignored: its name when it is
// a known plain name or looks like a directive (lower-case words joined by
// '-'), else unrecognized, so that a stray secret (a password or a key line
// outside its block) or control characters never reach the logs.
func ignoredName(name string) string {
	if plainNames[name] {
		return name
	}
	if len(name) > 48 || len(name) == 0 || name[0] < 'a' || name[0] > 'z' {
		return unrecognized
	}
	hyphen := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		case c == '-' && name[i-1] != '-' && i+1 < len(name):
			hyphen = true
		default:
			return unrecognized
		}
	}
	if !hyphen {
		return unrecognized
	}
	return name
}
