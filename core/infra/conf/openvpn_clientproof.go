package conf

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/xtls/xray-core/proxy/openvpn"
	"github.com/xtls/xray-core/proxy/openvpn/ovpn/clientproof"
)

// OpenVPNClientProof enables optional TLS-session-bound client authentication.
// A keyFile is resolved only while loading configuration; rotate it by reloading.
type OpenVPNClientProof struct {
	KeyID   string `json:"keyId"`
	Key     string `json:"key"`
	KeyFile string `json:"keyFile"`
}

// UnmarshalJSON rejects null, unknown/duplicate fields, wrong types and empty
// optional fields rather than silently turning malformed proof settings off.
func (p *OpenVPNClientProof) UnmarshalJSON(data []byte) error {
	fields, err := openVPNProofFields(data, true)
	if err != nil {
		return errors.New("OpenVPN: clientProof must be a valid object")
	}
	var v OpenVPNClientProof
	for name, raw := range fields {
		var target *string
		switch name {
		case "keyId":
			target = &v.KeyID
		case "key":
			target = &v.Key
		case "keyFile":
			target = &v.KeyFile
		default:
			return errors.New("OpenVPN: unknown clientProof field")
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, target) != nil || *target == "" {
			return errors.New("OpenVPN: clientProof fields must be nonempty strings")
		}
	}
	if err := v.validate(); err != nil {
		return err
	}
	*p = v
	return nil
}

func (p *OpenVPNClientProof) validate() error {
	if p == nil {
		return errors.New("OpenVPN: clientProof must not be null")
	}
	if err := clientproof.ValidateKeyID(p.KeyID); err != nil {
		return err
	}
	if (p.Key == "") == (p.KeyFile == "") {
		return errors.New("OpenVPN: clientProof needs exactly one of key and keyFile")
	}
	if p.Key != "" {
		if len(p.Key) != 64 {
			return errors.New("OpenVPN: clientProof key must be 64 hexadecimal characters")
		}
		raw, err := hex.DecodeString(p.Key)
		clear(raw)
		if err != nil {
			return errors.New("OpenVPN: clientProof key must be hexadecimal")
		}
	}
	return nil
}

func (p *OpenVPNClientProof) build() (*openvpn.ClientProofConfig, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	text := p.Key
	if p.KeyFile != "" {
		st, err := os.Stat(p.KeyFile)
		if err != nil || !st.Mode().IsRegular() {
			return nil, errors.New("OpenVPN: clientProof keyFile must be a regular file")
		}
		before := st
		f, err := openOpenVPNProofFile(p.KeyFile)
		if err != nil {
			return nil, errors.New("OpenVPN: cannot open clientProof keyFile")
		}
		defer f.Close()
		st, err = f.Stat()
		if err != nil || !st.Mode().IsRegular() || !os.SameFile(before, st) {
			return nil, errors.New("OpenVPN: clientProof keyFile must be a stable regular file")
		}
		if runtime.GOOS != "windows" && st.Mode().Perm()&0077 != 0 {
			return nil, errors.New("OpenVPN: clientProof keyFile must not allow group or other access")
		}
		raw, err := io.ReadAll(io.LimitReader(f, 129))
		defer clear(raw)
		if err != nil || len(raw) > 128 {
			return nil, errors.New("OpenVPN: clientProof keyFile must contain at most 128 bytes")
		}
		text = strings.TrimSpace(string(raw))
	}
	if len(text) != 64 {
		return nil, errors.New("OpenVPN: clientProof key must be 64 hexadecimal characters")
	}
	raw, err := hex.DecodeString(text)
	if err != nil {
		clear(raw)
		return nil, errors.New("OpenVPN: clientProof key must be hexadecimal")
	}
	return &openvpn.ClientProofConfig{KeyId: p.KeyID, Key: raw}, nil
}

func (p OpenVPNClientProof) Format(f fmt.State, _ rune) {
	fmt.Fprintf(f, "OpenVPNClientProof{KeyId:%q, Key:<redacted>, KeyFile:<redacted>}", p.KeyID)
}
func (p OpenVPNClientProof) String() string   { return fmt.Sprintf("%v", p) }
func (p OpenVPNClientProof) GoString() string { return p.String() }

// OpenVPNConfig needs this wrapper because encoding/json treats null pointer
// values as absent without invoking the nested UnmarshalJSON method.
func (c *OpenVPNConfig) UnmarshalJSON(data []byte) error {
	// Decode ordinary settings with exactly encoding/json's prior semantics,
	// including repeated fields, case-insensitive names, null and partial updates.
	type plain OpenVPNConfig
	v := plain(*c)
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	var ordinaryFields map[string]json.RawMessage
	if err := json.Unmarshal(data, &ordinaryFields); err != nil {
		return err
	}
	hasProof := false
	for name := range ordinaryFields {
		if strings.EqualFold(name, "clientProof") {
			hasProof = true
		}
	}
	if hasProof {
		fields, err := openVPNProofFields(data, false)
		if err != nil {
			return errors.New("OpenVPN: invalid or duplicate clientProof field")
		}
		for name, raw := range fields {
			if strings.EqualFold(name, "clientProof") {
				if name != "clientProof" || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
					return errors.New("OpenVPN: clientProof must be a non-null object with exact field spelling")
				}
			}
		}
	}
	*c = OpenVPNConfig(v)
	return nil
}

// openVPNProofFields checks that the complete input is an object and rejects
// duplicate names. Values are kept raw so unrelated settings keep their
// existing decoding rules.
func openVPNProofFields(data []byte, rejectAllDuplicates bool) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return nil, errors.New("object required")
	}
	fields := make(map[string]json.RawMessage)
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		name, ok := tok.(string)
		if !ok {
			return nil, errors.New("invalid field")
		}
		if _, exists := fields[name]; exists && (rejectAllDuplicates || strings.EqualFold(name, "clientProof")) {
			return nil, errors.New("duplicate field")
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return nil, err
		}
		fields[name] = raw
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("trailing data")
	}
	return fields, nil
}
