package encoding_test

import (
	"bytes"
	"testing"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	. "github.com/xtls/xray-core/proxy/vless/encoding"
)

func clientVerUser(t *testing.T) (*protocol.MemoryUser, *vless.MemoryValidator) {
	id := uuid.New()
	user := &protocol.MemoryUser{Email: "u@x"}
	user.Account = toAccount(&vless.Account{Id: id.String()})
	v := new(vless.MemoryValidator)
	common.Must(v.Add(user))
	return user, v
}

// header returns a request header for user, with the given addons, followed by
// a payload.
func header(t *testing.T, user *protocol.MemoryUser, addons *Addons) []byte {
	b := buf.New()
	defer b.Release()
	common.Must(EncodeRequestHeader(b, &protocol.RequestHeader{
		Version: Version,
		User:    user,
		Command: protocol.RequestCommandTCP,
		Address: net.DomainAddress("example.com"),
		Port:    443,
	}, addons))
	return append(append([]byte(nil), b.Bytes()...), "payload"...)
}

func checkFor(min, max []byte) ClientVerCheck {
	return func(u *protocol.MemoryUser, a *Addons) bool {
		ok, _ := ClientVerAllowed(u.Account.(*vless.MemoryAccount).ID.Bytes(), a.ClientVer, min, max)
		return ok
	}
}

func decode(t *testing.T, isfb bool, wire []byte, v vless.Validator, check ClientVerCheck) (*buf.Buffer, *Addons, bool, error) {
	first := buf.New()
	first.Write(wire)
	reader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(nil)), Buffer: buf.MultiBuffer{first}}
	var addons *Addons
	var err error
	if isfb {
		_, _, addons, isfb, err = DecodeRequestHeaderChecked(true, first, reader, v, check)
	} else {
		_, _, addons, isfb, err = DecodeRequestHeaderChecked(false, nil, reader, v, check)
	}
	return first, addons, isfb, err
}

func TestDecodeRequestHeaderClientVer(t *testing.T) {
	user, v := clientVerUser(t)
	id := user.Account.(*vless.MemoryAccount).ID.Bytes()
	ours := header(t, user, &Addons{ClientVer: SealClientVer(id, [3]byte{25, 3, 6})})
	vision := header(t, user, &Addons{Flow: vless.XRV, ClientVer: SealClientVer(id, [3]byte{25, 3, 6})})
	stock := header(t, user, &Addons{})
	other, _ := clientVerUser(t)
	foreign := header(t, user, &Addons{ClientVer: SealClientVer(other.Account.(*vless.MemoryAccount).ID.Bytes(), [3]byte{25, 3, 6})})

	cases := []struct {
		name  string
		wire  []byte
		check ClientVerCheck
		ok    bool
	}{
		{"nil check, ours", ours, nil, true},
		{"nil check, stock", stock, nil, true},
		{"no limits, stock", stock, checkFor(nil, nil), true},
		{"min ok", ours, checkFor([]byte{25, 3, 6}, nil), true},
		{"min ok, vision", vision, checkFor([]byte{25, 0, 0}, nil), true},
		{"min too high", ours, checkFor([]byte{25, 3, 7}, nil), false},
		{"min too high, vision", vision, checkFor([]byte{26, 0, 0}, nil), false},
		{"max too low", ours, checkFor(nil, []byte{25, 3, 5}), false},
		{"max ok", ours, checkFor(nil, []byte{26, 3, 27}), true},
		{"min, stock client", stock, checkFor([]byte{1, 0, 0}, nil), false},
		{"min, sealed under another id", foreign, checkFor([]byte{1, 0, 0}, nil), false},
	}
	for _, c := range cases {
		for _, isfb := range []bool{false, true} {
			first, addons, gotfb, err := decode(t, isfb, c.wire, v, c.check)
			if c.ok {
				if err != nil {
					t.Errorf("%s (fb %v): %v", c.name, isfb, err)
				} else if (addons.Flow == vless.XRV) != bytes.Equal(c.wire, vision) {
					t.Errorf("%s: flow %q", c.name, addons.Flow)
				}
				continue
			}
			if err == nil {
				t.Errorf("%s (fb %v): accepted", c.name, isfb)
				continue
			}
			// Refused like an unknown id: a fallback inbound gets isfb back
			// and the first read untouched, to send on to the fallback.
			if gotfb != isfb {
				t.Errorf("%s (fb %v): isfb = %v", c.name, isfb, gotfb)
			}
			if isfb && !bytes.Equal(first.Bytes(), c.wire) {
				t.Errorf("%s: first read consumed (%d of %d left)", c.name, first.Len(), len(c.wire))
			}
		}
	}

	// A stock header with an unknown id is still refused the same way.
	stranger, _ := clientVerUser(t)
	if _, _, fb, err := decode(t, true, header(t, stranger, &Addons{}), v, checkFor([]byte{1, 0, 0}, nil)); err == nil || !fb {
		t.Errorf("unknown id: err %v fb %v", err, fb)
	}
}

// A header whose addons do not all arrive in the first read is checked once
// they are read; a refusal then closes (no fallback is possible).
func TestDecodeRequestHeaderClientVerSplit(t *testing.T) {
	user, v := clientVerUser(t)
	id := user.Account.(*vless.MemoryAccount).ID.Bytes()
	wire := header(t, user, &Addons{ClientVer: SealClientVer(id, [3]byte{25, 3, 6})})
	for _, tc := range []struct {
		min []byte
		ok  bool
	}{{[]byte{25, 0, 0}, true}, {[]byte{26, 0, 0}, false}} {
		first := buf.New()
		first.Write(wire[:20])
		reader := &buf.BufferedReader{Reader: buf.NewReader(bytes.NewReader(wire[20:])), Buffer: buf.MultiBuffer{first}}
		_, _, _, fb, err := DecodeRequestHeaderChecked(true, first, reader, v, checkFor(tc.min, nil))
		if (err == nil) != tc.ok || (err != nil && fb) {
			t.Errorf("min %v: err %v fb %v", tc.min, err, fb)
		}
	}
}
