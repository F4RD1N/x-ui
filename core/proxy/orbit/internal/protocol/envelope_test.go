package protocol

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func loadObject(t *testing.T, name string) map[string]string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAPIIndependentGoldenAndRoundtrip(t *testing.T) {
	v := loadObject(t, "api-envelope.json")
	want := mustHex(t, v["plaintext_hex"])
	got, err := DecodeAPI(mustHex(t, v["ciphertext_hex"]), 0)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("%s %v", got, err)
	}
	for _, raw := range [][]byte{[]byte(`{"ok":true}`), []byte(`{"message":"Hello 世界","items":[1,null,false]}`), []byte(`{"error":{"code":401}}`), []byte(`[]`)} {
		encoded, err := EncodeAPI(raw, 0)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeAPI(encoded, 0)
		if err != nil || !bytes.Equal(decoded, raw) {
			t.Fatalf("%s %v", decoded, err)
		}
		plain, err := DecodeAPI(raw, 0)
		if err != nil || !bytes.Equal(plain, raw) {
			t.Fatal(err)
		}
		raw[0] = ' '
		if plain[0] == ' ' {
			t.Fatal("plainJSONinput alias")
		}
	}
}

func gzipEncrypted(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	key, iv := apiKeyIV()
	return cryptCTR(key, iv, out.Bytes())
}

func TestAPILimitsCorruptionAndMalformedJSON(t *testing.T) {
	for _, b := range [][]byte{nil, []byte("not-json"), []byte("{")} {
		if _, err := EncodeAPI(b, 0); err == nil {
			t.Fatal("invalidJSONencode")
		}
	}
	if _, err := EncodeAPI([]byte(`{"long":"value"}`), 2); err == nil {
		t.Fatal("input limit")
	}
	if _, err := EncodeAPI([]byte(`{}`), 2); err == nil {
		t.Fatal("compressed envelope limit")
	}
	for _, b := range [][]byte{nil, []byte("notgzip"), gzipEncrypted(t, []byte("not-json"))} {
		if _, err := DecodeAPI(b, 0); err == nil {
			t.Fatal("bad API accepted")
		}
	}
	encoded, _ := EncodeAPI([]byte(`{"ok":true}`), 0)
	if _, err := DecodeAPI(encoded, 2); err == nil {
		t.Fatal("input decode limit")
	}
	if _, err := DecodeAPI(encoded[:len(encoded)-1], 0); err == nil {
		t.Fatal("truncated trailer accepted")
	}
	encoded[len(encoded)-1] ^= 1
	if _, err := DecodeAPI(encoded, 0); err == nil {
		t.Fatal("corrupt gzip accepted")
	}
	bomb := gzipEncrypted(t, []byte(`"`+string(bytes.Repeat([]byte{'A'}, 10000))+`"`))
	if _, err := DecodeAPI(bomb, 1000); err == nil {
		t.Fatal("gzip expansion exceeded bound")
	}
	if _, err := readBounded(bytes.NewReader(nil), -1); err == nil {
		t.Fatal("negative max")
	}
	if _, err := readBounded(bytes.NewReader(nil), int(^uint(0)>>1)); err == nil {
		t.Fatal("overflow max")
	}
}

func TestRouterHeaderRequestAndCorrelation(t *testing.T) {
	p := RouterPacket{Random0: 12, CorrelationID: 0x11223344, Random1: 99, Type: 6, Flags: 2, Payload: []byte("hello")}
	b, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	want := mustHex(t, "0c44332211630602050068656c6c6f")
	if !bytes.Equal(b, want) {
		t.Fatalf("%x", b)
	}
	got, err := ParseRouterPacket(b)
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatal(got, err)
	}
	got.Payload[0] = 'H'
	if b[10] != 'h' {
		t.Fatal("router aliases input")
	}
	if _, err := ParseRouterResponse(b, p.CorrelationID); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRouterResponse(b, p.CorrelationID+1); err == nil {
		t.Fatal("correlation ignored")
	}
	for _, bad := range [][]byte{b[:9], b[:len(b)-1], append(append([]byte(nil), b...), 0)} {
		if _, err := ParseRouterPacket(bad); err == nil {
			t.Fatal("invalid outer length")
		}
		if _, err := ParseRouterResponse(bad, p.CorrelationID); err == nil {
			t.Fatal("bad response accepted")
		}
	}
	b[6] = 5
	if _, err := ParseRouterResponse(b, p.CorrelationID); err == nil {
		t.Fatal("response type ignored")
	}
	p.Payload = make([]byte, MaxRouterPayload)
	if _, err := p.MarshalBinary(); err != nil {
		t.Fatal(err)
	}
	p.Payload = append(p.Payload, 0)
	if _, err := p.MarshalBinary(); err == nil {
		t.Fatal("router overflow")
	}
	r := RouterRequest{FlatBuffer: []byte{1, 2, 3, 4}}
	for i := range r.UserInfo {
		r.UserInfo[i] = byte(i)
	}
	body, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParseRouterRequest(body)
	if err != nil || !reflect.DeepEqual(decoded, r) {
		t.Fatal(decoded, err)
	}
	body[133] ^= 255
	if decoded.FlatBuffer[0] != 1 {
		t.Fatal("request alias")
	}
	for _, bad := range [][]byte{make([]byte, 132), make([]byte, 65536), append(body, 0)} {
		if _, err := ParseRouterRequest(bad); err == nil {
			t.Fatal("bad router request size")
		}
	}
	for _, off := range []int{0, 2} {
		bad := append([]byte(nil), body...)
		bad[off] = 99
		if _, err := ParseRouterRequest(bad); err == nil {
			t.Fatal("requestformat")
		}
	}
	r.FlatBuffer = make([]byte, MaxRouterPayload-133)
	if _, err := r.MarshalBinary(); err != nil {
		t.Fatal(err)
	}
	r.FlatBuffer = append(r.FlatBuffer, 0)
	if _, err := r.MarshalBinary(); err == nil {
		t.Fatal("routerrequestoverflow")
	}
}

func TestRouterEnvelopeIndependentGolden(t *testing.T) {
	v := loadObject(t, "router-envelope.json")
	body := mustHex(t, v["body_hex"])
	want := mustHex(t, v["plaintext_hex"])
	got, err := DecodeRouterBody(body)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("len%d %v", len(got), err)
	}
	for _, n := range []int{0, 1, 1024, MaxRouterDecoded} {
		plain := bytes.Repeat([]byte{42}, n)
		encoded, err := EncodeRouterBody(plain, [8]byte{1, 2, 3, 4, 5, 6, 7, 8})
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeRouterBody(encoded)
		if err != nil || !bytes.Equal(decoded, plain) {
			t.Fatalf("n=%d %v", n, err)
		}
	}
	if _, err := EncodeRouterBody(make([]byte, MaxRouterDecoded+1), [8]byte{}); err == nil {
		t.Fatal("router inflatedlimit")
	}
}

func rawRouterCompressed(t *testing.T, plain []byte, tail []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := zlib.NewWriter(&out)
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	var nonce [8]byte
	key := routerKey(nonce)
	encrypted := cryptCTR(key[:], key[:], append(out.Bytes(), tail...))
	body := make([]byte, 10+len(encrypted))
	binary.LittleEndian.PutUint16(body[8:10], uint16(len(encrypted)))
	copy(body[10:], encrypted)
	return body
}

func TestRouterEnvelopeMalformedAndDecompressionLimits(t *testing.T) {
	body, _ := EncodeRouterBody([]byte("hello"), [8]byte{})
	for _, bad := range [][]byte{nil, make([]byte, 9), make([]byte, 65536), body[:len(body)-1], append(append([]byte(nil), body...), 0), make([]byte, 10), rawRouterCompressed(t, make([]byte, MaxRouterDecoded+1), nil), rawRouterCompressed(t, []byte("hello"), []byte{1, 2, 3})} {
		if _, err := DecodeRouterBody(bad); err == nil {
			t.Fatal("malformed router accepted")
		}
	}
	body[len(body)-1] ^= 1
	if _, err := DecodeRouterBody(body); err == nil {
		t.Fatal("bad zlib checksum accepted")
	}
}

func FuzzAPIAndRouterEnvelopes(f *testing.F) {
	f.Add([]byte("{}"))
	f.Add([]byte{1, 2, 3, 4})
	f.Add(make([]byte, 133))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<16 {
			return
		}
		_, _ = DecodeAPI(b, 65536)
		_, _ = DecodeRouterBody(b)
		_, _ = ParseRouterPacket(b)
		_, _ = ParseRouterRequest(b)
		if json.Valid(b) && len(b) < 60000 {
			encoded, err := EncodeAPI(b, 65536)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeAPI(encoded, 65536)
			if err != nil || !bytes.Equal(decoded, b) {
				t.Fatal("API roundtrip")
			}
		}
	})
}
