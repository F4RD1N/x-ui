package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

type nativeFixture struct {
	Tests []struct {
		Test         string `json:"test"`
		Hex          string `json:"hex"`
		Ciphertext   string `json:"ciphertextHex"`
		Plaintext    string `json:"plaintextHex"`
		Header       string `json:"headerHex"`
		PayloadBytes int    `json:"payloadBytesEmitted"`
	} `json:"tests"`
}

func loadNative(t *testing.T, name string) nativeFixture {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var f nativeFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestUserInfoNativeGolden(t *testing.T) {
	f := loadNative(t, "native-crypto.json")
	var ciphertext, plaintext []byte
	for _, test := range f.Tests {
		if test.Plaintext != "" {
			ciphertext = mustHex(t, test.Ciphertext)
			plaintext = mustHex(t, test.Plaintext)
		}
	}
	if len(ciphertext) != 128 || len(plaintext) != 128 {
		t.Fatal("missing golden")
	}
	u := UserInfo{UID: "audit-user", Token: "audit-token", DeviceID: "audit-device", MemberLevel: 7, Flag0: true, Flag1: true}
	encoded, err := EncodeUserInfo(u, bytes.NewReader(mustHex(t, "77276a5ec1fa2c95")))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded[:], ciphertext) {
		t.Fatalf("native ciphertext mismatch\n%s", hex.EncodeToString(encoded[:]))
	}
	decoded, err := DecodeUserInfo(ciphertext)
	if err != nil || decoded != u {
		t.Fatalf("%+v %v", decoded, err)
	}
	block, _ := aes.NewCipher(commonKey[:])
	got := make([]byte, 128)
	cipher.NewCBCDecrypter(block, commonKey[:]).CryptBlocks(got, ciphertext)
	if !bytes.Equal(got, plaintext) {
		t.Fatal("plaintext mismatch")
	}
	plaintext[76] ^= 1
	cipher.NewCBCEncrypter(block, commonKey[:]).CryptBlocks(got, plaintext)
	if _, err := DecodeUserInfo(got); !errors.Is(err, ErrMalformed) {
		t.Fatal(err)
	}
}

func TestUserInfoTruncationNULFlagsAndEntropy(t *testing.T) {
	for _, u := range []UserInfo{{}, {UID: strings.Repeat("U", 50), Token: strings.Repeat("T", 50), DeviceID: strings.Repeat("D", 50), MemberLevel: 65535}, {UID: "one\x00two", Token: strings.Repeat("é", 17), DeviceID: strings.Repeat("字", 14), Flag0: true}, {Flag1: true}} {
		encoded, err := EncodeUserInfo(u, bytes.NewReader(make([]byte, 8)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeUserInfo(encoded[:])
		if err != nil || got != NormalizeIdentity(u) {
			t.Fatalf("%+v %v", got, err)
		}
	}
	if _, err := EncodeUserInfo(UserInfo{}, bytes.NewReader(nil)); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
	if _, err := EncodeUserInfo(UserInfo{}, nil); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 127, 129, 256} {
		if _, err := DecodeUserInfo(make([]byte, n)); err == nil {
			t.Fatal(n)
		}
	}
}

func TestConnectNativeGoldenAndFormatRejection(t *testing.T) {
	f := loadNative(t, "native-crypto.json")
	var golden []byte
	for _, test := range f.Tests {
		if strings.HasPrefix(test.Test, "Complete native connection") {
			golden = mustHex(t, test.Hex)
		}
	}
	if len(golden) != 155 {
		t.Fatal("missing connect golden")
	}
	u, _ := EncodeUserInfo(UserInfo{UID: "audit-user", Token: "audit-token", DeviceID: "audit-device", MemberLevel: 7, Flag0: true, Flag1: true}, bytes.NewReader(mustHex(t, "77276a5ec1fa2c95")))
	id, err := ParseChannelID("00112233445566778899aabbccddeeff")
	if err != nil {
		t.Fatal(err)
	}
	c := ConnectRequest{UserInfo: u, ConnectionID: 0x11223344, ChannelID: id}
	if !bytes.Equal(wire(t, c.Frame(ConnectFlags)), golden) {
		t.Fatal("connect native mismatch")
	}
	got, err := ParseConnectRequest(c.Frame(2))
	if err != nil || got != c {
		t.Fatalf("%+v %v", got, err)
	}
	for _, s := range []string{"", strings.Repeat("a", 31), strings.Repeat("g", 32), strings.Repeat("a", 33), "00112233-4455-6677-8899-aabbccddeeff"} {
		if _, err := ParseChannelID(s); err == nil {
			t.Fatal("bad channel accepted")
		}
	}
	for _, mutate := range []func(*Frame){func(f *Frame) { f.Type = 9 }, func(f *Frame) { f.Payload = f.Payload[:150] }, func(f *Frame) { f.Payload[0] = 2 }, func(f *Frame) { f.Payload[2] = 2 }} {
		f := c.Frame(2)
		mutate(&f)
		if _, err := ParseConnectRequest(f); err == nil {
			t.Fatal("bad connect accepted")
		}
	}
}

func TestIndependentNativeAESVectors(t *testing.T) {
	f := loadNative(t, "native-crypto.json")
	key := make([]byte, 16)
	plain := make([]byte, 128)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range plain {
		plain[i] = byte(i)
	}
	block, _ := aes.NewCipher(key)
	for _, v := range f.Tests {
		if !strings.Contains(v.Test, "matches independent implementation, IV equals key") {
			continue
		}
		got := make([]byte, 128)
		if strings.Contains(v.Test, "CBC") {
			cipher.NewCBCEncrypter(block, key).CryptBlocks(got, plain)
		} else {
			cipher.NewCTR(block, key).XORKeyStream(got, plain)
		}
		if !bytes.Equal(got, mustHex(t, v.Ciphertext)) {
			t.Fatal(v.Test)
		}
	}
}

func FuzzUserInfo(f *testing.F) {
	f.Add("user", "token", "device", uint16(7), true, false)
	f.Fuzz(func(t *testing.T, uid, token, device string, member uint16, a, b bool) {
		u := UserInfo{uid, token, device, member, a, b}
		encoded, err := EncodeUserInfo(u, bytes.NewReader(make([]byte, 8)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeUserInfo(encoded[:])
		if err != nil || got != NormalizeIdentity(u) {
			t.Fatal("userinfo round trip")
		}
	})
}
