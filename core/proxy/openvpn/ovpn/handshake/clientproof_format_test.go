package handshake

import (
	"fmt"
	"strings"
	"testing"
)

func TestClientMessageProofFormattingRedacted(t *testing.T) {
	const proof = "1:my-key:UNIQUE_PROOF_VALUE"
	message := ClientMessage{Username: "user", Password: "private-pass", PeerInfo: "IV_VER=2.6.12\nUV_CORE_PROOF=" + proof + "\n"}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		output := fmt.Sprintf(verb, message)
		if strings.Contains(output, proof) || strings.Contains(output, "private-pass") || !strings.Contains(output, "UV_CORE_PROOF=<redacted>") {
			t.Errorf("format %s exposes proof or password", verb)
		}
	}
	wire := message.Marshal()
	decoded, _, err := ParseClientMessage(wire)
	if err != nil || !strings.Contains(decoded.PeerInfo, proof) {
		t.Fatal("redaction changed on-wire proof")
	}
}
