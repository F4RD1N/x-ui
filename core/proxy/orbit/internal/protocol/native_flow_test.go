package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
)

func TestAdditionalNativeFlowGoldens(t *testing.T) {
	b, err := os.ReadFile("testdata/native-flow.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Tests []struct {
			Test, FrameHex, HeaderHex, BodyHex    string
			Metadata                              uint16
			PayloadBytes, TotalBytes, LengthDelta int
			Full, Accepted                        bool
		}
	}
	if err := json.Unmarshal(b, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, v := range fixture.Tests {
		t.Run(v.Test, func(t *testing.T) {
			switch v.Test {
			case "connect response echoes metadata":
				got := wire(t, SocketConnectResponse{0x12345678, v.Metadata}.Frame())
				if !bytes.Equal(got, mustHex(t, v.FrameHex)) {
					t.Fatal("native response mismatch")
				}
			case "read close frame with zeroed allocator tail":
				got := wire(t, SocketReadClose{SocketID: 0x12345678}.Frame())
				if !bytes.Equal(got, mustHex(t, v.FrameHex)) {
					t.Fatal("native read-close mismatch")
				}
			case "buffer full parser requires byte one":
				got, err := ParseSocketBuffer(Frame{Type: TypeSocketBuffer, Payload: mustHex(t, v.BodyHex)})
				if err != nil || got.Flag != v.Full {
					t.Fatal(got, err)
				}
			case "native UDP inner builder":
				u := UDPEnvelope{Kind: UDPKindData, Source: netip.MustParseAddrPort("192.0.2.10:12345"), Destination: netip.MustParseAddrPort("198.51.100.20:53"), Data: bytes.Repeat([]byte{'v'}, v.PayloadBytes)}
				got, err := u.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got[:15], mustHex(t, v.HeaderHex)) {
					t.Fatal("native UDP header mismatch")
				}
				if v.FrameHex != "" && !bytes.Equal(got, mustHex(t, v.FrameHex)) {
					t.Fatal("native UDP payload mismatch")
				}
			case "native UDP receive bounds":
				got := make([]byte, v.TotalBytes)
				if len(got) >= 15 {
					got[0] = UDPKindData
					binary.LittleEndian.PutUint16(got[13:15], uint16(v.TotalBytes-15+v.LengthDelta))
				}
				_, err := ParseUDPEnvelope(got)
				if (err == nil) != v.Accepted {
					t.Fatalf("native acceptance differed: %v", err)
				}
			default:
				t.Fatalf("unhandled fixture %q", v.Test)
			}
		})
	}
}
