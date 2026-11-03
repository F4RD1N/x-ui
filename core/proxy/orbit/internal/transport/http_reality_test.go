package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestHTTPRealityRejectsUnverifiedCarrierBeforeWriting(t *testing.T) {
	for _, typ := range []uint16{1, 2, 3, 4} {
		a, b := net.Pipe()
		received := make(chan []byte, 1)
		go func() { p, _ := io.ReadAll(b); b.Close(); received <- p }()
		_, err := HTTPClient(context.Background(), a, HTTPOptions{Options: Options{Timeout: time.Second}, Type: typ, Header: HTTPHeader{CheaterID: 2, Domain: "owned.test"}, Reality: true})
		if !errors.Is(err, ErrHTTPProfile) {
			t.Fatal("unverified carrier accepted", typ, err)
		}
		if p := <-received; len(p) != 0 {
			t.Fatal("wrote native credentials or prefix before REALITY validation")
		}
	}
}
