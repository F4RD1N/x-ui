package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestNativeHTTPHeaders(t *testing.T) {
	for _, v := range fixtures(t).HTTPHeaders {
		kind := uint16(1)
		if v.TLS {
			kind = 2
		}
		b, e := MakeHTTPHeader(kind, HTTPHeader{CheaterID: kind, Domain: v.Host}, v.Path, &lcgReader{state: v.Seed})
		if e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(b, unhex(t, v.Hex)) {
			t.Fatalf("kind%d native HTTP differs\ngot %q\nwant%q", kind, b, unhex(t, v.Hex))
		}
		h, e := parseHTTPAuthorization(string(b))
		if e != nil || h.CheaterID != kind || h.CustomID != 0 {
			t.Fatal(h, e)
		}
	}
}

func TestHTTPOwnedLoopbackProfiles(t *testing.T) {
	for _, kind := range []uint16{1, 2, 3} {
		t.Run(string(rune('0'+kind)), func(t *testing.T) {
			st, ct := testTLS(t)
			if kind == 1 {
				st = nil
				ct = nil
			}
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			defer l.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				r, e := l.Accept()
				if e != nil {
					done <- e
					return
				}
				c, proxy, e := HTTPServer(ctx, r, HTTPServerOptions{TLSConfig: st})
				if e != nil {
					done <- e
					return
				}
				defer c.Close()
				if string(proxy) != "route\x00metadata" {
					done <- errors.New("proxy envelope lost")
					return
				}
				_, e = io.Copy(c, c)
				done <- e
			}()
			r, e := net.Dial("tcp", l.Addr().String())
			if e != nil {
				t.Fatal(e)
			}
			c, e := HTTPClient(ctx, r, HTTPOptions{Options: Options{ProxyBuffer: []byte("route\x00metadata")}, Type: kind, Header: HTTPHeader{CheaterID: map[uint16]uint16{1: 1, 2: 2, 3: 2}[kind], Domain: "vpn.test"}, Path: "/test", TLSConfig: ct})
			if e != nil {
				t.Fatal(e)
			}
			payload := bytes.Repeat([]byte("duplex\x00\xff"), 10000)
			writeDone := make(chan error, 1)
			go func() { _, e := c.Write(payload); writeDone <- e }()
			out := make([]byte, len(payload))
			if _, e = io.ReadFull(c, out); e != nil {
				t.Fatal(e)
			}
			if !bytes.Equal(out, payload) {
				t.Fatal("HTTP data changed")
			}
			if e = <-writeDone; e != nil {
				t.Fatal(e)
			}
			if e = c.CloseWrite(); e != nil {
				t.Fatal(e)
			}
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			c.Close()
		})
	}
}

func TestHTTPHeaderBounds(t *testing.T) {
	h := HTTPHeader{CheaterID: 3, CustomID: 1, Domain: "vpn.test", Extra: "opaque"}
	for _, d := range []string{"evil\r\nHost: bad", "x\x00y"} {
		if _, e := HTTPClient(context.Background(), nopConn{}, HTTPOptions{Type: 2, Header: HTTPHeader{CheaterID: 2, Domain: d}}); e == nil {
			t.Fatal("bad domain accepted")
		}
	}
	if _, e := HTTPClient(context.Background(), nopConn{}, HTTPOptions{Type: 2, Header: HTTPHeader{CheaterID: 2, CustomID: 1, Domain: "vpn.test"}}); e == nil {
		t.Fatal("the ByeDPI SOCKS custom ID was accepted without its helper")
	}
	if _, e := HTTPClient(context.Background(), nopConn{}, HTTPOptions{Type: 4, Header: HTTPHeader{CheaterID: 2, Domain: "vpn.test"}}); e == nil {
		t.Fatal("bad factory accepted")
	}
	if _, e := MakeHTTPHeader(1, h, "/\r\n", nil); e == nil {
		t.Fatal("header injection")
	}
	if _, e := MakeHTTPHeader(1, h, "/", bytes.NewReader(nil)); e == nil {
		t.Fatal("random error ignored")
	}
	if _, e := parseHTTPAuthorization("Authorization: invalid\r\n"); e == nil {
		t.Fatal("malformed authorization")
	}
}

type nopConn struct{ net.Conn }

func (nopConn) Close() error                     { return nil }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }

func TestHTTPRejectCertificateAndTimeout(t *testing.T) {
	st, _ := testTLS(t)
	a, b := net.Pipe()
	done := make(chan error, 1)
	go func() {
		_, _, e := HTTPServer(context.Background(), b, HTTPServerOptions{Options: Options{Timeout: time.Second}, TLSConfig: st})
		done <- e
	}()
	_, e := HTTPClient(context.Background(), a, HTTPOptions{Options: Options{Timeout: time.Second}, Type: 2, Header: HTTPHeader{CheaterID: 2, Domain: "vpn.test"}, TLSConfig: &tls.Config{ServerName: "vpn.test"}})
	if e == nil {
		t.Fatal("untrusted TLS accepted")
	}
	if e = <-done; e == nil {
		t.Fatal("server accepted rejected TLS")
	}
	a, b = net.Pipe()
	defer b.Close()
	_, _, e = HTTPServer(context.Background(), a, HTTPServerOptions{Options: Options{Timeout: 20 * time.Millisecond}})
	if e == nil {
		t.Fatal("silent peer did not time out")
	}
}

func FuzzHTTPAuthorization(f *testing.F) {
	f.Add([]byte("Authorization: x\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseHTTPAuthorization(string(b))
	})
}
