// Independent interoperability fixture, never imported by the production core.
// Build in a separate module with github.com/anytls/sing-anytls v0.0.11.
// That dependency is GPL-3.0-or-later; preserve its notices with the test binary.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	anytls "github.com/anytls/sing-anytls"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	address := flag.String("server", "", "loopback fixture address")
	password := flag.String("password", "fixture-password", "fixture-only credential")
	network := flag.String("network", "tcp", "tcp or udp")
	flag.Parse()
	host, _, err := net.SplitHostPort(*address)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return fmt.Errorf("fixture server must be a loopback address")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	client, err := anytls.NewClient(ctx, anytls.ClientConfig{Password: *password, Logger: logger.NOP(), IdleSessionCheckInterval: 30 * time.Second, IdleSessionTimeout: 60 * time.Second, DialOut: func(ctx context.Context) (net.Conn, error) {
		d := tls.Dialer{Config: &tls.Config{ServerName: "anytls.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}}
		return d.DialContext(ctx, "tcp", *address)
	}})
	if err != nil {
		return err
	}
	defer client.Close()
	for i := 0; i < 3; i++ {
		target := M.ParseSocksaddr("127.0.0.1:5300")
		streamTarget := target
		if *network == "udp" {
			streamTarget = uot.RequestDestination(2)
		} else if *network != "tcp" {
			return fmt.Errorf("unknown network")
		}
		conn, err := client.CreateProxy(ctx, streamTarget)
		if err != nil {
			return err
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		payload := bytes.Repeat([]byte("independent-reference-payload"), 100)
		var reply []byte
		if *network == "udp" {
			request := uot.Request{Destination: target}
			if err = uot.WriteRequest(conn, request); err != nil {
				conn.Close()
				return err
			}
			packets := uot.NewConn(conn, request)
			if _, err = packets.WriteTo(payload, target); err != nil {
				conn.Close()
				return err
			}
			reply = make([]byte, 8192)
			n, _, e := packets.ReadFrom(reply)
			if e != nil {
				conn.Close()
				return e
			}
			reply = reply[:n]
		} else {
			if _, err = conn.Write(payload); err != nil {
				conn.Close()
				return err
			}
			reply = make([]byte, len(payload))
			if _, err = io.ReadFull(conn, reply); err != nil {
				conn.Close()
				return err
			}
		}
		conn.Close()
		if !bytes.Equal(payload, reply) {
			return fmt.Errorf("reference payload mismatch")
		}
	}
	fmt.Println("reference client: three payload round trips passed")
	return nil
}
