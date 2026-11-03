// Test-only interoperability driver linking the GPL-3.0-or-later Mieru API.
// Built as an external process; the production Xray core does not import it.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/enfein/mieru/v3/apis/client"
	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 3 {
		return errors.New("usage: reference-client tcp|udp host:port")
	}
	network, address := os.Args[1], os.Args[2]
	host, p, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return err
	}
	cfg := map[string]interface{}{
		"profileName": "dialect11-local-interop",
		"user":        map[string]string{"name": "synthetic-user", "password": "synthetic-password"},
		"servers":     []interface{}{map[string]interface{}{"ipAddress": host, "portBindings": []interface{}{map[string]interface{}{"port": port, "protocol": strings.ToUpper(network)}}}},
		"mtu":         1400, "multiplexing": map[string]string{"level": "MULTIPLEXING_HIGH"},
	}
	b, _ := json.Marshal(cfg)
	profile := new(appctlpb.ClientProfile)
	if err := protojson.Unmarshal(b, profile); err != nil {
		return err
	}
	c := client.NewClient()
	if err := c.Store(&client.ClientConfig{Profile: profile}); err != nil {
		return err
	}
	if err := c.Start(); err != nil {
		return err
	}
	defer c.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	tcp := func(index int) error {
		conn, err := c.DialContext(ctx, &net.TCPAddr{IP: net.ParseIP("192.0.2.123"), Port: 443})
		if err != nil {
			return fmt.Errorf("TCP %d dial: %w", index, err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		want := bytes.Repeat([]byte(fmt.Sprintf("reference-session-%d\x00", index)), 4000)
		wrote := make(chan error, 1)
		go func() { _, err := conn.Write(want); wrote <- err }()
		got := make([]byte, len(want))
		if _, err := io.ReadFull(conn, got); err != nil {
			return fmt.Errorf("TCP %d read: %w", index, err)
		}
		if err := <-wrote; err != nil {
			return err
		}
		if !bytes.Equal(want, got) {
			return errors.New("TCP corruption")
		}
		return nil
	}
	for i := 0; i < 4; i++ {
		if err := tcp(i); err != nil {
			return err
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 4; i < 8; i++ {
		wg.Add(1)
		go func(i int) { defer wg.Done(); errs <- tcp(i) }(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			return err
		}
	}
	conn, err := c.DialContext(ctx, &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return fmt.Errorf("UDP associate: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	packets := apicommon.NewUDPAssociateWrapper(apicommon.NewPacketOverStreamTunnel(conn))
	for i := 0; i < 3; i++ {
		dest := &net.UDPAddr{IP: net.IPv4(192, 0, 2, byte(10+i)), Port: 5353 + i}
		want := []byte(fmt.Sprintf("reference UDP destination %d", i))
		if _, err := packets.WriteTo(want, dest); err != nil {
			return err
		}
		got := make([]byte, 4096)
		n, source, err := packets.ReadFrom(got)
		if err != nil {
			return err
		}
		if !bytes.Equal(want, got[:n]) || source.String() != dest.String() {
			return fmt.Errorf("UDP mismatch: %q from %v", got[:n], source)
		}
	}
	fmt.Println("PASS: 4 sequential TCP, 4 concurrent TCP, 3 UDP destinations")
	return nil
}
