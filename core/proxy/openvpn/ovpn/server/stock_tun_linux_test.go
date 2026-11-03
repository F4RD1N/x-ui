//go:build linux

package server

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This test must be explicitly launched under unshare -n. It creates temporary
// TUN interfaces only in that private namespace, and never changes host routes.
func TestStockOpenVPNTUNDataAndRekey(t *testing.T) {
	if os.Getenv("D11_OPENVPN_PRIVATE_NETNS") != "1" {
		t.Skip("requires dedicated unshare -n namespace")
	}
	mine, _ := os.Readlink("/proc/self/ns/net")
	host, _ := os.Readlink("/proc/1/ns/net")
	if mine == host {
		t.Fatal("refusing TUN test in host network namespace")
	}
	for _, binary := range []string{"/usr/sbin/openvpn", "/usr/sbin/ip", "/usr/bin/ping"} {
		if _, e := os.Stat(binary); e != nil {
			t.Skip("missing local oracle binary")
		}
	}
	if out, e := exec.Command("/usr/sbin/ip", "link", "set", "lo", "up").CombinedOutput(); e != nil {
		t.Fatalf("loopback: %v (%d bytes)", e, len(out))
	}
	for _, tcp := range []bool{false, true} {
		t.Run(fmt.Sprintf("tcp=%v", tcp), func(t *testing.T) {
			var packets atomic.Int32
			h := startHarnessTransform(t, Config{TCP: tcp, Renegotiate: time.Second}, func(p []byte) []byte {
				// Deterministic ICMP endpoint at the tunnel gateway, independently of the
				// host kernel and of the OpenVPN client under test.
				if len(p) < 28 || p[0] != 0x45 || p[9] != 1 || p[20] != 8 {
					return nil
				}
				p = append([]byte(nil), p...)
				for i := 0; i < 4; i++ {
					p[12+i], p[16+i] = p[16+i], p[12+i]
				}
				p[20] = 0
				p[22], p[23] = 0, 0
				binary.BigEndian.PutUint16(p[22:24], ipChecksum(p[20:]))
				p[10], p[11] = 0, 0
				binary.BigEndian.PutUint16(p[10:12], ipChecksum(p[:20]))
				packets.Add(1)
				return p
			})
			text := strings.Replace(h.text(t, ""), "dev tun", "dev ovtest\ndev-type tun", 1)
			dir := t.TempDir()
			profile := filepath.Join(dir, "client.ovpn")
			if e := os.WriteFile(profile, []byte(text), 0600); e != nil {
				t.Fatal(e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/usr/sbin/openvpn", "--config", profile, "--verb", "3")
			pipe, e := cmd.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			cmd.Stderr = cmd.Stdout
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() { cancel(); cmd.Wait() }()
			ready := make(chan struct{})
			go func() {
				scanner := bufio.NewScanner(pipe)
				once := false
				for scanner.Scan() {
					if !once && strings.Contains(scanner.Text(), "Initialization Sequence Completed") {
						close(ready)
						once = true
					}
				}
			}()
			select {
			case <-ready:
			case <-ctx.Done():
				t.Fatal("stock TUN initialization timed out")
			}
			// Real kernel ICMP requests cross the stock OpenVPN TUN, native server's
			// decrypt/encrypt path, and return across the TUN during multiple rekeys.
			result, e := exec.CommandContext(ctx, "/usr/bin/ping", "-n", "-c", "12", "-i", "0.2", "-W", "2", "-s", "1300", "10.8.0.1").CombinedOutput()
			if e != nil {
				t.Fatalf("stock TUN traffic: %v: %s", e, result)
			}
			if packets.Load() != 12 {
				t.Fatalf("received %d, expected 12 real IP packets", packets.Load())
			}
		})
	}
}
func ipChecksum(p []byte) uint16 {
	var sum uint32
	for len(p) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) > 0 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
