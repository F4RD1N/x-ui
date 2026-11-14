package sys

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSockstatCounts(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "net"), 0o755)
	os.WriteFile(filepath.Join(root, "net", "sockstat"), []byte("sockets: used 311234\nTCP: inuse 150981 orphan 21 tw 164464 alloc 288410 mem 161358\nUDP: inuse 8123 mem 900\nUDPLITE: inuse 0\nRAW: inuse 0\nFRAG: inuse 0 memory 0\n"), 0o644)
	os.WriteFile(filepath.Join(root, "net", "sockstat6"), []byte("TCP6: inuse 120034\nUDP6: inuse 12\nUDPLITE6: inuse 0\nRAW6: inuse 1\nFRAG6: inuse 0 memory 0\n"), 0o644)
	tcp, udp, ok := sockstatCounts(root)
	if !ok || tcp != 150981+120034+164464 || udp != 8123+12 {
		t.Fatalf("got tcp %d udp %d ok %v", tcp, udp, ok)
	}
	os.Remove(filepath.Join(root, "net", "sockstat6"))
	if tcp, udp, ok := sockstatCounts(root); !ok || tcp != 150981+164464 || udp != 8123 {
		t.Fatalf("without sockstat6: tcp %d udp %d ok %v", tcp, udp, ok)
	}
	if _, _, ok := sockstatCounts(t.TempDir()); ok {
		t.Fatal("no sockstat must fall back")
	}
}

func TestSockstatOnThisHost(t *testing.T) {
	tcp, udp, ok := sockstatCounts("/proc")
	if !ok {
		t.Skip("no /proc/net/sockstat")
	}
	t.Logf("this host: tcp %d udp %d", tcp, udp)
}
