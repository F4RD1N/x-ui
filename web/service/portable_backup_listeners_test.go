package service

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"gorm.io/gorm"
)

func portableSetSettings(t *testing.T, filename string, values map[string]string) {
	t.Helper()
	if err := withBackupDB(filename, false, func(db *gorm.DB) error {
		for key, value := range values {
			if err := db.Where("key = ?", key).Assign(model.Setting{Value: value}).FirstOrCreate(&model.Setting{Key: key}).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func portableLoopbackListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func TestPortableListenerPreflightRejectsOccupiedAndAllowsActualOwnedEndpoint(t *testing.T) {
	filename := portableFixtureDB(t)
	l := portableLoopbackListener(t)
	port := l.Addr().(*net.TCPAddr).Port
	portableSetSettings(t, filename, map[string]string{"webListen": "127.0.0.1", "webPort": strconv.Itoa(port), "subEnable": "false"})
	if err := validateBackupListeners(filename); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatal("unrelated occupied socket was not rejected:", err)
	}
	release := RegisterRestoreListener("test-panel", l.Addr().String(), l)
	defer release()
	if err := validateBackupListeners(filename); err != nil {
		t.Fatal("exact running panel endpoint must be reusable:", err)
	}
	release()
	if err := validateBackupListeners(filename); err == nil {
		t.Fatal("released ownership was still trusted")
	}
}

func TestPortableListenerPreflightDoesNotTrustPortOnlyOrSavedSettings(t *testing.T) {
	filename := portableFixtureDB(t)
	l := portableLoopbackListener(t)
	port := l.Addr().(*net.TCPAddr).Port
	other, err := net.Listen("tcp", net.JoinHostPort("127.0.0.2", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	release := RegisterRestoreListener("test-panel", l.Addr().String(), l)
	defer release()
	portableSetSettings(t, filename, map[string]string{"webListen": "127.0.0.2", "webPort": strconv.Itoa(port), "subEnable": "false"})
	if err := validateBackupListeners(filename); err == nil {
		t.Fatal("unrelated process on same port and another address was exempted")
	}
}

func TestPortableListenerPreflightRejectsInvalidSettingsAndOverlaps(t *testing.T) {
	for _, tc := range []struct {
		name   string
		values map[string]string
	}{
		{"invalid address", map[string]string{"webListen": "127.0.0.1:443"}},
		{"negative port", map[string]string{"webPort": "-1"}},
		{"ephemeral port", map[string]string{"webPort": "0"}},
		{"overflow port", map[string]string{"webPort": "65536"}},
		{"invalid enabled", map[string]string{"subEnable": "yes"}},
		{"same endpoints", map[string]string{"webListen": "127.0.0.1", "subListen": "127.0.0.1", "webPort": "31000", "subPort": "31000"}},
		{"wildcard overlap", map[string]string{"webListen": "", "subListen": "127.0.0.1", "webPort": "31000", "subPort": "31000"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filename := portableFixtureDB(t)
			portableSetSettings(t, filename, tc.values)
			if err := validateBackupListeners(filename); err == nil {
				t.Fatal("invalid listener configuration accepted")
			}
		})
	}
}

func TestPortableListenerPreflightClosesProbesAndKeepsNewerOwnership(t *testing.T) {
	filename := portableFixtureDB(t)
	l := portableLoopbackListener(t)
	addr := l.Addr().String()
	port := l.Addr().(*net.TCPAddr).Port
	portableSetSettings(t, filename, map[string]string{"webListen": "127.0.0.1", "webPort": strconv.Itoa(port), "subEnable": "false"})
	older := RegisterRestoreListener("test-panel", addr, l)
	newer := RegisterRestoreListener("test-panel", addr, l)
	defer newer()
	older()
	if err := validateBackupListeners(filename); err != nil {
		t.Fatal("old cleanup erased current socket ownership:", err)
	}
	newer()
	_ = l.Close()
	if err := validateBackupListeners(filename); err != nil {
		t.Fatal("available port rejected:", err)
	}
	reopened, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal("probe socket leaked:", err)
	}
	_ = reopened.Close()
}

func TestPortableRestoreRejectsInvalidOrMismatchedPanelTLSBeforeRuntimeChanges(t *testing.T) {
	filename := portableFixtureDB(t)
	cert, key, _, _ := portableFixtureCertificate(t, t.TempDir())
	_, otherKey, _, _ := portableFixtureCertificate(t, t.TempDir())
	for _, tc := range []struct {
		name, cert, key string
		valid           bool
	}{
		{"missing pair", cert, "", false},
		{"missing file", cert, "/nonexistent/backup-test-private-key", false},
		{"mismatched pair", cert, otherKey, false},
		{"valid pair", cert, key, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			portableSetSettings(t, filename, map[string]string{"webCertFile": tc.cert, "webKeyFile": tc.key})
			err := validateBackupTLSSettings(filename)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%t, result=%v", tc.valid, err)
			}
		})
	}
}
