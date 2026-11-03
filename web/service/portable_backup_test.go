package service

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	portable "github.com/mhsanaei/3x-ui/v2/util/backup"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

func portableFixtureDB(t *testing.T) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "panel.db")
	err := withBackupDB(filename, false, func(db *gorm.DB) error {
		for _, item := range []any{&model.User{}, &model.Inbound{}, &model.Setting{}, &model.HistoryOfSeeders{}, &xray.ClientTraffic{}} {
			if err := db.AutoMigrate(item); err != nil {
				return err
			}
		}
		hash, err := bcrypt.GenerateFromPassword([]byte("fixture-password"), bcrypt.MinCost)
		if err != nil {
			return err
		}
		if err := db.Create(&model.User{Username: "fixture-admin", Password: string(hash)}).Error; err != nil {
			return err
		}
		if err := db.Create(&model.HistoryOfSeeders{SeederName: "UserPasswordHash"}).Error; err != nil {
			return err
		}
		return db.Create(&model.Setting{Key: "xrayTemplateConfig", Value: `{"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}`}).Error
	})
	if err != nil {
		t.Fatal(err)
	}
	return filename
}

func portableAddInbound(t *testing.T, filename string, settings, stream string) {
	t.Helper()
	if err := withBackupDB(filename, false, func(db *gorm.DB) error {
		return db.Create(&model.Inbound{UserId: 1, Enable: true, Listen: "127.0.0.1", Port: 1443, Protocol: model.AnyTLS, Tag: "native-test", Settings: settings, StreamSettings: stream, Sniffing: `{}`}).Error
	}); err != nil {
		t.Fatal(err)
	}
}

func portableFixtureCertificate(t *testing.T, directory string) (string, string, []byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	certPath, keyPath := filepath.Join(directory, "certificate.pem"), filepath.Join(directory, "private.pem")
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, certPEM, keyPEM
}

func TestPortableSnapshotIsAtomicWithWALWriters(t *testing.T) {
	filename := portableFixtureDB(t)
	db, err := database.OpenPanelBackup(filename, false)
	if err != nil {
		t.Fatal(err)
	}
	handle, _ := db.DB()
	defer handle.Close()
	if err := db.Exec("PRAGMA journal_mode=WAL").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&[]model.Setting{{Key: "pair-a", Value: "0"}, {Key: "pair-b", Value: "0"}}).Error; err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	failures := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i <= 100; i++ {
			select {
			case <-stop:
				return
			default:
			}
			err := db.Transaction(func(tx *gorm.DB) error {
				if err := tx.Model(&model.Setting{}).Where("key='pair-a'").Update("value", fmt.Sprint(i)).Error; err != nil {
					return err
				}
				time.Sleep(time.Millisecond)
				return tx.Model(&model.Setting{}).Where("key='pair-b'").Update("value", fmt.Sprint(i)).Error
			})
			if err != nil {
				failures <- err
				return
			}
		}
	}()
	defer func() {
		close(stop)
		wg.Wait()
		select {
		case err := <-failures:
			t.Error(err)
		default:
		}
	}()
	for i := 0; i < 8; i++ {
		snapshot, cleanup, err := snapshotPanelDatabase(db, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		info, _ := os.Stat(snapshot)
		dirInfo, _ := os.Stat(filepath.Dir(snapshot))
		if info.Mode().Perm() != 0600 || dirInfo.Mode().Perm() != 0700 {
			t.Fatal("snapshot permissions are not private")
		}
		err = withBackupDB(snapshot, true, func(copy *gorm.DB) error {
			var rows []model.Setting
			if err := copy.Where("key IN ?", []string{"pair-a", "pair-b"}).Order("key").Find(&rows).Error; err != nil {
				return err
			}
			if len(rows) != 2 || rows[0].Value != rows[1].Value {
				return errors.New("snapshot captured a partially committed transaction")
			}
			return nil
		})
		cleanup()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestPortableBundleRestoresNativeFieldsAndManagedAssets(t *testing.T) {
	filename := portableFixtureDB(t)
	original := t.TempDir()
	certPath, keyPath, certPEM, keyPEM := portableFixtureCertificate(t, original)
	proofPath := filepath.Join(original, "proof.key")
	if err := os.WriteFile(proofPath, []byte(strings.Repeat("ab", 32)), 0600); err != nil {
		t.Fatal(err)
	}
	stream, _ := json.Marshal(map[string]any{"security": "tls", "tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificateFile": certPath, "keyFile": keyPath}}}})
	settings := `{"clients":[{"email":"active","password":"fixture","uuidHashMiddle":true,"enable":true},{"email":"disabled","password":"other","enable":false}],"clientExport":{"nested":{"retained":true}}}`
	portableAddInbound(t, filename, settings, string(stream))
	if err := withBackupDB(filename, false, func(db *gorm.DB) error {
		if err := db.Create(&[]model.Setting{{Key: "webCertFile", Value: certPath}, {Key: "webKeyFile", Value: keyPath}, {Key: "subCertFile", Value: certPath}, {Key: "subKeyFile", Value: keyPath}}).Error; err != nil {
			return err
		}
		template, _ := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"protocol": "openvpn", "tag": "vpn", "settings": map[string]any{"ovpn": "client\n", "clientProof": map[string]any{"keyId": "fixture", "keyFile": proofPath}}}}})
		return db.Model(&model.Setting{}).Where("key='xrayTemplateConfig'").Update("value", string(template)).Error
	}); err != nil {
		t.Fatal(err)
	}
	archive, err := portableBackupFromSnapshot(filename)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := portable.Decode(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Assets) != 3 {
		t.Fatalf("assets=%d, want 3 deduplicated references", len(bundle.Assets))
	}
	if err := os.RemoveAll(original); err != nil {
		t.Fatal(err)
	}
	checked := false
	candidate, err := preparePanelRestore(bytes.NewReader(archive), t.TempDir(), func(config string) error {
		checked = true
		if strings.Contains(config, "clientExport") || strings.Contains(config, `"disabled"`) {
			return errors.New("panel-only or inactive account reached core")
		}
		if !strings.Contains(config, `"uuidHashMiddle":true`) {
			return errors.New("compatibility flag was lost")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer candidate.cleanup(false)
	if !checked || candidate.assets == "" {
		t.Fatal("candidate validation or managed asset installation missing")
	}
	refs, err := panelBackupReferences(candidate.database)
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 3 {
		t.Fatal("rewritten references lost")
	}
	contents := make(map[string]bool)
	for _, ref := range refs {
		if !strings.HasPrefix(ref, candidate.assets+string(os.PathSeparator)) {
			t.Fatal("reference escaped managed asset directory")
		}
		info, err := os.Stat(ref)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("asset missing or mode is not 0600")
		}
		data, _ := os.ReadFile(ref)
		contents[string(data)] = true
	}
	if !contents[string(certPEM)] || !contents[string(keyPEM)] || !contents[strings.Repeat("ab", 32)] {
		t.Fatal("asset bytes changed")
	}
	if err := withBackupDB(candidate.database, true, func(db *gorm.DB) error {
		var inbound model.Inbound
		if err := db.First(&inbound).Error; err != nil {
			return err
		}
		if inbound.Settings != settings {
			return errors.New("stored native nested settings changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPortableRestoreLegacySQLiteAndCandidateRejectionCleanup(t *testing.T) {
	filename := portableFixtureDB(t)
	portableAddInbound(t, filename, `{"clients":[{"email":"fixture","password":"secret","enable":true}]}`, `{}`)
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := preparePanelRestore(bytes.NewReader(data), t.TempDir(), func(string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if candidate.assets != "" {
		t.Fatal("legacy DB unexpectedly created assets")
	}
	candidate.cleanup(false)
	parent := t.TempDir()
	if _, err := preparePanelRestore(bytes.NewReader(data), parent, func(string) error { return errors.New("fixture parser rejection") }); err == nil {
		t.Fatal("candidate core rejection ignored")
	}
	entries, _ := os.ReadDir(parent)
	if len(entries) != 0 {
		t.Fatal("failed preparation left private staged files")
	}
}

func TestPortableRestoreRejectsMissingAndUnreferencedAssets(t *testing.T) {
	filename := portableFixtureDB(t)
	asset := filepath.Join(t.TempDir(), "key.pem")
	os.WriteFile(asset, []byte("fixture"), 0600)
	data, _ := os.ReadFile(filename)
	extra, err := portable.Encode(data, []string{asset})
	if err != nil {
		t.Fatal(err)
	}
	portableAddInbound(t, filename, `{"clients":[{"password":"fixture","enable":true}]}`, fmt.Sprintf(`{"tlsSettings":{"certificates":[{"keyFile":%q}]}}`, asset))
	data, _ = os.ReadFile(filename)
	missing, err := portable.Encode(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, archive := range map[string][]byte{"extra": extra, "missing": missing} {
		t.Run(name, func(t *testing.T) {
			called := false
			parent := t.TempDir()
			if _, err := preparePanelRestore(bytes.NewReader(archive), parent, func(string) error { called = true; return nil }); err == nil {
				t.Fatal("accepted mismatched asset inventory")
			}
			if called {
				t.Fatal("invalid bundle reached core validation")
			}
			entries, _ := os.ReadDir(parent)
			if len(entries) != 0 {
				t.Fatal("failed bundle left assets")
			}
		})
	}
}

func TestPortableReferenceRewriterIsNarrowAndPreservesNumbers(t *testing.T) {
	input := `{"protocol":"openvpn","settings":{"clientProof":{"keyFile":"../../original"},"unrelated":{"keyFile":"do-not-read"},"tlsSettings":{"certificates":[{"certificateFile":"cert","keyFile":"key"}]},"large":9007199254740993,"inline":"-----BEGIN KEY-----\\nunchanged"}}`
	var refs []string
	output, changed, err := rewriteBackupReferences(input, "", func(ref string) (string, error) {
		refs = append(refs, ref)
		return "/managed/" + filepath.Base(ref), nil
	})
	if err != nil || !changed {
		t.Fatal(err)
	}
	if len(refs) != 3 || !strings.Contains(output, `"large":9007199254740993`) || !strings.Contains(output, `"keyFile":"do-not-read"`) {
		t.Fatal("rewriter read unrelated data or lost precision")
	}
}

func TestPortablePrepareRejectsMalformedBundlesBeforeCoreValidation(t *testing.T) {
	filename := portableFixtureDB(t)
	data, _ := os.ReadFile(filename)
	valid, err := portable.Encode(data, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, upload := range map[string][]byte{"truncated-zip": valid[:len(valid)-12], "not-a-zip": []byte("PKxxthis is not a backup archive"), "corrupt-sqlite": []byte("SQLite format 3\x00corrupt")} {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			checked := false
			if _, err := preparePanelRestore(bytes.NewReader(upload), parent, func(string) error { checked = true; return nil }); err == nil {
				t.Fatal("malformed upload was accepted")
			}
			if checked {
				t.Fatal("malformed upload reached core validation")
			}
			entries, _ := os.ReadDir(parent)
			if len(entries) != 0 {
				t.Fatal("malformed upload left staging files")
			}
		})
	}
}

func TestPortableConcurrentRestoresAreSerializedBeforeRuntimeChanges(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("fixture executable uses a POSIX shell")
	}
	filename := portableFixtureDB(t)
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	dbDir := t.TempDir()
	t.Setenv("XUI_BIN_FOLDER", bin)
	t.Setenv("XUI_DB_FOLDER", dbDir)
	program := filepath.Join(bin, xray.GetBinaryName())
	script := `#!/bin/sh
if ! mkdir "$0.active" 2>/dev/null; then
  touch "$0.concurrent"
  exit 1
fi
sleep 0.15
rmdir "$0.active"
exit 1
`
	if err := os.WriteFile(program, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { <-start; results <- (&ServerService{}).importPortableBackup(bytes.NewReader(data)) }()
	}
	close(start)
	for i := 0; i < 2; i++ {
		if err := <-results; err == nil {
			t.Fatal("fixture rejection did not stop restore before runtime changes")
		}
	}
	if _, err := os.Stat(program + ".concurrent"); !os.IsNotExist(err) {
		t.Fatal("two restores entered validation concurrently")
	}
	entries, _ := os.ReadDir(dbDir)
	if len(entries) != 0 {
		t.Fatal("rejected concurrent restores left staging data")
	}
}

func TestPortableCommitRealSQLitePreservesNativeRowsAndRollsBack(t *testing.T) {
	for _, failStart := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "rollback"}[failStart], func(t *testing.T) {
			live := portableFixtureDB(t)
			incoming := portableFixtureDB(t)
			listener := portableLoopbackListener(t)
			releaseListener := RegisterRestoreListener("publication-fixture", listener.Addr().String(), listener)
			defer releaseListener()
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			portableSetSettings(t, incoming, map[string]string{"webListen": "127.0.0.1", "webPort": port, "subEnable": "false"})
			native := `{"clients":[{"email":"restored","username":"fixture","password":"secret","uuidMetadataTrailer":false,"enable":true}],"clientExport":{"nested":[1,2,3]},"transport":"udp"}`
			if err := withBackupDB(incoming, false, func(db *gorm.DB) error {
				return db.Create(&model.Inbound{UserId: 1, Enable: true, Listen: "127.0.0.1", Port: 2443, Protocol: model.Mieru, Tag: "restored-mieru", Settings: native, StreamSettings: `{}`, Sniffing: `{}`}).Error
			}); err != nil {
				t.Fatal(err)
			}
			archive, err := portableBackupFromSnapshot(incoming)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := preparePanelRestore(bytes.NewReader(archive), filepath.Dir(live), func(string) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.cleanup(false)
			active, err := database.OpenPanelBackup(live, false)
			if err != nil {
				t.Fatal(err)
			}
			closeActive := func() error {
				if active == nil {
					return nil
				}
				handle, err := active.DB()
				active = nil
				if err != nil {
					return err
				}
				return handle.Close()
			}
			defer closeActive()
			running, manual := true, false
			oldConfig := &xray.Config{}
			hooks := panelRestoreHooks{Running: func() bool { return running }, Manual: func() bool { return manual }, SetManual: func(v bool) { manual = v }, PreviousConfig: func() *xray.Config { return oldConfig }, Stop: func() error { running = false; return nil }, CloseDB: closeActive, Checkpoint: func() error { return active.Exec("PRAGMA wal_checkpoint(TRUNCATE)").Error }, Rename: os.Rename,
				OpenDB: func(filename string) error {
					var err error
					active, err = database.OpenPanelBackup(filename, false)
					return err
				},
				Start: func(cfg *xray.Config) error {
					if failStart && cfg == prepared.config {
						return errors.New("injected core startup failure")
					}
					running = true
					return nil
				}}
			err = commitPanelRestore(live, prepared.database, prepared.config, hooks)
			if (err != nil) != failStart {
				t.Fatalf("unexpected commit result: %v", err)
			}
			if active == nil || !running || manual {
				t.Fatal("runtime or SQL handle was not usable after transaction")
			}
			var rows []model.Inbound
			if err := active.Find(&rows).Error; err != nil {
				t.Fatal(err)
			}
			if failStart {
				if len(rows) != 0 {
					t.Fatal("failed restore replaced predecessor rows")
				}
			} else {
				if len(rows) != 1 || rows[0].Settings != native {
					t.Fatal("committed SQLite lost nested native fields")
				}
			}
		})
	}
}

func TestPortableRestoreDoesNotPublishCandidateBeforeStartupSuccess(t *testing.T) {
	for _, failStart := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "rollback"}[failStart], func(t *testing.T) {
			previous := database.GetDB()
			live := portableFixtureDB(t)
			incoming := portableFixtureDB(t)
			listener := portableLoopbackListener(t)
			releaseListener := RegisterRestoreListener("publication-fixture", listener.Addr().String(), listener)
			defer releaseListener()
			_, port, _ := net.SplitHostPort(listener.Addr().String())
			portableSetSettings(t, incoming, map[string]string{"webListen": "127.0.0.1", "webPort": port, "subEnable": "false"})
			portableAddInbound(t, incoming, `{"clients":[{"email":"candidate-only","password":"fixture","enable":true}]}`, `{}`)
			archive, err := portableBackupFromSnapshot(incoming)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := preparePanelRestore(bytes.NewReader(archive), filepath.Dir(live), func(string) error { return nil })
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.cleanup(false)
			if err := database.InitDB(live); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = database.CloseDB()
				if previous != nil {
					_ = database.PublishDB(previous)
				}
			}()
			oldHandle := database.GetDB()
			oldConfig := &xray.Config{}
			running, manual := true, false
			hooks := (&ServerService{}).portableRestoreHooks()
			hooks.Running = func() bool { return running }
			hooks.Manual = func() bool { return manual }
			hooks.SetManual = func(value bool) { manual = value }
			hooks.PreviousConfig = func() *xray.Config { return oldConfig }
			hooks.Stop = func() error { running = false; return nil }
			attempted := false
			hooks.Start = func(cfg *xray.Config) error {
				if cfg == prepared.config {
					attempted = true
					if database.GetDB() != oldHandle {
						t.Error("candidate became globally visible before startup succeeded")
					}
					result := make(chan error, 1)
					go func() {
						result <- database.GetDB().Create(&model.Setting{Key: "during-start", Value: "must-not-be-acknowledged"}).Error
					}()
					if err := <-result; err == nil {
						t.Error("write was acknowledged against a rollbackable candidate")
					}
					if release, ok := database.TryMutation(); ok {
						release()
						t.Error("mutation admission remained open during commit")
					}
					if failStart {
						return errors.New("injected startup rejection")
					}
				}
				running = true
				return nil
			}
			end := database.BeginRestore()
			err = commitPanelRestore(live, prepared.database, prepared.config, hooks)
			end()
			if (err != nil) != failStart {
				t.Fatalf("unexpected result: %v", err)
			}
			if !attempted {
				t.Fatal("startup boundary not exercised")
			}
			var rows []model.Inbound
			if err := database.GetDB().Find(&rows).Error; err != nil {
				t.Fatal(err)
			}
			if failStart && len(rows) != 0 {
				t.Fatal("failed candidate remained published")
			}
			if !failStart && len(rows) != 1 {
				t.Fatal("successful candidate was not published")
			}
			release, ok := database.TryMutation()
			if !ok {
				t.Fatal("admission did not reopen")
			}
			err = database.GetDB().Create(&model.Setting{Key: "after-commit", Value: "acknowledged"}).Error
			release()
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPortableStoppedReloadFlagIsScopedAndClearsPendingRestart(t *testing.T) {
	beforeStop, beforeNeed := restoreStoppedReload.Load(), isNeedXrayRestart.Load()
	defer func() { restoreStoppedReload.Store(beforeStop); isNeedXrayRestart.Store(beforeNeed) }()
	restoreStoppedReload.Store(true)
	isNeedXrayRestart.Store(true)
	if !ConsumeRestoreStoppedReload() {
		t.Fatal("stopped reload flag was lost")
	}
	if ConsumeRestoreStoppedReload() {
		t.Fatal("stopped reload flag affected a later restart")
	}
	if isNeedXrayRestart.Load() {
		t.Fatal("pending restart would undo intentionally stopped state")
	}
}
