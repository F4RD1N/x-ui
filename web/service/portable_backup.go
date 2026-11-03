package service

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	portable "github.com/mhsanaei/3x-ui/v2/util/backup"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"gorm.io/gorm"
)

// Separate lock orders avoid a gated cron/Telegram backup waiting on the
// restore serializer while restore waits for that mutation to drain.
var portableRestoreMu sync.Mutex
var portableSnapshotMu sync.Mutex
var restoreStoppedReload atomic.Bool

// GetBackup returns the portable archive used by HTTP and Telegram exports.
func (s *ServerService) GetBackup() ([]byte, error) {
	portableSnapshotMu.Lock()
	defer portableSnapshotMu.Unlock()
	filename, cleanup, err := snapshotPanelDatabase(database.GetDB(), filepath.Dir(config.GetDBPath()))
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return portableBackupFromSnapshot(filename)
}

func (s *ServerService) atomicRawBackup() ([]byte, error) {
	portableSnapshotMu.Lock()
	defer portableSnapshotMu.Unlock()
	filename, cleanup, err := snapshotPanelDatabase(database.GetDB(), filepath.Dir(config.GetDBPath()))
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return readBoundedBackupFile(filename, portable.MaxDatabase)
}

type preparedPanelRestore struct {
	directory string
	database  string
	assets    string
	config    *xray.Config
}

func (candidate *preparedPanelRestore) cleanup(keepAssets bool) {
	_ = os.RemoveAll(candidate.directory)
	if !keepAssets && candidate.assets != "" {
		_ = os.RemoveAll(candidate.assets)
	}
}

// preparePanelRestore does all parsing, migrations, asset installation and core
// validation before the caller is allowed to stop the live runtime.
func preparePanelRestore(reader io.Reader, directory string, testConfig func(string) error) (_ *preparedPanelRestore, resultErr error) {
	absoluteDirectory, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	directory = absoluteDirectory
	stage, err := os.MkdirTemp(directory, ".xui-restore-")
	if err != nil {
		return nil, err
	}
	candidate := &preparedPanelRestore{directory: stage, database: filepath.Join(stage, "candidate.db")}
	defer func() {
		if resultErr != nil {
			candidate.cleanup(false)
		}
	}()
	upload, err := os.OpenFile(filepath.Join(stage, "upload"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer upload.Close()
	size, err := io.Copy(upload, io.LimitReader(reader, portable.MaxTotal+1))
	if err != nil {
		return nil, errors.New("cannot stage backup upload")
	}
	if size <= 0 || size > portable.MaxTotal {
		return nil, errors.New("backup upload exceeds size limit")
	}
	if err = upload.Sync(); err != nil {
		return nil, err
	}
	var signature [16]byte
	if _, err = upload.ReadAt(signature[:], 0); err != nil {
		return nil, errors.New("backup is truncated")
	}
	var assets []portable.Asset
	isBundle := !isSQLiteBackup(signature[:])
	if isBundle {
		bundle, err := portable.Decode(upload, size)
		if err != nil {
			return nil, err
		}
		if err = os.WriteFile(candidate.database, bundle.Database, 0600); err != nil {
			return nil, err
		}
		assets = bundle.Assets
	} else {
		if size > portable.MaxDatabase {
			return nil, errors.New("backup database exceeds size limit")
		}
		if err = upload.Close(); err != nil {
			return nil, err
		}
		if err = os.Rename(upload.Name(), candidate.database); err != nil {
			return nil, err
		}
	}
	if err = database.MigratePanelBackup(candidate.database); err != nil {
		return nil, err
	}
	if err = migratePortableCandidate(candidate.database); err != nil {
		return nil, err
	}
	if isBundle {
		candidate.assets, err = installBackupAssets(candidate.database, directory, assets)
		if err != nil {
			return nil, err
		}
	}
	if err = validateBackupTLSSettings(candidate.database); err != nil {
		return nil, err
	}
	candidate.config, err = portableCandidateConfig(candidate.database)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(candidate.config)
	if err != nil {
		return nil, err
	}
	if testConfig == nil {
		return nil, errors.New("candidate core validation is unavailable")
	}
	if err = testConfig(string(encoded)); err != nil {
		return nil, fmt.Errorf("backup core configuration is invalid: %w", err)
	}
	return candidate, nil
}

// The old import called a void migration helper which swallowed SQL errors.
// Apply required legacy repairs privately and return every failure instead.
func migratePortableCandidate(filename string) error {
	return withBackupDB(filename, false, func(db *gorm.DB) error {
		return db.Transaction(func(tx *gorm.DB) error {
			for _, table := range []string{"inbounds", "client_traffics"} {
				if err := tx.Exec("UPDATE " + table + " SET all_time=IFNULL(up,0)+IFNULL(down,0) WHERE IFNULL(all_time,0)=0 AND (IFNULL(up,0)+IFNULL(down,0))>0").Error; err != nil {
					return err
				}
			}
			var inbounds []model.Inbound
			if err := tx.Find(&inbounds).Error; err != nil {
				return err
			}
			for _, inbound := range inbounds {
				if strings.TrimSpace(inbound.Settings) == "" {
					continue
				}
				var settings map[string]json.RawMessage
				if json.Unmarshal([]byte(inbound.Settings), &settings) != nil || settings == nil {
					return errors.New("backup contains malformed inbound settings")
				}
				var clients []map[string]json.RawMessage
				if raw, exists := settings["clients"]; exists {
					if json.Unmarshal(raw, &clients) != nil {
						return errors.New("backup inbound clients must be objects")
					}
				}
				changed := false
				legacy := inbound.Protocol == model.VMESS || inbound.Protocol == model.VLESS || inbound.Protocol == model.Trojan
				for _, client := range clients {
					if client == nil {
						return errors.New("backup client must be an object")
					}
					if legacy {
						var flow string
						_ = json.Unmarshal(client["flow"], &flow)
						if flow == "xtls-rprx-direct" {
							client["flow"] = json.RawMessage(`""`)
							changed = true
						}
						var tgID string
						if json.Unmarshal(client["tgId"], &tgID) == nil {
							if number, err := strconv.ParseInt(strings.ReplaceAll(tgID, " ", ""), 10, 64); err == nil {
								client["tgId"], _ = json.Marshal(number)
								changed = true
							}
						}
					}
					var metadata struct {
						Email      string
						Enable     *bool
						TotalGB    int64
						ExpiryTime int64
						Reset      int
					}
					encoded, _ := json.Marshal(client)
					if err := json.Unmarshal(encoded, &metadata); err != nil {
						return errors.New("backup has invalid client accounting metadata")
					}
					if metadata.Email == "" {
						continue
					}
					var count int64
					if err := tx.Model(&xray.ClientTraffic{}).Where("email = ?", metadata.Email).Count(&count).Error; err != nil {
						return err
					}
					if count == 0 {
						enabled := metadata.Enable == nil || *metadata.Enable
						row := xray.ClientTraffic{InboundId: inbound.Id, Email: metadata.Email, Enable: enabled, Total: metadata.TotalGB, ExpiryTime: metadata.ExpiryTime, Reset: metadata.Reset}
						if err := tx.Create(&row).Error; err != nil {
							return err
						}
					}
				}
				if changed {
					settings["clients"], _ = json.Marshal(clients)
					encoded, _ := json.Marshal(settings)
					if err := tx.Model(&model.Inbound{}).Where("id = ?", inbound.Id).Update("settings", string(encoded)).Error; err != nil {
						return err
					}
				}
			}
			return nil
		})
	})
}

func portableCandidateConfig(filename string) (*xray.Config, error) {
	var configOut xray.Config
	err := withBackupDB(filename, true, func(db *gorm.DB) error {
		var inbounds []model.Inbound
		if err := db.Preload("ClientStats").Find(&inbounds).Error; err != nil {
			return err
		}
		template := xrayTemplateConfig
		if len(inbounds) > 0 {
			template = previousXrayTemplateConfig
		}
		var row model.Setting
		err := db.Where("key = ?", "xrayTemplateConfig").Take(&row).Error
		if err == nil {
			template = row.Value
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err := json.Unmarshal([]byte(template), &configOut); err != nil {
			return errors.New("backup Xray template is invalid")
		}
		configOut.OutboundConfigs = withDirectMark(configOut.OutboundConfigs)
		for _, inbound := range inbounds {
			if !inbound.Enable {
				continue
			}
			settings, err := coreInboundSettings(&inbound)
			if errors.Is(err, errNoActiveNativeClients) {
				continue
			}
			if err != nil {
				return coreInboundProjectionError(string(inbound.Protocol), err)
			}
			inbound.Settings = settings
			if strings.TrimSpace(inbound.StreamSettings) != "" {
				var stream map[string]json.RawMessage
				if json.Unmarshal([]byte(inbound.StreamSettings), &stream) != nil || stream == nil {
					return errors.New("backup contains invalid stream settings")
				}
				delete(stream, "externalProxy")
				for _, key := range []string{"tlsSettings", "realitySettings"} {
					if raw, exists := stream[key]; exists {
						var settings map[string]json.RawMessage
						if json.Unmarshal(raw, &settings) == nil && settings != nil {
							delete(settings, "settings")
							stream[key], _ = json.Marshal(settings)
						}
					}
				}
				encoded, _ := json.Marshal(stream)
				inbound.StreamSettings = string(encoded)
			}
			configOut.InboundConfigs = append(configOut.InboundConfigs, *inbound.GenXrayInboundConfig())
		}
		return nil
	})
	return &configOut, err
}

func validateBackupTLSSettings(filename string) error {
	return withBackupDB(filename, true, func(db *gorm.DB) error {
		var rows []model.Setting
		if err := db.Where("key IN ?", []string{"webCertFile", "webKeyFile", "subCertFile", "subKeyFile"}).Find(&rows).Error; err != nil {
			return err
		}
		values := make(map[string]string)
		for _, row := range rows {
			values[row.Key] = row.Value
		}
		for _, prefix := range []string{"web", "sub"} {
			cert, key := values[prefix+"CertFile"], values[prefix+"KeyFile"]
			if cert == "" && key == "" {
				continue
			}
			if cert == "" || key == "" {
				return errors.New("backup TLS certificate and key must both be present")
			}
			if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
				return errors.New("backup panel or subscription TLS keypair is invalid")
			}
		}
		return nil
	})
}

func (s *ServerService) importPortableBackup(reader io.Reader) error {
	portableRestoreMu.Lock()
	defer portableRestoreMu.Unlock()
	candidate, err := preparePanelRestore(reader, filepath.Dir(config.GetDBPath()), xray.TestConfig)
	if err != nil {
		return err
	}
	committed, retainAssets := false, false
	defer func() { candidate.cleanup(committed || retainAssets) }()

	endMaintenance, admitted := database.TryBeginRestore()
	if !admitted {
		return errors.New("panel lifecycle operation is in progress; retry the restore shortly")
	}
	defer endMaintenance()
	if err := validateBackupListeners(candidate.database); err != nil {
		return err
	}
	portableSnapshotMu.Lock()
	defer portableSnapshotMu.Unlock()

	// The existing lifecycle lock blocks scheduled/manual restarts throughout
	// the DB switch. Production hooks below do not recursively acquire it.
	lock.Lock()
	defer lock.Unlock()
	needRestart := isNeedXrayRestart.Load()
	err = commitPanelRestore(config.GetDBPath(), candidate.database, candidate.config, s.portableRestoreHooks())
	if err != nil {
		var recovery *panelRestoreRecoveryError
		retainAssets = errors.As(err, &recovery)
		isNeedXrayRestart.Store(needRestart)
		return err
	}
	committed = true
	return nil
}

func (s *ServerService) portableRestoreHooks() panelRestoreHooks {
	var privateCandidate *gorm.DB
	var privateCandidatePath string
	// Capture current listener ports before the global predecessor is closed.
	panelPort, _ := s.xrayService.settingService.GetPort()
	subPort, _ := s.xrayService.settingService.GetSubPort()
	return panelRestoreHooks{
		Running:   s.xrayService.IsXrayRunning,
		Manual:    isManuallyStopped.Load,
		SetManual: isManuallyStopped.Store,
		PreviousConfig: func() *xray.Config {
			if p != nil {
				return p.GetConfig()
			}
			return nil
		},
		Stop: func() error {
			if p != nil && p.IsRunning() {
				return p.Stop()
			}
			return nil
		},
		CloseDB: func() error {
			var privateErr error
			if privateCandidate != nil {
				if handle, err := privateCandidate.DB(); err != nil {
					privateErr = err
				} else {
					privateErr = handle.Close()
				}
				privateCandidate = nil
			}
			return errors.Join(privateErr, database.CloseDB())
		},
		OpenDB: database.InitDB,
		OpenCandidate: func(filename string) error {
			var err error
			privateCandidate, err = database.OpenInitializedDB(filename)
			privateCandidatePath = filename
			return err
		},
		PublishCandidate: func() error {
			// A candidate core may itself occupy a future HTTP listener. Probe
			// again before publication so that failure still rolls back safely.
			if err := validateBackupListeners(privateCandidatePath); err != nil {
				return err
			}
			// Clear predecessor requests before publication. A later accepted
			// mutation may set the flag for the newly published database.
			isNeedXrayRestart.Store(false)
			if err := database.PublishDB(privateCandidate); err != nil {
				return err
			}
			privateCandidate = nil
			return nil
		},
		Checkpoint: func() error {
			if database.GetDB() == nil {
				return errors.New("panel database is unavailable")
			}
			var checkpoint struct{ Busy, Log, Checkpointed int }
			if err := database.GetDB().Raw("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&checkpoint).Error; err != nil {
				return err
			}
			if checkpoint.Busy != 0 {
				return errors.New("panel database checkpoint is busy")
			}
			return nil
		},
		Start: func(next *xray.Config) error {
			if next == nil {
				return errors.New("previous core configuration is unavailable")
			}
			ports := make(map[int]bool)
			for _, inbound := range next.InboundConfigs {
				if inbound.Port > 0 {
					ports[inbound.Port] = true
				}
			}
			if _, port := metricsListen(next.Metrics); port > 0 {
				ports[port] = true
			}
			if panelPort > 0 {
				ports[panelPort] = true
			}
			if subPort > 0 {
				ports[subPort] = true
			}
			syncReservedPorts(ports)
			p = xray.NewProcess(next)
			result = ""
			if err := p.Start(); err != nil {
				return err
			}
			// Start() starts the child; detect immediate bind/initialization exit
			// before discarding the previous database.
			for until := time.Now().Add(time.Second); time.Now().Before(until); {
				if !p.IsRunning() {
					return errors.New("restored core exited during startup")
				}
				time.Sleep(25 * time.Millisecond)
			}
			return nil
		},
		Rename: os.Rename,
	}
}

// ScheduleRestoreReload activates restored HTTP/subscription settings through
// the existing SIGHUP lifecycle while preserving an intentionally stopped core.
func ScheduleRestoreReload(delay time.Duration) error {
	restoreStoppedReload.Store(isManuallyStopped.Load())
	isNeedXrayRestart.Store(false)
	if err := (&PanelService{}).RestartPanel(delay); err != nil {
		restoreStoppedReload.Store(false)
		return err
	}
	return nil
}

func ConsumeRestoreStoppedReload() bool {
	stopped := restoreStoppedReload.Swap(false)
	if stopped {
		isNeedXrayRestart.Store(false)
	}
	return stopped
}
