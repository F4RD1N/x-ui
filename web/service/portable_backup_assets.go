package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	portable "github.com/mhsanaei/3x-ui/v2/util/backup"
	"gorm.io/gorm"
)

// snapshotPanelDatabase obtains one consistent SQLite snapshot, including WAL
// transactions. A checkpoint followed by reading the live file is not atomic.
func snapshotPanelDatabase(db *gorm.DB, directory string) (filename string, cleanup func(), err error) {
	if db == nil {
		return "", nil, errors.New("panel database is unavailable")
	}
	dir, err := os.MkdirTemp(directory, ".xui-backup-")
	if err != nil {
		return "", nil, err
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	filename = filepath.Join(dir, "database.db")
	if err = db.Exec("VACUUM INTO ?", filename).Error; err != nil {
		cleanup()
		return "", nil, fmt.Errorf("cannot snapshot panel database: %w", err)
	}
	if err = os.Chmod(filename, 0600); err != nil {
		cleanup()
		return "", nil, err
	}
	return filename, cleanup, nil
}

func readBoundedBackupFile(filename string, limit int64) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("backup file exceeds its size limit")
	}
	return data, nil
}

func withBackupDB(filename string, readOnly bool, action func(*gorm.DB) error) error {
	db, err := database.OpenPanelBackup(filename, readOnly)
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	return action(db)
}

// rewriteBackupReferences deliberately recognizes only supported file-bearing
// settings. Ordinary strings, inline PEM, URLs and manifest paths never become
// filesystem write destinations. Numbers retain their original JSON precision.
func rewriteBackupReferences(input, protocol string, replace func(string) (string, error)) (string, bool, error) {
	if strings.TrimSpace(input) == "" {
		return input, false, nil
	}
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return "", false, errors.New("backup contains malformed protocol JSON")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return "", false, errors.New("backup contains trailing protocol JSON")
	}
	changed := false
	fileRef := func(object map[string]any, key string) error {
		value, exists := object[key]
		if !exists || value == nil {
			return nil
		}
		ref, ok := value.(string)
		if !ok {
			return errors.New("backup file reference must be a string")
		}
		if ref == "" {
			return nil
		}
		if strings.ContainsAny(ref, "\x00\r\n") {
			return errors.New("backup contains an invalid file reference")
		}
		rewritten, err := replace(ref)
		if err != nil {
			return err
		}
		if rewritten != ref {
			object[key] = rewritten
			changed = true
		}
		return nil
	}
	var walk func(any, bool) error
	walk = func(value any, openvpn bool) error {
		switch item := value.(type) {
		case []any:
			for _, child := range item {
				if err := walk(child, openvpn); err != nil {
					return err
				}
			}
		case map[string]any:
			if p, ok := item["protocol"].(string); ok {
				openvpn = p == "openvpn" || p == "ov"
			}
			if tls, ok := item["tlsSettings"].(map[string]any); ok {
				if certificates, ok := tls["certificates"].([]any); ok {
					for _, certificate := range certificates {
						if object, ok := certificate.(map[string]any); ok {
							for _, key := range []string{"certificateFile", "keyFile"} {
								if err := fileRef(object, key); err != nil {
									return err
								}
							}
						}
					}
				}
			}
			if openvpn {
				if proof, ok := item["clientProof"].(map[string]any); ok {
					if err := fileRef(proof, "keyFile"); err != nil {
						return err
					}
				}
			}
			for _, child := range item {
				if err := walk(child, openvpn); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(value, protocol == "openvpn" || protocol == "ov"); err != nil {
		return "", false, err
	}
	if !changed {
		return input, false, nil
	}
	output, err := json.Marshal(value)
	return string(output), true, err
}

// visitPanelBackupReferences uses one private DB handle so all references come
// from the same snapshot. Mutations are limited to explicitly recognized paths.
func visitPanelBackupReferences(db *gorm.DB, replace func(string) (string, error)) error {
	var inbounds []model.Inbound
	if err := db.Find(&inbounds).Error; err != nil {
		return err
	}
	for _, inbound := range inbounds {
		updates := make(map[string]any)
		for field, original := range map[string]string{"settings": inbound.Settings, "stream_settings": inbound.StreamSettings} {
			value, changed, err := rewriteBackupReferences(original, string(inbound.Protocol), replace)
			if err != nil {
				return err
			}
			if changed {
				updates[field] = value
			}
		}
		if len(updates) > 0 {
			if err := db.Model(&model.Inbound{}).Where("id = ?", inbound.Id).Updates(updates).Error; err != nil {
				return err
			}
		}
	}
	var settings []model.Setting
	if err := db.Find(&settings).Error; err != nil {
		return err
	}
	for _, setting := range settings {
		value, changed := setting.Value, false
		var err error
		switch setting.Key {
		case "webCertFile", "webKeyFile", "subCertFile", "subKeyFile":
			if value != "" {
				value, err = replace(value)
				changed = value != setting.Value
			}
		case "xrayTemplateConfig":
			value, changed, err = rewriteBackupReferences(value, "", replace)
		}
		if err != nil {
			return err
		}
		if changed {
			if err := db.Model(&model.Setting{}).Where("id = ?", setting.Id).Update("value", value).Error; err != nil {
				return err
			}
		}
	}
	return nil
}

func panelBackupReferences(filename string) ([]string, error) {
	refs := make(map[string]bool)
	err := withBackupDB(filename, true, func(db *gorm.DB) error {
		return visitPanelBackupReferences(db, func(ref string) (string, error) {
			if strings.ContainsAny(ref, "\x00\r\n") {
				return "", errors.New("backup contains an invalid file reference")
			}
			refs[ref] = true
			if len(refs) > portable.MaxAssets {
				return "", errors.New("too many backup file references")
			}
			return ref, nil
		})
	})
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(refs))
	for ref := range refs {
		result = append(result, ref)
	}
	sort.Strings(result)
	return result, nil
}

// installBackupAssets writes only into a fresh private managed directory. The
// source reference is an opaque lookup key; even absolute/traversal references
// cannot choose an extraction path. The caller retains this directory on commit.
func installBackupAssets(filename, parent string, assets []portable.Asset) (string, error) {
	refs, err := panelBackupReferences(filename)
	if err != nil {
		return "", err
	}
	if len(refs) != len(assets) {
		return "", errors.New("backup asset references are missing or unreferenced")
	}
	byReference := make(map[string]portable.Asset, len(assets))
	for _, asset := range assets {
		if _, duplicate := byReference[asset.Reference]; duplicate {
			return "", errors.New("duplicate backup asset reference")
		}
		byReference[asset.Reference] = asset
	}
	for _, ref := range refs {
		if _, exists := byReference[ref]; !exists {
			return "", errors.New("backup is missing a referenced asset")
		}
	}
	if len(refs) == 0 {
		return "", nil
	}
	dir, err := os.MkdirTemp(parent, ".xui-restored-assets-")
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(dir)
		}
	}()
	rewrites := make(map[string]string, len(refs))
	for index, ref := range refs {
		destination := filepath.Join(dir, fmt.Sprintf("asset-%03d.pem", index))
		if err = os.WriteFile(destination, byReference[ref].Data, 0600); err != nil {
			return "", err
		}
		rewrites[ref] = destination
	}
	err = withBackupDB(filename, false, func(db *gorm.DB) error {
		return db.Transaction(func(tx *gorm.DB) error {
			return visitPanelBackupReferences(tx, func(ref string) (string, error) {
				path, ok := rewrites[ref]
				if !ok {
					return "", errors.New("backup reference changed during restore")
				}
				return path, nil
			})
		})
	})
	if err != nil {
		return "", err
	}
	keep = true
	return dir, nil
}

func portableBackupFromSnapshot(filename string) ([]byte, error) {
	data, err := readBoundedBackupFile(filename, portable.MaxDatabase)
	if err != nil {
		return nil, err
	}
	refs, err := panelBackupReferences(filename)
	if err != nil {
		return nil, err
	}
	return portable.Encode(data, refs)
}

func isSQLiteBackup(data []byte) bool { return bytes.HasPrefix(data, []byte("SQLite format 3\x00")) }
