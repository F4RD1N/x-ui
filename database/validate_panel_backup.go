package database

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
	"github.com/mhsanaei/3x-ui/v2/xray"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// OpenPanelBackup opens an isolated database, never replacing the global panel
// handle. Read-only candidates cannot create sidecars or execute schema code.
func OpenPanelBackup(filename string, readOnly bool) (*gorm.DB, error) {
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: absolute}
	q := url.Values{"_busy_timeout": {"5000"}}
	if readOnly {
		q.Set("mode", "ro")
		q.Set("immutable", "1")
	}
	u.RawQuery = q.Encode()
	db, err := gorm.Open(sqlite.Open(u.String()), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return nil, errors.New("cannot open backup database")
	}
	if err = db.Exec("PRAGMA trusted_schema=OFF").Error; err != nil {
		if sqlDB, e := db.DB(); e == nil {
			_ = sqlDB.Close()
		}
		return nil, err
	}
	return db, nil
}

// ValidatePanelBackup rejects unrelated SQLite files and active schema objects
// before any migrations or runtime shutdown. Old tables may lack columns added
// by later releases; the required columns are the original panel contract.
func ValidatePanelBackup(filename string) error {
	info, err := os.Lstat(filename)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("backup database must be a regular file")
	}
	db, err := OpenPanelBackup(filename, true)
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	var integrity []struct {
		IntegrityCheck string `gorm:"column:integrity_check"`
	}
	if err = db.Raw("PRAGMA integrity_check").Scan(&integrity).Error; err != nil || len(integrity) != 1 || integrity[0].IntegrityCheck != "ok" {
		return errors.New("backup database failed its integrity check")
	}
	var schema []struct{ Type, Name, SQL string }
	if err = db.Raw("SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").Scan(&schema).Error; err != nil {
		return err
	}
	tables := make(map[string]bool)
	for _, entry := range schema {
		if entry.Type == "trigger" || entry.Type == "view" || regexp.MustCompile(`(?is)^\s*CREATE\s+VIRTUAL\s+TABLE\b`).MatchString(entry.SQL) {
			return errors.New("backup contains unsupported active schema objects")
		}
		if entry.Type == "table" {
			tables[entry.Name] = true
		}
	}
	for table, required := range map[string][]string{
		"users":    {"id", "username", "password"},
		"settings": {"id", "key", "value"},
		"inbounds": {"id", "user_id", "enable", "listen", "port", "protocol", "settings", "stream_settings", "tag", "sniffing"},
	} {
		if !tables[table] {
			return fmt.Errorf("backup is missing panel table %s", table)
		}
		var columns []struct{ Name string }
		if err = db.Raw("PRAGMA table_info(" + table + ")").Scan(&columns).Error; err != nil {
			return err
		}
		found := make(map[string]bool)
		for _, column := range columns {
			found[column.Name] = true
		}
		for _, column := range required {
			if !found[column] {
				return fmt.Errorf("backup panel table %s is missing a required column", table)
			}
		}
	}
	var users, invalid int64
	if err = db.Table("users").Count(&users).Error; err != nil {
		return err
	}
	if err = db.Table("users").Where("username IS NULL OR password IS NULL OR trim(username) = '' OR length(password) = 0").Count(&invalid).Error; err != nil {
		return err
	}
	if users == 0 || invalid != 0 {
		return errors.New("backup must contain usable panel user accounts")
	}
	var duplicates int64
	if err = db.Raw("SELECT count(*) FROM (SELECT key FROM settings GROUP BY key HAVING count(*) > 1)").Scan(&duplicates).Error; err != nil {
		return err
	}
	if duplicates != 0 {
		return errors.New("backup contains duplicate setting keys")
	}
	return nil
}

// MigratePanelBackup performs schema/password migrations against a private
// candidate. It returns every failure and never creates a default admin user.
func MigratePanelBackup(filename string) error {
	if err := ValidatePanelBackup(filename); err != nil {
		return err
	}
	db, err := OpenPanelBackup(filename, false)
	if err != nil {
		return err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	for _, item := range []any{&model.User{}, &model.Inbound{}, &model.OutboundTraffics{}, &model.Setting{}, &model.InboundClientIps{}, &xray.ClientTraffic{}, &model.HistoryOfSeeders{}, &model.CustomGeoResource{}} {
		if err = db.AutoMigrate(item); err != nil {
			return fmt.Errorf("cannot migrate candidate panel schema: %w", err)
		}
	}
	if err = db.Transaction(func(tx *gorm.DB) error {
		var marker int64
		if err := tx.Model(&model.HistoryOfSeeders{}).Where("seeder_name = ?", "UserPasswordHash").Count(&marker).Error; err != nil {
			return err
		}
		var users []model.User
		if err := tx.Find(&users).Error; err != nil {
			return err
		}
		for _, user := range users {
			if marker != 0 {
				if !validBackupBcrypt(user.Password) {
					return errors.New("backup contains an invalid migrated account password")
				}
				continue
			}
			// An old backup with a missing seeder record may already hold bcrypt.
			// Never hash that hash again and lock its administrator out.
			if validBackupBcrypt(user.Password) {
				continue
			}
			hash, err := crypto.HashPasswordAsBcrypt(user.Password)
			if err != nil {
				return err
			}
			if err = tx.Model(&model.User{}).Where("id = ?", user.Id).Update("password", hash).Error; err != nil {
				return err
			}
		}
		if marker != 0 {
			return nil
		}
		return tx.Create(&model.HistoryOfSeeders{SeederName: "UserPasswordHash"}).Error
	}); err != nil {
		return fmt.Errorf("cannot migrate candidate panel users: %w", err)
	}
	// A candidate is a self-contained file before it is renamed into place.
	return db.Exec("PRAGMA journal_mode=DELETE").Error
}

var backupBcryptPattern = regexp.MustCompile(`^\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)

func validBackupBcrypt(password string) bool {
	if !backupBcryptPattern.MatchString(password) {
		return false
	}
	if _, err := bcrypt.Cost([]byte(password)); err != nil {
		return false
	}
	encoded := password[len(password)-53:]
	alphabet := base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").WithPadding(base64.NoPadding).Strict()
	salt, saltErr := alphabet.DecodeString(encoded[:22])
	hash, hashErr := alphabet.DecodeString(encoded[22:])
	return saltErr == nil && hashErr == nil && len(salt) == 16 && len(hash) == 23
}
