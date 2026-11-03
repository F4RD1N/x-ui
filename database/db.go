// Package database provides database initialization, migration, and management utilities
// for the 3x-ui panel using GORM with SQLite.
package database

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"log"
	"os"
	"path"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/crypto"
	"github.com/mhsanaei/3x-ui/v2/xray"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var currentDB atomic.Pointer[gorm.DB]
var initializationMu sync.Mutex

const (
	defaultUsername = "admin"
	defaultPassword = "admin"
)

func initModels(db *gorm.DB) error {
	models := []any{
		&model.User{},
		&model.Inbound{},
		&model.OutboundTraffics{},
		&model.Setting{},
		&model.InboundClientIps{},
		&xray.ClientTraffic{},
		&model.HistoryOfSeeders{},
		&model.CustomGeoResource{},
	}
	for _, model := range models {
		if err := db.AutoMigrate(model); err != nil {
			log.Printf("Error auto migrating model: %v", err)
			return err
		}
	}
	return nil
}

// initUser creates a default admin user if the users table is empty.
func initUser(db *gorm.DB) error {
	empty, err := isTableEmpty(db, "users")
	if err != nil {
		log.Printf("Error checking if users table is empty: %v", err)
		return err
	}
	if empty {
		hashedPassword, err := crypto.HashPasswordAsBcrypt(defaultPassword)

		if err != nil {
			log.Printf("Error hashing default password: %v", err)
			return err
		}

		user := &model.User{
			Username: defaultUsername,
			Password: hashedPassword,
		}
		return db.Create(user).Error
	}
	return nil
}

// runSeeders migrates user passwords to bcrypt and records seeder execution to prevent re-running.
func runSeeders(db *gorm.DB, isUsersEmpty bool) error {
	empty, err := isTableEmpty(db, "history_of_seeders")
	if err != nil {
		log.Printf("Error checking if users table is empty: %v", err)
		return err
	}

	if empty && isUsersEmpty {
		hashSeeder := &model.HistoryOfSeeders{
			SeederName: "UserPasswordHash",
		}
		return db.Create(hashSeeder).Error
	} else {
		var seedersHistory []string
		db.Model(&model.HistoryOfSeeders{}).Pluck("seeder_name", &seedersHistory)

		if !slices.Contains(seedersHistory, "UserPasswordHash") && !isUsersEmpty {
			var users []model.User
			db.Find(&users)

			for _, user := range users {
				hashedPassword, err := crypto.HashPasswordAsBcrypt(user.Password)
				if err != nil {
					log.Printf("Error hashing password for user '%s': %v", user.Username, err)
					return err
				}
				db.Model(&user).Update("password", hashedPassword)
			}

			hashSeeder := &model.HistoryOfSeeders{
				SeederName: "UserPasswordHash",
			}
			return db.Create(hashSeeder).Error
		}
	}

	return nil
}

// isTableEmpty returns true if the named table contains zero rows.
func isTableEmpty(db *gorm.DB, tableName string) (bool, error) {
	var count int64
	err := db.Table(tableName).Count(&count).Error
	return count == 0, err
}

// InitDB sets up the database connection, migrates models, and runs seeders.
func InitDB(dbPath string) error {
	initializationMu.Lock()
	defer initializationMu.Unlock()
	next, err := OpenInitializedDB(dbPath)
	if err != nil {
		return err
	}
	currentDB.Store(next)
	return nil
}

// OpenInitializedDB runs all initialization against a private handle. It never
// exposes a partially migrated database through GetDB.
func OpenInitializedDB(dbPath string) (_ *gorm.DB, resultErr error) {
	dir := path.Dir(dbPath)
	if err := os.MkdirAll(dir, fs.ModePerm); err != nil {
		return nil, err
	}
	var gormLogger logger.Interface
	if config.IsDebug() {
		gormLogger = logger.Default
	} else {
		gormLogger = logger.Discard
	}
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: gormLogger})
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			if handle, err := db.DB(); err == nil {
				_ = handle.Close()
			}
		}
	}()
	if err := initModels(db); err != nil {
		return nil, err
	}
	isUsersEmpty, err := isTableEmpty(db, "users")
	if err != nil {
		return nil, err
	}
	if err := initUser(db); err != nil {
		return nil, err
	}
	if err := runSeeders(db, isUsersEmpty); err != nil {
		return nil, err
	}
	return db, nil
}

// PublishDB is the final, atomic restore commit. Callers retain responsibility
// for closing the predecessor, so no request can be redirected to a candidate
// which might later be rolled back.
func PublishDB(next *gorm.DB) error {
	if next == nil {
		return errors.New("cannot publish a nil panel database")
	}
	initializationMu.Lock()
	defer initializationMu.Unlock()
	currentDB.Store(next)
	return nil
}

// CloseDB closes the database connection if it exists.
func CloseDB() error {
	db := GetDB()
	if db != nil {
		sqlDB, err := db.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}

// GetDB returns the global GORM database instance.
func GetDB() *gorm.DB {
	return currentDB.Load()
}

func IsNotFound(err error) bool {
	return errors.Is(err, gorm.ErrRecordNotFound)
}

// IsSQLiteDB checks if the given file is a valid SQLite database by reading its signature.
func IsSQLiteDB(file io.ReaderAt) (bool, error) {
	signature := []byte("SQLite format 3\x00")
	buf := make([]byte, len(signature))
	_, err := file.ReadAt(buf, 0)
	if err != nil {
		return false, err
	}
	return bytes.Equal(buf, signature), nil
}

// Checkpoint performs a WAL checkpoint on the SQLite database to ensure data consistency.
func Checkpoint() error {
	db := GetDB()
	if db == nil {
		return errors.New("panel database is unavailable")
	}
	// Update WAL
	err := db.Exec("PRAGMA wal_checkpoint;").Error
	if err != nil {
		return err
	}
	return nil
}

// ValidateSQLiteDB opens the provided sqlite DB path with a throw-away connection
// and runs a PRAGMA integrity_check to ensure the file is structurally sound.
// It does not mutate global state or run migrations.
func ValidateSQLiteDB(dbPath string) error {
	if _, err := os.Stat(dbPath); err != nil { // file must exist
		return err
	}
	gdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		return err
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		return err
	}
	defer sqlDB.Close()
	var res string
	if err := gdb.Raw("PRAGMA integrity_check;").Scan(&res).Error; err != nil {
		return err
	}
	if res != "ok" {
		return errors.New("sqlite integrity check failed: " + res)
	}
	return nil
}
