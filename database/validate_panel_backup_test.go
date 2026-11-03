package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"golang.org/x/crypto/bcrypt"
)

func createPanelValidationFixture(t *testing.T) string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "fixture.db")
	db, err := OpenPanelBackup(filename, false)
	if err != nil {
		t.Fatal(err)
	}
	sql, _ := db.DB()
	defer sql.Close()
	for _, query := range []string{
		`CREATE TABLE users (id integer PRIMARY KEY, username text, password text)`,
		`CREATE TABLE settings (id integer PRIMARY KEY, key text, value text)`,
		`CREATE TABLE inbounds (id integer PRIMARY KEY, user_id integer, enable numeric, listen text, port integer, protocol text, settings text, stream_settings text, tag text, sniffing text)`,
		`INSERT INTO users VALUES(1,'fixture-admin','fixture-password')`,
		`INSERT INTO inbounds VALUES(1,1,1,'127.0.0.1',1443,'anytls','{"clients":[{"password":"fixture","uuidHashMiddle":true}],"clientExport":{"private":"retained"}}','{}','native','{}')`,
	} {
		if err := db.Exec(query).Error; err != nil {
			t.Fatal(err)
		}
	}
	return filename
}

func mutateValidationFixture(t *testing.T, filename, sql string) {
	t.Helper()
	db, err := OpenPanelBackup(filename, false)
	if err != nil {
		t.Fatal(err)
	}
	handle, _ := db.DB()
	defer handle.Close()
	if err := db.Exec(sql).Error; err != nil {
		t.Fatal(err)
	}
}

func TestValidatePanelBackupAcceptsLegacyAndMigratesWithoutGlobalMutation(t *testing.T) {
	filename := createPanelValidationFixture(t)
	globalBefore := GetDB()
	if err := ValidatePanelBackup(filename); err != nil {
		t.Fatal(err)
	}
	if err := MigratePanelBackup(filename); err != nil {
		t.Fatal(err)
	}
	if GetDB() != globalBefore {
		t.Fatal("candidate migration changed the global DB handle")
	}
	db, err := OpenPanelBackup(filename, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, _ := db.DB()
	defer handle.Close()
	var user model.User
	if err := db.First(&user).Error; err != nil {
		t.Fatal(err)
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte("fixture-password")) != nil {
		t.Fatal("legacy admin could not authenticate after migration")
	}
	var inbound model.Inbound
	if err := db.First(&inbound).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inbound.Settings, `"uuidHashMiddle":true`) || !strings.Contains(inbound.Settings, `"private":"retained"`) {
		t.Fatal("native nested settings changed")
	}
	if !db.Migrator().HasColumn(&model.Inbound{}, "all_time") {
		t.Fatal("new schema column was not migrated")
	}
}

func TestValidatePanelBackupRejectsUnrelatedAndActiveSchema(t *testing.T) {
	for name, query := range map[string]string{
		"missing-users":      `DROP TABLE users`,
		"empty-users":        `DELETE FROM users`,
		"blank-user":         `UPDATE users SET username=' '`,
		"blank-password":     `UPDATE users SET password=''`,
		"missing-settings":   `DROP TABLE settings`,
		"missing-column":     `ALTER TABLE inbounds DROP COLUMN protocol`,
		"view":               `CREATE VIEW arbitrary_view AS SELECT * FROM users`,
		"trigger":            `CREATE TRIGGER arbitrary_trigger AFTER UPDATE ON users BEGIN DELETE FROM settings; END`,
		"virtual-table":      `CREATE VIRTUAL TABLE search USING fts3(value)`,
		"duplicate-settings": `INSERT INTO settings(key,value) VALUES('webPort','1'),('webPort','2')`,
	} {
		t.Run(name, func(t *testing.T) {
			filename := createPanelValidationFixture(t)
			mutateValidationFixture(t, filename, query)
			if err := ValidatePanelBackup(filename); err == nil {
				t.Fatal("accepted an invalid panel backup")
			}
		})
	}
}

func TestValidatePanelBackupRejectsCorruptionAndLinks(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "invalid.db")
	if err := os.WriteFile(filename, []byte("SQLite format 3\x00invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePanelBackup(filename); err == nil {
		t.Fatal("accepted corrupt database")
	}
	valid := createPanelValidationFixture(t)
	link := filepath.Join(t.TempDir(), "link.db")
	if err := os.Symlink(valid, link); err == nil {
		if err := ValidatePanelBackup(link); err == nil {
			t.Fatal("accepted database symlink")
		}
	}
}

func TestCandidateMigrationDoesNotRehashExistingBcryptWithoutMarker(t *testing.T) {
	filename := createPanelValidationFixture(t)
	hash, err := bcrypt.GenerateFromPassword([]byte("original"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	db, err := OpenPanelBackup(filename, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&model.User{}).Where("id=1").Update("password", string(hash)).Error; err != nil {
		t.Fatal(err)
	}
	handle, _ := db.DB()
	handle.Close()
	if err := MigratePanelBackup(filename); err != nil {
		t.Fatal(err)
	}
	db, err = OpenPanelBackup(filename, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, _ = db.DB()
	defer handle.Close()
	var row model.User
	if err := db.Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Password != string(hash) {
		t.Fatal("existing bcrypt was rehashed")
	}
}

func TestCandidateMigrationRejectsInvalidPasswordsWithSeederMarker(t *testing.T) {
	for name, password := range map[string]string{
		"plaintext":          "plain-text-password",
		"bad-alphabet":       "$2a$10$" + strings.Repeat("!", 53),
		"noncanonical-salt":  "$2a$10$" + strings.Repeat("A", 53),
		"extra-encoding":     "$2a$10$" + strings.Repeat(".", 54),
		"truncated-encoding": "$2a$10$" + strings.Repeat(".", 52),
	} {
		t.Run(name, func(t *testing.T) {
			filename := createPanelValidationFixture(t)
			db, err := OpenPanelBackup(filename, false)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.AutoMigrate(&model.HistoryOfSeeders{}); err != nil {
				t.Fatal(err)
			}
			if err := db.Create(&model.HistoryOfSeeders{SeederName: "UserPasswordHash"}).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.Model(&model.User{}).Where("id=1").Update("password", password).Error; err != nil {
				t.Fatal(err)
			}
			handle, _ := db.DB()
			handle.Close()
			if err := MigratePanelBackup(filename); err == nil {
				t.Fatal("accepted an unusable migrated admin password")
			}
		})
	}
}
