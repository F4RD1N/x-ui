//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKeepFilesPrivate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XUI_DB_FOLDER", dir)
	t.Setenv("XUI_BIN_FOLDER", dir)
	files := []string{"x-ui.db", "config.json", "config-xray-1.json", "geoip.dat"}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(dir, f), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		os.Chmod(filepath.Join(dir, f), 0o644)
	}
	keepFilesPrivate()
	for _, f := range files {
		fi, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o600)
		if f == "geoip.dat" {
			want = 0o644 // holds no secrets
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v", f, fi.Mode().Perm(), want)
		}
	}
}
