package main

import (
	"os"
	"path/filepath"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// keepFilesPrivate makes what the panel and its cores write readable by
// root only -- the database and the cores' configs hold every client's
// credentials and the inbounds' private keys -- and takes the other users'
// access away from such files an older version left readable.
func keepFilesPrivate() {
	setPrivateUmask()
	paths := []string{config.GetDBPath(), xray.GetConfigPath()}
	if m, err := filepath.Glob(filepath.Join(config.GetBinFolderPath(), "config-*.json")); err == nil {
		paths = append(paths, m...)
	}
	for _, p := range paths {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o077 != 0 {
			os.Chmod(p, fi.Mode().Perm()&^0o077)
		}
	}
}
