package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/config"
	"github.com/mhsanaei/3x-ui/v2/logger"
)

// Certificate fields accept a URL as well as a path. Saving one downloads the
// file and stores the local path in its place, so a certificate can be handed
// to the panel by link instead of being copied onto the server first.
//
// Downloads land next to the database rather than under /usr/local/x-ui, which
// the installer wipes on every upgrade.

// maxCertSize bounds a download. Certificates and keys are a few kilobytes; a
// larger response is a redirect to something else, not a certificate.
const maxCertSize = 4 << 20

// certStorageDir is where downloaded certificates are kept.
func certStorageDir() string {
	return filepath.Join(config.GetDBFolderPath(), "certs")
}

// IsCertURL reports whether a certificate field holds a URL to fetch rather
// than a path on this server.
func IsCertURL(value string) bool {
	v := strings.TrimSpace(value)
	return strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://")
}

// localCertPath is the file a URL is stored as. The name keeps the URL's own
// basename so the file is recognisable, and carries a hash of the full URL so
// that two certificates with the same basename cannot overwrite each other and
// so that re-saving the same URL replaces its file instead of accumulating.
func localCertPath(rawURL string) string {
	sum := sha256.Sum256([]byte(rawURL))
	base := path.Base(strings.SplitN(strings.TrimSpace(rawURL), "?", 2)[0])
	base = strings.TrimSuffix(base, "/")
	if base == "" || base == "." || base == "/" {
		base = "cert"
	}
	ext := path.Ext(base)
	name := strings.TrimSuffix(base, ext)
	if ext == "" {
		ext = ".pem"
	}
	return filepath.Join(certStorageDir(), fmt.Sprintf("%s-%s%s", name, hex.EncodeToString(sum[:4]), ext))
}

// DownloadCert fetches a certificate or key and returns the path it was saved
// to. A value that is not a URL is returned unchanged, so this is safe to call
// on every certificate field whether or not the user used a link.
func DownloadCert(value string) (string, error) {
	if !IsCertURL(value) {
		return value, nil
	}
	rawURL := strings.TrimSpace(value)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return "", fmt.Errorf("downloading %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("downloading %s: server answered %s", rawURL, resp.Status)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCertSize))
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", rawURL, err)
	}
	if len(body) == 0 {
		return "", fmt.Errorf("downloading %s: the file is empty", rawURL)
	}

	if err := os.MkdirAll(certStorageDir(), 0o700); err != nil {
		return "", fmt.Errorf("creating the certificate folder: %w", err)
	}

	dest := localCertPath(rawURL)
	// Written through a temporary file so that a failed write cannot leave a
	// half-written certificate where a working one used to be.
	tmp := dest + ".tmp"
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		return "", fmt.Errorf("saving %s: %w", dest, err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return "", fmt.Errorf("saving %s: %w", dest, err)
	}

	logger.Info("Downloaded certificate ", rawURL, " to ", dest)
	return dest, nil
}

// MaterializeStreamCerts rewrites a stream settings document, replacing any
// certificate or key given as a URL with the path it was downloaded to. The
// document is returned unchanged when it holds no certificate URLs, so an
// inbound that was saved with plain paths keeps byte-identical settings.
func MaterializeStreamCerts(streamSettings string) (string, error) {
	if streamSettings == "" || !strings.Contains(streamSettings, "http") {
		return streamSettings, nil
	}

	var doc map[string]any
	if err := json.Unmarshal([]byte(streamSettings), &doc); err != nil {
		// Not our business to reject it here; the config parser will.
		return streamSettings, nil
	}

	changed := false
	// Both TLS and REALITY carry a "certificates" array of the same shape.
	for _, key := range []string{"tlsSettings", "realitySettings", "xtlsSettings"} {
		section, ok := doc[key].(map[string]any)
		if !ok {
			continue
		}
		certs, ok := section["certificates"].([]any)
		if !ok {
			continue
		}
		for _, entry := range certs {
			cert, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			for _, field := range []string{"certificateFile", "keyFile"} {
				value, ok := cert[field].(string)
				if !ok || !IsCertURL(value) {
					continue
				}
				local, err := DownloadCert(value)
				if err != nil {
					return "", err
				}
				cert[field] = local
				changed = true
			}
		}
	}

	if !changed {
		return streamSettings, nil
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	return string(out), nil
}
