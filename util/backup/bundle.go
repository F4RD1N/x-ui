// Package backup implements bounded, portable panel backups. Paths in the
// manifest are reference identifiers only: extraction never writes to them.
package backup

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

const (
	MaxDatabase = 128 << 20
	MaxAsset    = 4 << 20
	MaxAssets   = 256
	MaxTotal    = 192 << 20
)

type Asset struct {
	Reference string `json:"reference"`
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Data      []byte `json:"-"`
}
type Manifest struct {
	Format         string  `json:"format"`
	Version        int     `json:"version"`
	DatabaseSHA256 string  `json:"databaseSha256"`
	Assets         []Asset `json:"assets"`
}
type Bundle struct {
	Database []byte
	Assets   []Asset
}

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// ReadAsset snapshots an explicitly configured file, including a certificate
// manager's symlink. Only regular target bytes enter the archive. Restore never
// follows manifest references or materializes archive symlinks.
func ReadAsset(path string) ([]byte, error) {
	before, err := os.Stat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > MaxAsset {
		return nil, errors.New("backup asset must be a readable regular file within the size limit")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open backup asset")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("backup asset changed during snapshot")
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxAsset+1))
	if err != nil || len(b) > MaxAsset {
		return nil, errors.New("cannot read backup asset within size limit")
	}
	final, err := f.Stat()
	if err != nil || final.Size() != after.Size() || !final.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("backup asset changed during snapshot")
	}
	return b, nil
}

func Encode(database []byte, references []string) ([]byte, error) {
	if len(database) == 0 || len(database) > MaxDatabase {
		return nil, errors.New("backup database exceeds size limit")
	}
	refs := append([]string(nil), references...)
	sort.Strings(refs)
	manifest := Manifest{Format: "x-ui-portable-backup", Version: 1, DatabaseSHA256: digest(database), Assets: []Asset{}}
	seen := make(map[string]bool)
	total := len(database)
	for _, ref := range refs {
		if seen[ref] {
			continue
		}
		if ref == "" || strings.ContainsAny(ref, "\x00\r\n") {
			return nil, errors.New("invalid backup asset reference")
		}
		seen[ref] = true
		if len(seen) > MaxAssets {
			return nil, errors.New("too many backup assets")
		}
		data, err := ReadAsset(ref)
		if err != nil {
			return nil, err
		}
		total += len(data)
		if total > MaxTotal {
			return nil, errors.New("backup exceeds total size limit")
		}
		manifest.Assets = append(manifest.Assets, Asset{Reference: ref, Name: fmt.Sprintf("assets/%03d.bin", len(manifest.Assets)), SHA256: digest(data), Size: int64(len(data)), Data: data})
	}
	var buffer bytes.Buffer
	w := zip.NewWriter(&buffer)
	write := func(name string, data []byte) error {
		h := &zip.FileHeader{Name: name, Method: zip.Deflate}
		h.SetMode(0600)
		f, err := w.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = f.Write(data)
		return err
	}
	meta, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	if err = write("manifest.json", meta); err != nil {
		return nil, err
	}
	if err = write("database.db", database); err != nil {
		return nil, err
	}
	for _, asset := range manifest.Assets {
		if err = write(asset.Name, asset.Data); err != nil {
			return nil, err
		}
	}
	if err = w.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// Decode checks every member before returning any bytes to the restore layer.
// It rejects extras, duplicates, links, traversal, truncation, and zip bombs.
func Decode(reader io.ReaderAt, size int64) (*Bundle, error) {
	if size <= 0 || size > MaxTotal {
		return nil, errors.New("backup upload exceeds size limit")
	}
	z, err := zip.NewReader(reader, size)
	if err != nil {
		return nil, errors.New("invalid backup archive")
	}
	if len(z.File) < 2 || len(z.File) > MaxAssets+2 {
		return nil, errors.New("invalid backup member count")
	}
	files := make(map[string]*zip.File)
	var expanded uint64
	for _, f := range z.File {
		if files[f.Name] != nil || !f.Mode().IsRegular() {
			return nil, errors.New("backup contains duplicate or non-regular member")
		}
		expanded += f.UncompressedSize64
		if f.UncompressedSize64 > MaxDatabase || expanded > MaxTotal {
			return nil, errors.New("expanded backup exceeds size limit")
		}
		files[f.Name] = f
	}
	read := func(name string, limit int64) ([]byte, error) {
		f := files[name]
		if f == nil || f.UncompressedSize64 > uint64(limit) {
			return nil, errors.New("backup member missing or too large")
		}
		r, err := f.Open()
		if err != nil {
			return nil, errors.New("cannot read backup member")
		}
		defer r.Close()
		b, err := io.ReadAll(io.LimitReader(r, limit+1))
		if err != nil || int64(len(b)) > limit || uint64(len(b)) != f.UncompressedSize64 {
			return nil, errors.New("invalid backup member data")
		}
		return b, nil
	}
	meta, err := read("manifest.json", 256<<10)
	if err != nil {
		return nil, err
	}
	var manifest Manifest
	d := json.NewDecoder(bytes.NewReader(meta))
	d.DisallowUnknownFields()
	if d.Decode(&manifest) != nil || manifest.Format != "x-ui-portable-backup" || manifest.Version != 1 || len(manifest.Assets) > MaxAssets {
		return nil, errors.New("unsupported backup manifest")
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid backup manifest trailing data")
	}
	if len(files) != len(manifest.Assets)+2 {
		return nil, errors.New("backup contains unlisted members")
	}
	db, err := read("database.db", MaxDatabase)
	if err != nil || digest(db) != manifest.DatabaseSHA256 {
		return nil, errors.New("backup database integrity mismatch")
	}
	names, refs := make(map[string]bool), make(map[string]bool)
	for i := range manifest.Assets {
		a := &manifest.Assets[i]
		if a.Name != fmt.Sprintf("assets/%03d.bin", i) || names[a.Name] || a.Reference == "" || refs[a.Reference] || strings.ContainsAny(a.Reference, "\x00\r\n") || a.Size < 0 || a.Size > MaxAsset {
			return nil, errors.New("invalid backup asset manifest")
		}
		names[a.Name], refs[a.Reference] = true, true
		a.Data, err = read(a.Name, MaxAsset)
		if err != nil || int64(len(a.Data)) != a.Size || digest(a.Data) != a.SHA256 {
			return nil, errors.New("backup asset integrity mismatch")
		}
	}
	return &Bundle{Database: db, Assets: manifest.Assets}, nil
}
