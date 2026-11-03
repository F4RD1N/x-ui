package backup

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPortableBundleRoundTrip(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "private.pem")
	if err := os.WriteFile(key, []byte("private fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	db := []byte("SQLite format 3\x00fixture")
	b, err := Encode(db, []string{key, key})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Database, db) || len(got.Assets) != 1 || got.Assets[0].Reference != key || string(got.Assets[0].Data) != "private fixture" {
		t.Fatal("backup did not preserve database and asset")
	}
	if _, err := os.Stat(filepath.Join(dir, "assets")); !os.IsNotExist(err) {
		t.Fatal("decoder wrote an asset")
	}
}

func TestBundleSnapshotsConfiguredCertificateSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	os.WriteFile(target, []byte("secret"), 0600)
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	data, err := Encode([]byte("db"), []string{link})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(got.Assets) != 1 || got.Assets[0].Reference != link || string(got.Assets[0].Data) != "secret" {
		t.Fatal("configured certificate symlink did not become regular backup bytes")
	}
	for _, p := range []string{filepath.Join(dir, "missing"), dir} {
		if _, err := Encode([]byte("db"), []string{p}); err == nil {
			t.Fatal("accepted unsafe asset")
		}
	}
}

func TestBundleRejectsArchiveSymlink(t *testing.T) {
	base, err := Encode([]byte("db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(base), int64(len(base)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	for _, source := range reader.File {
		r, err := source.Open()
		if err != nil {
			t.Fatal(err)
		}
		var body bytes.Buffer
		body.ReadFrom(r)
		r.Close()
		h := source.FileHeader
		if h.Name == "database.db" {
			h.SetMode(os.ModeSymlink | 0777)
		}
		entry, err := w.CreateHeader(&h)
		if err != nil {
			t.Fatal(err)
		}
		entry.Write(body.Bytes())
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(bytes.NewReader(out.Bytes()), int64(out.Len())); err == nil {
		t.Fatal("archive symlink accepted")
	}
}

func TestBundleRejectsMalformedArchives(t *testing.T) {
	base, _ := Encode([]byte("database"), nil)
	mutate := func(change func(map[string][]byte) []string) []byte {
		r, _ := zip.NewReader(bytes.NewReader(base), int64(len(base)))
		m := make(map[string][]byte)
		for _, f := range r.File {
			rc, _ := f.Open()
			var b bytes.Buffer
			b.ReadFrom(rc)
			rc.Close()
			m[f.Name] = b.Bytes()
		}
		names := change(m)
		if names == nil {
			for n := range m {
				names = append(names, n)
			}
		}
		var out bytes.Buffer
		w := zip.NewWriter(&out)
		for _, n := range names {
			f, _ := w.Create(n)
			f.Write(m[n])
		}
		w.Close()
		return out.Bytes()
	}
	tests := map[string][]byte{
		"traversal": mutate(func(m map[string][]byte) []string { m["../escape"] = []byte("bad"); return nil }),
		"absolute":  mutate(func(m map[string][]byte) []string { m["/etc/x-ui/key"] = []byte("bad"); return nil }),
		"duplicate": mutate(func(m map[string][]byte) []string { return []string{"manifest.json", "database.db", "database.db"} }),
		"corrupt":   mutate(func(m map[string][]byte) []string { m["database.db"] = []byte("tampered"); return nil }),
		"missing":   mutate(func(m map[string][]byte) []string { delete(m, "database.db"); return nil }),
		"version": mutate(func(m map[string][]byte) []string {
			var v Manifest
			json.Unmarshal(m["manifest.json"], &v)
			v.Version = 2
			m["manifest.json"], _ = json.Marshal(v)
			return nil
		}),
		"trailing": mutate(func(m map[string][]byte) []string {
			m["manifest.json"] = append(m["manifest.json"], []byte("{}")...)
			return nil
		}),
		"truncated": base[:len(base)-9],
	}
	for name, b := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(bytes.NewReader(b), int64(len(b))); err == nil {
				t.Fatal("accepted malformed archive")
			}
		})
	}
}

func TestBundleBounds(t *testing.T) {
	if _, err := Decode(bytes.NewReader(nil), MaxTotal+1); err == nil {
		t.Fatal("accepted oversized upload")
	}
	if _, err := Encode(nil, nil); err == nil {
		t.Fatal("accepted empty database")
	}
}
