package service

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xtls/xray-core/app/router"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// normalizeWhole is the previous implementation: the whole list in memory.
// The streaming one must give the same list.
func normalizeWhole(t *testing.T, data []byte) *router.GeoSiteList {
	t.Helper()
	var list router.GeoSiteList
	if err := proto.Unmarshal(data, &list); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, e := range list.Entry {
		e.CountryCode = strings.ToUpper(e.CountryCode)
	}
	return &list
}

func writeTemp(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "geosite.dat")
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func sampleList() *router.GeoSiteList {
	return &router.GeoSiteList{Entry: []*router.GeoSite{
		{CountryCode: "cn", Domain: []*router.Domain{{Type: router.Domain_Domain, Value: "baidu.com"}, {Type: router.Domain_Full, Value: "a.b.cn"}}},
		{CountryCode: "GOOGLE", Domain: []*router.Domain{{Type: router.Domain_Plain, Value: "google"}}},
		{CountryCode: "category-ads-all", Domain: []*router.Domain{{Type: router.Domain_Regex, Value: "^ads?\\."}}},
		{CountryCode: "Mixed-Case_1", Domain: nil},
		{CountryCode: "", Domain: []*router.Domain{{Value: "empty.code"}}},
	}}
}

func TestNormalizeGeositeMatchesWholeList(t *testing.T) {
	data, err := proto.Marshal(sampleList())
	if err != nil {
		t.Fatal(err)
	}
	p := writeTemp(t, data)
	if err := NormalizeGeositeCountryCodes(p); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if len(got) != len(data) {
		t.Fatalf("size changed: %d -> %d", len(data), len(got))
	}
	var list router.GeoSiteList
	if err := proto.Unmarshal(got, &list); err != nil {
		t.Fatalf("result does not parse: %v", err)
	}
	if want := normalizeWhole(t, data); !proto.Equal(&list, want) {
		t.Fatalf("got %v\nwant %v", &list, want)
	}
	for _, e := range list.Entry {
		if e.CountryCode != strings.ToUpper(e.CountryCode) {
			t.Fatalf("code %q not uppercased", e.CountryCode)
		}
	}
}

func TestNormalizeGeositeAlreadyUpperIsUntouched(t *testing.T) {
	l := sampleList()
	for _, e := range l.Entry {
		e.CountryCode = strings.ToUpper(e.CountryCode)
	}
	data, _ := proto.Marshal(l)
	p := writeTemp(t, data)
	old, _ := os.Stat(p)
	if err := NormalizeGeositeCountryCodes(p); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	now, _ := os.Stat(p)
	if !bytes.Equal(got, data) || !now.ModTime().Equal(old.ModTime()) {
		t.Fatal("an already normalized file was written")
	}
}

// Fields the panel does not know (a newer geosite format, other tools'
// additions) are kept byte for byte; only the codes change.
func TestNormalizeGeositeKeepsUnknownFields(t *testing.T) {
	var entry []byte
	entry = protowire.AppendTag(entry, 3, protowire.BytesType)
	entry = protowire.AppendBytes(entry, []byte("resource-hash"))
	entry = protowire.AppendTag(entry, 1, protowire.BytesType)
	entry = protowire.AppendString(entry, "ir")
	entry = protowire.AppendTag(entry, 5, protowire.VarintType)
	entry = protowire.AppendVarint(entry, 300)
	entry = protowire.AppendTag(entry, 6, protowire.Fixed32Type)
	entry = protowire.AppendFixed32(entry, 7)
	entry = protowire.AppendTag(entry, 7, protowire.Fixed64Type)
	entry = protowire.AppendFixed64(entry, 9)
	var data []byte
	data = protowire.AppendTag(data, 9, protowire.VarintType) // a top-level field that is not an entry
	data = protowire.AppendVarint(data, 1)
	data = protowire.AppendTag(data, 1, protowire.BytesType)
	data = protowire.AppendBytes(data, entry)
	want := bytes.Replace(data, []byte("ir"), []byte("IR"), 1)

	p := writeTemp(t, data)
	if err := NormalizeGeositeCountryCodes(p); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x\nwant %x", got, want)
	}
}

// A damaged file is reported and not written at all, even where its start
// could have been patched.
func TestNormalizeGeositeDamagedFileIsLeftAlone(t *testing.T) {
	data, _ := proto.Marshal(sampleList())
	for _, cut := range []int{len(data) - 1, len(data) - 3, 5, 1} {
		p := writeTemp(t, data[:cut])
		if err := NormalizeGeositeCountryCodes(p); err == nil {
			t.Fatalf("cut at %d: no error", cut)
		}
		got, _ := os.ReadFile(p)
		if !bytes.Equal(got, data[:cut]) {
			t.Fatalf("cut at %d: the file was changed", cut)
		}
	}
	p := writeTemp(t, []byte("<html>not a geosite file</html>"))
	if err := NormalizeGeositeCountryCodes(p); err == nil {
		t.Fatal("an HTML page parsed as a geosite file")
	}
}

func TestNormalizeGeositeEmptyFile(t *testing.T) {
	p := writeTemp(t, nil)
	if err := NormalizeGeositeCountryCodes(p); err != nil {
		t.Fatalf("empty file: %v", err)
	}
}

// GEOSITE_DIR=<dir with real geosite*.dat files>: each one gives the same
// list as the whole-list normalization, and the streaming one allocates a
// small fraction of the file's size.
func TestNormalizeGeositeRealFiles(t *testing.T) {
	dir := os.Getenv("GEOSITE_DIR")
	if dir == "" {
		t.Skip("GEOSITE_DIR not set")
	}
	files, _ := filepath.Glob(filepath.Join(dir, "geosite*.dat"))
	if len(files) == 0 {
		t.Skip("no geosite*.dat in GEOSITE_DIR")
	}
	for _, src := range files {
		orig, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		// as published, and with every code lowercased (files that went
		// through the old normalization are uppercase already)
		var low router.GeoSiteList
		if err := proto.Unmarshal(orig, &low); err != nil {
			t.Fatal(err)
		}
		for _, e := range low.Entry {
			e.CountryCode = strings.ToLower(e.CountryCode)
		}
		lowered, _ := proto.Marshal(&low)
		for _, data := range [][]byte{orig, lowered} {
			p := writeTemp(t, data)
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			if err := NormalizeGeositeCountryCodes(p); err != nil {
				t.Fatalf("%s: %v", src, err)
			}
			runtime.ReadMemStats(&after)
			alloc := after.TotalAlloc - before.TotalAlloc
			got, _ := os.ReadFile(p)
			var list router.GeoSiteList
			if err := proto.Unmarshal(got, &list); err != nil {
				t.Fatalf("%s: result does not parse: %v", src, err)
			}
			if want := normalizeWhole(t, data); !proto.Equal(&list, want) {
				t.Fatalf("%s: differs from the whole-list normalization", src)
			}
			t.Logf("%s: %d MB, %d entries, allocated %d KB", filepath.Base(src), len(data)>>20, len(list.Entry), alloc>>10)
			if alloc > 4<<20 {
				t.Fatalf("%s: allocated %d KB", src, alloc>>10)
			}
		}
	}
}
