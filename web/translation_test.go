package web

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// flatKeys returns the dotted keys of a parsed translation file.
func flatKeys(prefix string, m map[string]any, out map[string]bool) {
	for k, v := range m {
		if sub, ok := v.(map[string]any); ok {
			flatKeys(prefix+k+".", sub, out)
		} else {
			out[prefix+k] = true
		}
	}
}

// Every translation file has the same keys, and every key the pages and
// the Go code name exists, so no language falls back to an empty string.
func TestTranslationsComplete(t *testing.T) {
	files := map[string]map[string]bool{}
	err := fs.WalkDir(i18nFS, "translation", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := fs.ReadFile(i18nFS, path)
		if err != nil {
			return err
		}
		var m map[string]any
		if err := toml.Unmarshal(data, &m); err != nil {
			t.Errorf("%s: %v", path, err)
			return nil
		}
		keys := map[string]bool{}
		flatKeys("", m, keys)
		files[filepath.Base(path)] = keys
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 13 {
		t.Fatalf("%d translation files, want 13", len(files))
	}

	used := map[string]bool{
		// PlanSubInbounds' messages, named by key in the service.
		"pages.inbounds.multiInstanceNoCores": true, "pages.inbounds.multiInstanceChooseOne": true,
		"pages.inbounds.multiInstanceNeedCores": true, "pages.inbounds.multiInstanceAllReserved": true,
		"pages.inbounds.multiInstanceFewPorts": true, "pages.inbounds.subInboundSocket": true,
	}
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`i18n\s+"([^"]+)"`),
		regexp.MustCompile(`I18nWeb\(c,\s*"([^"]+)"`),
		regexp.MustCompile(`I18nBot\("([^"]+)"`),
	}
	for _, root := range []string{".", "../sub"} {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !(strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".go")) || strings.HasSuffix(path, "_test.go") {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, re := range patterns {
				for _, m := range re.FindAllStringSubmatch(string(data), -1) {
					if !strings.HasSuffix(m[1], ".") { // a prefix joined to a key
						used[m[1]] = true
					}
				}
			}
			return nil
		})
	}

	all := map[string]bool{}
	for _, keys := range files {
		for k := range keys {
			all[k] = true
		}
	}
	for name, keys := range files {
		var missing []string
		for k := range all {
			if !keys[k] {
				missing = append(missing, k)
			}
		}
		for k := range used {
			if !keys[k] && !all[k] {
				missing = append(missing, k)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Errorf("%s lacks %s", name, strings.Join(missing, ", "))
		}
	}
}
