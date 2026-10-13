package hw

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FS reads system files below Root ("" is the real system). Paths given to
// its methods are system paths ("/sys/class/net"); results are system paths
// too.
type FS struct{ Root string }

// EnvFS is the real system, or the tree XUI_HW_ROOT names (tests only).
func EnvFS() FS {
	if r := os.Getenv("XUI_HW_ROOT"); r != "" {
		if abs, err := filepath.Abs(r); err == nil {
			return FS{Root: filepath.Clean(abs)}
		}
	}
	return FS{}
}

// P maps an absolute system path into the root. It panics if the result
// would leave the root: a test must never read the real system by accident.
func (fs FS) P(abs string) string {
	if fs.Root == "" {
		return abs
	}
	j := filepath.Join(fs.Root, abs)
	if j != fs.Root && !strings.HasPrefix(j, fs.Root+string(os.PathSeparator)) {
		panic("hw: path escapes the root: " + abs)
	}
	return j
}

// unP turns a path below the root back into a system path.
func (fs FS) unP(p string) string {
	if fs.Root == "" {
		return p
	}
	r := strings.TrimPrefix(p, fs.Root)
	if r == "" {
		return "/"
	}
	return filepath.ToSlash(r)
}

func (fs FS) Read(abs string) (string, error) {
	b, err := os.ReadFile(fs.P(abs))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ReadTrim is the file's content without surrounding space, "" on any error.
func (fs FS) ReadTrim(abs string) string {
	s, err := fs.Read(abs)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(s)
}

// Exists reports whether the path exists, without following a final symlink.
func (fs FS) Exists(abs string) bool {
	_, err := os.Lstat(fs.P(abs))
	return err == nil
}

// Glob is filepath.Glob on system paths.
func (fs FS) Glob(pattern string) []string {
	m, _ := filepath.Glob(fs.P(pattern))
	out := make([]string, 0, len(m))
	for _, p := range m {
		out = append(out, fs.unP(p))
	}
	return out
}

// ReadDir lists a directory's entry names, sorted; nil on error.
func (fs FS) ReadDir(abs string) []string {
	ents, err := os.ReadDir(fs.P(abs))
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out
}

// Resolve follows every symlink in the path, relative or absolute, the way
// the kernel would but inside the root (an absolute target means the root's
// path), at most 16 links deep. It returns a system path. A missing
// component ends the walk: the rest is appended as it is.
func (fs FS) Resolve(abs string) string {
	rest := strings.Split(strings.Trim(filepath.ToSlash(filepath.Clean("/"+abs)), "/"), "/")
	cur := "/"
	links := 0
	for len(rest) > 0 {
		c := rest[0]
		rest = rest[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			cur = filepath.ToSlash(filepath.Dir(cur))
			continue
		}
		next := filepath.ToSlash(filepath.Join(cur, c))
		st, err := os.Lstat(fs.P(next))
		if err != nil {
			return filepath.ToSlash(filepath.Join(append([]string{next}, rest...)...))
		}
		if st.Mode()&os.ModeSymlink == 0 {
			cur = next
			continue
		}
		links++
		if links > 16 {
			return filepath.ToSlash(filepath.Join(append([]string{next}, rest...)...))
		}
		t, err := os.Readlink(fs.P(next))
		if err != nil {
			return filepath.ToSlash(filepath.Join(append([]string{next}, rest...)...))
		}
		t = filepath.ToSlash(t)
		if strings.HasPrefix(t, "/") {
			cur = "/"
		}
		rest = append(strings.Split(strings.Trim(t, "/"), "/"), rest...)
	}
	return cur
}

// LinkBase is the base name of a symlink's target ("ixgbe" for a driver
// link), "" when the path is not a symlink.
func (fs FS) LinkBase(abs string) string {
	t, err := os.Readlink(fs.P(abs))
	if err != nil {
		return ""
	}
	return filepath.Base(filepath.ToSlash(t))
}
