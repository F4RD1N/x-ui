package hw

import (
	"bufio"
	"os"
	"strings"
)

var pciIDFiles = []string{"/usr/share/misc/pci.ids", "/usr/share/hwdata/pci.ids"}

// PCIName is a device's name from the pci.ids database, short: "Intel
// 82599ES 10-Gigabit SFI/SFP+" for 8086:10fb. "" when there is no database or
// the device is not in it.
func PCIName(fs FS, vendor, device string) string {
	vendor, device = hexID(vendor), hexID(device)
	if vendor == "" || device == "" {
		return ""
	}
	for _, p := range pciIDFiles {
		f, err := os.Open(fs.P(p))
		if err != nil {
			continue
		}
		v, d := scanPCIIDs(f, vendor, device)
		f.Close()
		if v == "" {
			continue
		}
		if d == "" {
			return ""
		}
		return shortVendor(v) + " " + shortDevice(d)
	}
	return ""
}

// scanPCIIDs finds a vendor line ("8086  Intel Corporation") and, under it,
// a device line ("\t10fb  82599ES ..."), reading the file line by line.
func scanPCIIDs(f *os.File, vendor, device string) (vname, dname string) {
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1<<16)
	in := false
	for sc.Scan() {
		l := sc.Text()
		if l == "" || l[0] == '#' {
			continue
		}
		if l[0] != '\t' {
			if in {
				return vname, ""
			}
			if strings.HasPrefix(l, "C ") {
				return "", "" // device classes follow the vendors
			}
			if id, name, ok := strings.Cut(l, "  "); ok && strings.ToLower(id) == vendor {
				in, vname = true, strings.TrimSpace(name)
			}
			continue
		}
		if !in || strings.HasPrefix(l, "\t\t") {
			continue
		}
		if id, name, ok := strings.Cut(l[1:], "  "); ok && strings.ToLower(id) == device {
			return vname, strings.TrimSpace(name)
		}
	}
	return vname, ""
}

// shortVendor drops the company form: "Intel Corporation" is "Intel".
func shortVendor(v string) string {
	for _, s := range []string{" and subsidiaries", " Corporation", " Corp.", ", Inc.", " Inc.", " Technologies", " Co., Ltd.", " Co.,Ltd.", " Ltd."} {
		if i := strings.Index(v, s); i > 0 {
			v = v[:i]
		}
	}
	return strings.TrimSpace(v)
}

// shortDevice drops what every NIC is: "... Network Connection".
func shortDevice(d string) string {
	for _, s := range []string{" Network Connection", " Ethernet Controller", " Ethernet controller", " Network Adapter"} {
		d = strings.TrimSuffix(d, s)
	}
	return strings.TrimSpace(d)
}
