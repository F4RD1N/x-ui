package hw

import (
	"encoding/json"
	"fmt"
	"path/filepath"
)

// InstancesFile is the file in the panel's bin folder that tells "x-ui tune
// nic" and "x-ui diag" how the xray instances split the CPUs.
const InstancesFile = "instances.json"

// Instances is the content of instances.json.
type Instances struct {
	Version   int        `json:"version"`   // 1
	Allowed   string     `json:"allowed"`   // CPU list the panel may use
	Instances []Instance `json:"instances"` // running instances, in the panel's natural name order
}

// Instance is one running xray instance.
type Instance struct {
	Name   string `json:"name"`
	CPUs   string `json:"cpus"`             // CPU list ("" = unpinned)
	Cores  int    `json:"cores"`            // the request: 0 = auto
	Config string `json:"config"`           // absolute path of its config-<slug>.json
	Egress string `json:"egress,omitempty"` // outgoing IPv4 the core sends from
}

// InstancesPath is instances.json in the bin folder.
func InstancesPath(binFolder string) string { return filepath.Join(binFolder, InstancesFile) }

// ReadInstances reads instances.json (a system path, below fs's root).
func ReadInstances(fs FS, path string) (*Instances, error) {
	data, err := fs.Read(path)
	if err != nil {
		return nil, err
	}
	s := &Instances{}
	if err := json.Unmarshal([]byte(data), s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("%s: version %d is not supported", path, s.Version)
	}
	return s, nil
}

// Marshal is the file's bytes: indented JSON and a newline, the same bytes
// for the same content (no time in it), so the panel writes it only when the
// split changes.
func (s *Instances) Marshal() []byte {
	c := *s
	if c.Version == 0 {
		c.Version = 1
	}
	if c.Instances == nil {
		c.Instances = []Instance{}
	}
	b, _ := json.MarshalIndent(&c, "", "  ")
	return append(b, '\n')
}
