//go:build linux

package diag

import (
	"encoding/json"
	"io"
)

// writeJSON prints the report as indented JSON. Maps come out with sorted
// keys and every list as [] rather than null, so the output is stable.
func (c *ctx) writeJSON(w io.Writer) error {
	r := c.r
	for _, nr := range r.NICs {
		if nr.IRQs == nil {
			nr.IRQs = []IRQReport{}
		}
	}
	if r.Hardware.Nodes == nil {
		r.Hardware.Nodes = []NodeReport{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}
