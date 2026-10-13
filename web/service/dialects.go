package service

import (
	"encoding/json"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/common"
)

// checkDialects refuses VLESS dialects the core would refuse. It takes a
// list of whole numbers 0-255; a config it refuses stops the inbound's whole
// instance and every sub-inbound's, with every other inbound on them.
func checkDialects(in *model.Inbound) error {
	if in.Protocol != model.VLESS {
		return nil
	}
	var settings struct {
		Dialects json.RawMessage `json:"dialects"`
	}
	if err := json.Unmarshal([]byte(in.Settings), &settings); err != nil || len(settings.Dialects) == 0 || string(settings.Dialects) == "null" {
		return nil
	}
	var dialects []uint32
	if err := json.Unmarshal(settings.Dialects, &dialects); err != nil {
		return common.NewError("dialects must be a list of whole numbers 0-255:", string(settings.Dialects))
	}
	for _, d := range dialects {
		if d > 255 {
			return common.NewErrorf("dialects must each be 0-255, got %d", d)
		}
	}
	return nil
}
