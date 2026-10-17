package service

import (
	"encoding/json"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/common"
	"github.com/mhsanaei/3x-ui/v2/xray"
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

// checkInboundBuilds refuses an inbound the core would refuse, before any of
// it reaches a running core. The live add would fail, and the cores that run
// the inbound and its sub-inbounds -- with every other inbound on them -- be
// restarted into a config they cannot load. It checks the inbound as a core
// started now would get it (coreInbound), from a copy.
func checkInboundBuilds(in *model.Inbound) error {
	c := *in
	if err := coreInbound(&c); err != nil {
		return err
	}
	b, err := json.Marshal(c.GenXrayInboundConfig())
	if err != nil {
		return err
	}
	if err := xray.CheckInbound(b); err != nil {
		return common.NewError("the core would refuse this inbound:", err)
	}
	return nil
}
