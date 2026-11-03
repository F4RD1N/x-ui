package service

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/mhsanaei/3x-ui/v2/database"
	"github.com/mhsanaei/3x-ui/v2/database/model"
	"github.com/mhsanaei/3x-ui/v2/util/native_client"
)

type NativeClientConfig struct {
	Config   json.RawMessage `json:"config"`
	Filename string          `json:"filename"`
}

// quotaUsed avoids adding signed counters, which can overflow for corrupt or
// very large saved traffic totals. Negative counters never increase usage.
func nativeConfigQuotaUsed(limit, up, down int64) bool {
	if limit <= 0 {
		return false
	}
	if up < 0 {
		up = 0
	}
	if down < 0 {
		down = 0
	}
	return up >= limit || down >= limit || up >= limit-down
}

func nativeConfigFilename(inbound *model.Inbound, client model.Client) string {
	var b strings.Builder
	for _, c := range string(inbound.Protocol) + "-" + inbound.Remark + "-" + client.Email {
		if b.Len() >= 112 {
			break
		}
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-_") + ".json"
}

// GetNativeClientConfig exports exactly one saved account owned by the caller.
// It does not use subscription IDs, generate credentials, update usage, or
// mutate the database/core. Missing/foreign rows share the same safe error.
func (s *InboundService) GetNativeClientConfig(userID, inboundID int, email, host string) (*NativeClientConfig, error) {
	if userID <= 0 || inboundID <= 0 || email == "" || len(email) > 255 || !utf8.ValidString(email) || strings.TrimSpace(email) == "" || strings.IndexFunc(email, unicode.IsControl) >= 0 {
		return nil, errors.New("Invalid client configuration request")
	}
	host, err := native_client.Host(host)
	if err != nil {
		return nil, errors.New("A valid server endpoint is required")
	}
	var inbound model.Inbound
	if database.GetDB().Preload("ClientStats").Where("id = ? AND user_id = ?", inboundID, userID).First(&inbound).Error != nil {
		return nil, errors.New("The selected inbound is unavailable")
	}
	if !native_client.Supports(inbound.Protocol) {
		return nil, errors.New("This protocol does not support native client JSON")
	}
	now := time.Now()
	if !inbound.Enable || inbound.ExpiryTime > 0 && inbound.ExpiryTime <= now.UnixMilli() || nativeConfigQuotaUsed(inbound.Total, inbound.Up, inbound.Down) {
		return nil, errors.New("The selected inbound is inactive")
	}
	clients, err := s.GetClients(&inbound)
	if err != nil {
		return nil, errors.New("The saved client configuration is invalid")
	}
	var selected *model.Client
	for i := range clients {
		if clients[i].Email == email {
			if selected != nil {
				return nil, errors.New("The selected client identity is ambiguous")
			}
			selected = &clients[i]
		}
	}
	if selected == nil {
		return nil, errors.New("The selected client is unavailable")
	}
	if !selected.Enable || selected.ExpiryTime > 0 && selected.ExpiryTime <= now.UnixMilli() || inbound.Protocol == model.Orbit && selected.ExpiresAt > 0 && selected.ExpiresAt <= now.Unix() {
		return nil, errors.New("The selected client is inactive")
	}
	statsFound := false
	for _, stat := range inbound.ClientStats {
		if stat.Email != selected.Email {
			continue
		}
		if statsFound {
			return nil, errors.New("The selected client identity is ambiguous")
		}
		statsFound = true
		if !stat.Enable || stat.ExpiryTime > 0 && stat.ExpiryTime <= now.UnixMilli() || nativeConfigQuotaUsed(stat.Total, stat.Up, stat.Down) || nativeConfigQuotaUsed(selected.TotalGB, stat.Up, stat.Down) {
			return nil, errors.New("The selected client is inactive")
		}
	}
	config, err := native_client.FullConfig(&inbound, *selected, host)
	if err != nil {
		return nil, err
	}
	return &NativeClientConfig{Config: config, Filename: nativeConfigFilename(&inbound, *selected)}, nil
}
