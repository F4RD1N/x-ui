// Package model defines the database models and data structures used by the 3x-ui panel.
package model

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mhsanaei/3x-ui/v2/util/json_util"
	"github.com/mhsanaei/3x-ui/v2/xray"
)

// Protocol represents the protocol type for Xray inbounds.
type Protocol string

// Protocol constants for different Xray inbound protocols
const (
	VMESS       Protocol = "vmess"
	VLESS       Protocol = "vless"
	Tunnel      Protocol = "tunnel"
	HTTP        Protocol = "http"
	Trojan      Protocol = "trojan"
	Shadowsocks Protocol = "shadowsocks"
	Mixed       Protocol = "mixed"
	WireGuard   Protocol = "wireguard"
	Hysteria    Protocol = "hysteria"
)

// User represents a user account in the 3x-ui panel.
type User struct {
	Id       int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// Inbound represents an Xray inbound configuration with traffic statistics and settings.
type Inbound struct {
	Id                   int                  `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`                                                    // Unique identifier
	UserId               int                  `json:"-"`                                                                                               // Associated user ID
	Up                   int64                `json:"up" form:"up"`                                                                                    // Upload traffic in bytes
	Down                 int64                `json:"down" form:"down"`                                                                                // Download traffic in bytes
	Total                int64                `json:"total" form:"total"`                                                                              // Total traffic limit in bytes
	AllTime              int64                `json:"allTime" form:"allTime" gorm:"default:0"`                                                         // All-time traffic usage
	Remark               string               `json:"remark" form:"remark"`                                                                            // Human-readable remark
	Enable               bool                 `json:"enable" form:"enable" gorm:"index:idx_enable_traffic_reset,priority:1"`                           // Whether the inbound is enabled
	ExpiryTime           int64                `json:"expiryTime" form:"expiryTime"`                                                                    // Expiration timestamp
	TrafficReset         string               `json:"trafficReset" form:"trafficReset" gorm:"default:never;index:idx_enable_traffic_reset,priority:2"` // Traffic reset schedule
	LastTrafficResetTime int64                `json:"lastTrafficResetTime" form:"lastTrafficResetTime" gorm:"default:0"`                               // Last traffic reset timestamp
	ClientStats          []xray.ClientTraffic `gorm:"foreignKey:InboundId;references:Id" json:"clientStats" form:"clientStats"`                        // Client traffic statistics

	// Xray configuration fields
	Listen         string   `json:"listen" form:"listen"`
	Port           int      `json:"port" form:"port"`
	Protocol       Protocol `json:"protocol" form:"protocol"`
	Settings       string   `json:"settings" form:"settings"`
	StreamSettings string   `json:"streamSettings" form:"streamSettings"`
	Tag            string   `json:"tag" form:"tag" gorm:"unique"`
	Sniffing       string   `json:"sniffing" form:"sniffing"`

	// XrayInstance names the Xray core process this inbound runs in; inbounds
	// with the same name share one process. XrayCores is how many CPU cores
	// that process may use, 0 meaning an automatic share of the cores left
	// over. It belongs to the instance, so all its inbounds carry the same
	// value.
	XrayInstance string `json:"xrayInstance" form:"xrayInstance" gorm:"default:''"`
	XrayCores    int    `json:"xrayCores" form:"xrayCores" gorm:"default:0"`

	// SubInbounds is a JSON list of SubInbound: copies of this inbound on
	// other ports, each in its own xray instance. They share everything
	// else -- protocol, settings, clients, transport -- with this inbound.
	SubInbounds string `json:"subInbounds" form:"subInbounds" gorm:"default:''"`

	// SubOf is set on the copies ExpandSubInbounds makes: the id of the
	// inbound they belong to. Not stored.
	SubOf int `json:"subOf,omitempty" gorm:"-"`
}

// SubInbound is one sub-inbound: the only settings it has of its own.
type SubInbound struct {
	Port     int    `json:"port"`
	Instance string `json:"instance"`
	Cores    int    `json:"cores"` // 0 = auto
	Enable   bool   `json:"enable"`
}

// SubTagSep joins an inbound's tag and a sub-inbound's port into the
// sub-inbound's tag: inbound-443~sub444.
const SubTagSep = "~sub"

// SubTag returns the tag of the sub-inbound of parent on port.
func SubTag(parent string, port int) string {
	return fmt.Sprintf("%s%s%d", parent, SubTagSep, port)
}

// ParentTag returns the inbound tag a sub-inbound tag belongs to; any
// other tag is returned as it is.
func ParentTag(tag string) string {
	if i := strings.Index(tag, SubTagSep); i >= 0 {
		return tag[:i]
	}
	return tag
}

// Subs returns the inbound's sub-inbounds.
func (i *Inbound) Subs() []SubInbound {
	if strings.TrimSpace(i.SubInbounds) == "" {
		return nil
	}
	var out []SubInbound
	if json.Unmarshal([]byte(i.SubInbounds), &out) != nil {
		return nil
	}
	return out
}

// SetSubs stores subs as the inbound's sub-inbounds.
func (i *Inbound) SetSubs(subs []SubInbound) {
	if len(subs) == 0 {
		i.SubInbounds = ""
		return
	}
	b, _ := json.Marshal(subs)
	i.SubInbounds = string(b)
}

// ExpandSubInbounds returns the inbounds with each one's sub-inbounds after
// it, as inbounds of their own: the same inbound on the sub-inbound's port,
// with its tag, instance and cores, enabled when both it and the inbound
// are. The copies carry SubOf.
func ExpandSubInbounds(list []*Inbound) []*Inbound {
	out := make([]*Inbound, 0, len(list))
	for _, in := range list {
		out = append(out, in)
		for _, sub := range in.Subs() {
			c := *in
			c.Port = sub.Port
			c.Tag = SubTag(in.Tag, sub.Port)
			c.XrayInstance = sub.Instance
			c.XrayCores = sub.Cores
			c.Enable = in.Enable && sub.Enable
			c.SubInbounds = ""
			c.SubOf = in.Id
			out = append(out, &c)
		}
	}
	return out
}

// XrayInstancePrefix is how default instance names start: xray-1, xray-2, ...
const XrayInstancePrefix = "xray-"

// NextXrayInstanceName returns the first default instance name not in used.
func NextXrayInstanceName(used map[string]bool) string {
	for n := 1; ; n++ {
		name := fmt.Sprintf("%s%d", XrayInstancePrefix, n)
		if !used[name] {
			return name
		}
	}
}

// LessInstanceName orders instance names naturally, so xray-2 comes before
// xray-10.
func LessInstanceName(a, b string) bool {
	for a != "" && b != "" {
		ad, bd := isDigit(a[0]), isDigit(b[0])
		if ad && bd {
			na, ra := splitDigits(a)
			nb, rb := splitDigits(b)
			ta, tb := trimZeros(na), trimZeros(nb)
			if len(ta) != len(tb) {
				return len(ta) < len(tb)
			}
			if ta != tb {
				return ta < tb
			}
			if len(na) != len(nb) {
				return len(na) < len(nb)
			}
			a, b = ra, rb
			continue
		}
		if a[0] != b[0] {
			return a[0] < b[0]
		}
		a, b = a[1:], b[1:]
	}
	return len(a) < len(b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func splitDigits(s string) (string, string) {
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

func trimZeros(s string) string {
	for len(s) > 1 && s[0] == '0' {
		s = s[1:]
	}
	return s
}

// OutboundTraffics tracks traffic statistics for Xray outbound connections.
type OutboundTraffics struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Tag   string `json:"tag" form:"tag" gorm:"unique"`
	Up    int64  `json:"up" form:"up" gorm:"default:0"`
	Down  int64  `json:"down" form:"down" gorm:"default:0"`
	Total int64  `json:"total" form:"total" gorm:"default:0"`
}

// InboundClientIps stores IP addresses associated with inbound clients for access control.
type InboundClientIps struct {
	Id          int    `json:"id" gorm:"primaryKey;autoIncrement"`
	ClientEmail string `json:"clientEmail" form:"clientEmail" gorm:"unique"`
	Ips         string `json:"ips" form:"ips"`
}

// HistoryOfSeeders tracks which database seeders have been executed to prevent re-running.
type HistoryOfSeeders struct {
	Id         int    `json:"id" gorm:"primaryKey;autoIncrement"`
	SeederName string `json:"seederName"`
}

// GenXrayInboundConfig generates an Xray inbound configuration from the Inbound model.
func (i *Inbound) GenXrayInboundConfig() *xray.InboundConfig {
	listen := i.Listen
	// Default to 0.0.0.0 (all interfaces) when listen is empty
	// This ensures proper dual-stack IPv4/IPv6 binding in systems where bindv6only=0
	if listen == "" {
		listen = "0.0.0.0"
	}
	listen = fmt.Sprintf("\"%v\"", listen)
	return &xray.InboundConfig{
		Listen:         json_util.RawMessage(listen),
		Port:           i.Port,
		Protocol:       string(i.Protocol),
		Settings:       json_util.RawMessage(i.Settings),
		StreamSettings: json_util.RawMessage(i.StreamSettings),
		Tag:            i.Tag,
		Sniffing:       json_util.RawMessage(i.Sniffing),
	}
}

// Setting stores key-value configuration settings for the 3x-ui panel.
type Setting struct {
	Id    int    `json:"id" form:"id" gorm:"primaryKey;autoIncrement"`
	Key   string `json:"key" form:"key"`
	Value string `json:"value" form:"value"`
}

type CustomGeoResource struct {
	Id            int    `json:"id" gorm:"primaryKey;autoIncrement"`
	Type          string `json:"type" gorm:"not null;uniqueIndex:idx_custom_geo_type_alias;column:geo_type"`
	Alias         string `json:"alias" gorm:"not null;uniqueIndex:idx_custom_geo_type_alias"`
	Url           string `json:"url" gorm:"not null"`
	LocalPath     string `json:"localPath" gorm:"column:local_path"`
	LastUpdatedAt int64  `json:"lastUpdatedAt" gorm:"default:0;column:last_updated_at"`
	LastModified  string `json:"lastModified" gorm:"column:last_modified"`
	CreatedAt     int64  `json:"createdAt" gorm:"autoCreateTime;column:created_at"`
	UpdatedAt     int64  `json:"updatedAt" gorm:"autoUpdateTime;column:updated_at"`
}

// Client represents a client configuration for Xray inbounds with traffic limits and settings.
type Client struct {
	ID         string `json:"id,omitempty"`                 // Unique client identifier
	Security   string `json:"security"`                     // Security method (e.g., "auto", "aes-128-gcm")
	Password   string `json:"password,omitempty"`           // Client password
	Flow       string `json:"flow,omitempty"`               // Flow control (XTLS)
	Auth       string `json:"auth,omitempty"`               // Auth password (Hysteria)
	Email      string `json:"email"`                        // Client email identifier
	LimitIP    int    `json:"limitIp"`                      // IP limit for this client
	TotalGB    int64  `json:"totalGB" form:"totalGB"`       // Total traffic limit in GB
	ExpiryTime int64  `json:"expiryTime" form:"expiryTime"` // Expiration timestamp
	Enable     bool   `json:"enable" form:"enable"`         // Whether the client is enabled
	TgID       int64  `json:"tgId" form:"tgId"`             // Telegram user ID for notifications
	SubID      string `json:"subId" form:"subId"`           // Subscription identifier
	Comment    string `json:"comment" form:"comment"`       // Client comment
	Reset      int    `json:"reset" form:"reset"`           // Reset period in days
	CreatedAt  int64  `json:"created_at,omitempty"`         // Creation timestamp
	UpdatedAt  int64  `json:"updated_at,omitempty"`         // Last update timestamp
}
