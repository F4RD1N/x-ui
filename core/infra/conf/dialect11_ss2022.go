package conf

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
)

// UUID identity keys are an opt-in import notation. The resulting wire keys
// are ordinary SS2022 PSKs; stock cryptography and protocol handlers are used.
func NormalizeSS2022IdentityKey(method, identity string) (string, error) {
	size, err := ss2022KeySize(method)
	if err != nil {
		return "", err
	}
	id, err := uuid.Parse(identity)
	if err != nil {
		return identity, nil
	}
	key := append([]byte(nil), id[:]...)
	if size == 32 {
		key = append(key, id[:]...)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func ss2022KeySize(method string) (int, error) {
	switch method {
	case "2022-blake3-aes-128-gcm":
		return 16, nil
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return 32, nil
	default:
		return 0, errors.New("uuidIdentityKeys requires an exact supported Shadowsocks 2022 method")
	}
}

func ss2022UUIDFlag(object map[string]json.RawMessage) (enabled, present bool, err error) {
	raw, present := object["uuidIdentityKeys"]
	if !present {
		return false, false, nil
	}
	delete(object, "uuidIdentityKeys")
	if string(raw) == "null" || json.Unmarshal(raw, &enabled) != nil {
		return false, true, errors.New("uuidIdentityKeys must be a boolean")
	}
	return enabled, true, nil
}

func ss2022OutboundObject(object map[string]json.RawMessage) error {
	enabled, _, err := ss2022UUIDFlag(object)
	if err != nil || !enabled {
		return err
	}
	var method, password string
	if json.Unmarshal(object["method"], &method) != nil || json.Unmarshal(object["password"], &password) != nil {
		return errors.New("uuidIdentityKeys requires method and password on the same server")
	}
	size, err := ss2022KeySize(method)
	if err != nil {
		return err
	}
	parts := strings.Split(password, ":")
	psk, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil || len(psk) != size {
		return errors.New("uuidIdentityKeys requires a canonical server PSK of the method's key length")
	}
	for i := 1; i < len(parts); i++ {
		parts[i], err = NormalizeSS2022IdentityKey(method, parts[i])
		if err != nil {
			return err
		}
	}
	object["password"], _ = json.Marshal(strings.Join(parts, ":"))
	return nil
}

type dialect11SSClient struct{ ShadowsocksClientConfig }

func (c *dialect11SSClient) UnmarshalJSON(raw []byte) error {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return errors.New("Shadowsocks settings must be an object")
	}
	if err := ss2022OutboundObject(object); err != nil {
		return err
	}
	if servers, ok := object["servers"]; ok {
		var list []map[string]json.RawMessage
		if json.Unmarshal(servers, &list) != nil {
			return errors.New("Shadowsocks servers must be an array")
		}
		for _, server := range list {
			if server == nil {
				return errors.New("Shadowsocks server must be an object")
			}
			if err := ss2022OutboundObject(server); err != nil {
				return err
			}
		}
		object["servers"], _ = json.Marshal(list)
	}
	normalized, _ := json.Marshal(object)
	return json.Unmarshal(normalized, &c.ShadowsocksClientConfig)
}
func (c *dialect11SSClient) Build() (proto.Message, error) { return c.ShadowsocksClientConfig.Build() }

type dialect11SSServer struct{ ShadowsocksServerConfig }

func (c *dialect11SSServer) UnmarshalJSON(raw []byte) error {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return errors.New("Shadowsocks settings must be an object")
	}
	all, _, err := ss2022UUIDFlag(object)
	if err != nil {
		return err
	}
	var method string
	_ = json.Unmarshal(object["method"], &method)
	if all {
		if _, err := ss2022KeySize(method); err != nil {
			return err
		}
	}
	if clients, ok := object["clients"]; ok {
		var list []map[string]json.RawMessage
		if json.Unmarshal(clients, &list) != nil {
			return errors.New("Shadowsocks clients must be an array")
		}
		for _, client := range list {
			if client == nil {
				return errors.New("Shadowsocks client must be an object")
			}
			enabled, present, err := ss2022UUIDFlag(client)
			if err != nil {
				return err
			}
			if !present {
				enabled = all
			}
			if enabled {
				var key string
				if json.Unmarshal(client["password"], &key) != nil {
					return errors.New("UUID identity requires a password string")
				}
				key, err = NormalizeSS2022IdentityKey(method, key)
				if err != nil {
					return err
				}
				client["password"], _ = json.Marshal(key)
			}
		}
		object["clients"], _ = json.Marshal(list)
	}
	normalized, _ := json.Marshal(object)
	return json.Unmarshal(normalized, &c.ShadowsocksServerConfig)
}
func (c *dialect11SSServer) Build() (proto.Message, error) { return c.ShadowsocksServerConfig.Build() }

func init() {
	inboundConfigLoader.cache["shadowsocks"] = func() interface{} { return new(dialect11SSServer) }
	outboundConfigLoader.cache["shadowsocks"] = func() interface{} { return new(dialect11SSClient) }
}
