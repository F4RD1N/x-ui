package websocket

import (
	"net/http"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet"
)

func (c *Config) GetNormalizedPath() string {
	path := c.Path
	if path == "" {
		return "/"
	}
	if path[0] != '/' {
		return "/" + path
	}
	return path
}

// AnyPath tells whether this server takes every path: its path is "*" (or
// "/*"). A client with that path sends "/*", which such a server takes too.
func (c *Config) AnyPath() bool {
	return c.GetNormalizedPath() == "/*"
}

func (c *Config) GetRequestHeader() http.Header {
	header := http.Header{}
	for k, v := range c.Header {
		header.Add(k, v)
	}
	utils.TryDefaultHeadersWith(header, "ws")
	return header
}

func init() {
	common.Must(internet.RegisterProtocolConfigCreator(protocolName, func() interface{} {
		return new(Config)
	}))
}
