// Package global provides global variables and interfaces for accessing web and subscription servers.
package global

import (
	"context"
	"github.com/mhsanaei/3x-ui/v2/config"
	_ "unsafe"

	"github.com/robfig/cron/v3"
)

var (
	webServer WebServer
	subServer SubServer
)

// WebServer interface defines methods for accessing the web server instance.
type WebServer interface {
	GetCron() *cron.Cron     // Get the cron scheduler
	GetCtx() context.Context // Get the server context
	GetWSHub() any           // Get the WebSocket hub (using any to avoid circular dependency)
}

// SubServer interface defines methods for accessing the subscription server instance.
type SubServer interface {
	GetCtx() context.Context // Get the server context
}

// SetWebServer sets the global web server instance.
func SetWebServer(s WebServer) {
	webServer = s
}

// GetWebServer returns the global web server instance.
func GetWebServer() WebServer {
	return webServer
}

// SetSubServer sets the global subscription server instance.
func SetSubServer(s SubServer) {
	subServer = s
}

// GetSubServer returns the global subscription server instance.
func GetSubServer() SubServer {
	return subServer
}

// assetsFingerprint identifies the panel's embedded assets (see
// SetAssetsFingerprint).
var assetsFingerprint string

// SetAssetsFingerprint records a fingerprint of the embedded assets.
func SetAssetsFingerprint(fp string) {
	assetsFingerprint = fp
}

// AssetVersion is what asset URLs carry (?<AssetVersion>) so browsers fetch
// them again after an update. The assets are cached for a year, and the
// version number alone does not change between builds of a branch, so a
// browser kept old scripts next to new pages; the fingerprint changes
// whenever any asset does.
func AssetVersion() string {
	if assetsFingerprint == "" {
		return config.GetVersion()
	}
	return config.GetVersion() + "-" + assetsFingerprint
}
