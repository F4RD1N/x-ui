package service

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/mhsanaei/3x-ui/v2/database/model"
	"gorm.io/gorm"
)

type restoreListener struct {
	requested string
	actual    string
}

var restoreListeners = struct {
	sync.Mutex
	owned map[string]*restoreListener
}{owned: make(map[string]*restoreListener)}

// RegisterRestoreListener records an actually opened panel/subscription socket.
// Saved settings alone cannot establish ownership: they may await a reload.
// The returned cleanup cannot erase a newer listener's registration.
func RegisterRestoreListener(kind, requested string, listener net.Listener) func() {
	entry := &restoreListener{requested: requested, actual: listener.Addr().String()}
	restoreListeners.Lock()
	restoreListeners.owned[kind] = entry
	restoreListeners.Unlock()
	return func() {
		restoreListeners.Lock()
		if restoreListeners.owned[kind] == entry {
			delete(restoreListeners.owned, kind)
		}
		restoreListeners.Unlock()
	}
}

type backupListener struct {
	kind, address string
	host          net.IP
	port          int
}

func backupListenerSettings(filename string) ([]backupListener, error) {
	var endpoints []backupListener
	err := withBackupDB(filename, true, func(db *gorm.DB) error {
		var rows []model.Setting
		if err := db.Where("key IN ?", []string{"webListen", "webPort", "subListen", "subPort", "subEnable"}).Find(&rows).Error; err != nil {
			return err
		}
		values := make(map[string]string)
		for _, key := range []string{"webListen", "webPort", "subListen", "subPort", "subEnable"} {
			values[key] = defaultValueMap[key]
		}
		for _, row := range rows {
			values[row.Key] = row.Value
		}
		subEnabled, err := strconv.ParseBool(values["subEnable"])
		if err != nil {
			return errors.New("backup subscription enable setting is invalid")
		}
		for _, kind := range []string{"web", "sub"} {
			if kind == "sub" && !subEnabled {
				continue
			}
			port, err := strconv.Atoi(values[kind+"Port"])
			if err != nil || port < 1 || port > 65535 {
				return fmt.Errorf("backup %s listener port is invalid", kind)
			}
			host := values[kind+"Listen"]
			var ip net.IP
			if host != "" {
				ip = net.ParseIP(host)
				if ip == nil {
					return fmt.Errorf("backup %s listener address must be an IP address or empty", kind)
				}
				host = ip.String()
			}
			endpoints = append(endpoints, backupListener{kind: kind, address: net.JoinHostPort(host, strconv.Itoa(port)), host: ip, port: port})
		}
		return nil
	})
	return endpoints, err
}

// Check new sockets without stopping the existing ones. Only an exact endpoint
// already opened by this process is exempted. Matching a port number or saved
// setting alone must not hide an unrelated process occupying another address.
func validateBackupListeners(filename string) error {
	endpoints, err := backupListenerSettings(filename)
	if err != nil {
		return err
	}
	if len(endpoints) == 2 {
		a, b := endpoints[0], endpoints[1]
		if a.port == b.port && (a.host == nil || b.host == nil || a.host.IsUnspecified() || b.host.IsUnspecified() || a.host.Equal(b.host)) {
			return errors.New("backup panel and subscription listeners overlap")
		}
	}
	restoreListeners.Lock()
	owned := make([]restoreListener, 0, len(restoreListeners.owned))
	for _, listener := range restoreListeners.owned {
		owned = append(owned, *listener)
	}
	restoreListeners.Unlock()
	var probes []net.Listener
	defer func() {
		for _, probe := range probes {
			_ = probe.Close()
		}
	}()
	for _, endpoint := range endpoints {
		alreadyOwned := false
		for _, listener := range owned {
			if endpoint.address == listener.requested || endpoint.address == listener.actual {
				alreadyOwned = true
				break
			}
		}
		if alreadyOwned {
			continue
		}
		listener, err := net.Listen("tcp", endpoint.address)
		if err != nil {
			return fmt.Errorf("backup %s listener is unavailable: %w", endpoint.kind, err)
		}
		probes = append(probes, listener)
	}
	return nil
}
