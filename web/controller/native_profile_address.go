package controller

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/mhsanaei/3x-ui/v2/web/service"
)

type nativeProfileLookup func(context.Context, string) ([]net.IPAddr, error)

// prepareNativeProfileAddress resolves only during explicit form generation.
// A selected numeric endpoint is preserved together with its certificate SAN,
// so later subscription requests cannot silently pick another address.
func prepareNativeProfileAddress(ctx context.Context, requestHost string, request *service.NativeCredentialRequest, lookup nativeProfileLookup) error {
	if request.ServerName == "" {
		host := requestHost
		if split, _, err := net.SplitHostPort(host); err == nil {
			host = split
		} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		}
		request.ServerName = host
	}
	if request.Protocol != "orbit" {
		return nil
	}
	valid := func(ip net.IP) bool { return ip != nil && (ip.IsGlobalUnicast() || ip.IsLoopback()) }
	if request.ServerAddress != "" {
		ip := net.ParseIP(request.ServerAddress)
		if !valid(ip) {
			return errors.New("Orbit serverAddress must be a numeric unicast IP")
		}
		request.ServerAddress = ip.String()
		return nil
	}
	if ip := net.ParseIP(request.ServerName); ip != nil {
		if !valid(ip) {
			return errors.New("Orbit server name must identify a unicast endpoint")
		}
		request.ServerAddress = ip.String()
		return nil
	}
	// Validate a DNS host before allowing a lookup; URLs, ports, zones, spaces
	// and empty names are not DNS endpoint identifiers.
	host := strings.TrimSuffix(request.ServerName, ".")
	if host == "" || len(host) > 253 {
		return errors.New("Orbit server name must be a DNS host or numeric IP")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("Orbit server name must be a DNS host or numeric IP")
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
				return errors.New("Orbit server name must be a DNS host or numeric IP")
			}
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addresses, err := lookup(ctx, host)
	if err != nil {
		return errors.New("Orbit endpoint lookup failed; set a numeric serverAddress")
	}
	var selected net.IP
	for _, address := range addresses {
		if address.Zone != "" || !valid(address.IP) {
			continue
		}
		if selected == nil {
			selected = address.IP
		}
		if address.IP.To4() != nil {
			selected = address.IP
			break
		}
	}
	if selected == nil {
		return errors.New("Orbit endpoint lookup returned no unicast IP; set serverAddress")
	}
	request.ServerName, request.ServerAddress = strings.ToLower(host), selected.String()
	return nil
}
