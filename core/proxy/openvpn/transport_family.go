package openvpn

import (
	"context"
	"net"

	"github.com/xtls/xray-core/common/dice"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
)

type transportIPResolver interface {
	LookupIP(context.Context, string, string) ([]net.IP, error)
}

// transportFamily preserves explicit OpenVPN transport-family selectors when
// adapting to Xray's generic TCP/UDP dialer. DomainStrategy in Config controls
// destinations inside the tunnel and must not override this bootstrap choice.
// Explicit-family hostnames use system bootstrap DNS, matching the ordinary
// system dialer's bootstrap path. They are resolved locally before chaining;
// unsuffixed transports retain the dialer's own DNS and routing decisions.
func (h *Handler) transportFamily(ctx context.Context, network string, dest xnet.Destination) (xnet.Destination, error) {
	if err := ctx.Err(); err != nil {
		return xnet.Destination{}, err
	}
	v4, v6 := network == "tcp4" || network == "udp4", network == "tcp6" || network == "udp6"
	if !v4 && !v6 {
		return dest, nil
	}
	if !dest.Address.Family().IsDomain() {
		if v4 && !dest.Address.Family().IsIPv4() || v6 && !dest.Address.Family().IsIPv6() {
			return xnet.Destination{}, errors.New("OpenVPN transport address does not match ", network)
		}
		return dest, nil
	}
	resolver := h.transportResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	family := "ip4"
	if v6 {
		family = "ip6"
	}
	ips, err := resolver.LookupIP(ctx, family, dest.Address.Domain())
	// Also reject an answer racing with cancellation before the dialer opens
	// a new transport. Never bootstrap through application DNS: it may route
	// its own queries through the tunnel whose setup is waiting on this call.
	if cause := ctx.Err(); cause != nil {
		return xnet.Destination{}, cause
	}
	if err != nil {
		return xnet.Destination{}, errors.New("failed to resolve OpenVPN transport family").Base(err)
	}
	ips = keepFamilies(ips, v4, v6)
	if len(ips) == 0 {
		return xnet.Destination{}, dns.ErrEmptyResponse
	}
	dest.Address = xnet.IPAddress(ips[dice.Roll(len(ips))])
	return dest, nil
}
