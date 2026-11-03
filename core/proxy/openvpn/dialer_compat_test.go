package openvpn

import (
	"context"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
)

func (*fakeDialer) SetOutboundGateway(context.Context, *session.Outbound)   {}
func (interopDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
func (*burstOutbound) SenderSettings() *serial.TypedMessage                 { return nil }
func (*burstOutbound) ProxySettings() *serial.TypedMessage                  { return nil }
