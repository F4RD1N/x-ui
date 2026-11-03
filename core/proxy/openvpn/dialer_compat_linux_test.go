package openvpn

import (
	"context"
	"github.com/xtls/xray-core/common/session"
)

func (*socketDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
