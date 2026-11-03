package anytls

import (
	"context"
	"github.com/xtls/xray-core/common/session"
)

// The server core's Dialer adds a gateway hook; these ported client test
// dialers intentionally do not alter gateway selection.
func (panicDialer) SetOutboundGateway(context.Context, *session.Outbound)    {}
func (errDialer) SetOutboundGateway(context.Context, *session.Outbound)      {}
func (ctxBoundDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
func (*blockedDialer) SetOutboundGateway(context.Context, *session.Outbound) {}
