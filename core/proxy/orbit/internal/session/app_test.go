package session

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

func TestApplicationControlRoundTripAndQueueBound(t *testing.T) {
	c, s := pair(t, Options{AppQueue: 1})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request := protocol.AppMessage{Type: 1, RequestID: 0x12345678}
	if e := c.SendApp(ctx, request); e != nil {
		t.Fatal(e)
	}
	m, e := s.ReceiveApp(ctx)
	if e != nil || m.Type != request.Type || m.RequestID != request.RequestID || len(m.Data) != 0 {
		t.Fatal(m, e)
	}
	reply := protocol.AppMessage{Type: 2, RequestID: m.RequestID, Data: []byte(`{"node_id":7,"ip":"192.0.2.1"}`)}
	if e = s.SendApp(ctx, reply); e != nil {
		t.Fatal(e)
	}
	m, e = c.ReceiveApp(ctx)
	if e != nil || m.Type != 2 || m.RequestID != reply.RequestID || !bytes.Equal(m.Data, reply.Data) {
		t.Fatal(m, e)
	}
	if _, e = s.ReceiveApp(nil); e == nil {
		t.Fatal("nil context accepted")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, e = s.ReceiveApp(canceled); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if e = c.SendApp(ctx, request); e != nil {
		t.Fatal(e)
	}
	_ = c.SendApp(ctx, request)
	select {
	case <-s.Done():
		if !errors.Is(s.Err(), ErrBufferLimit) {
			t.Fatal(s.Err())
		}
	case <-ctx.Done():
		t.Fatal("unbounded app queue")
	}
}
