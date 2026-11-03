package orbit

import (
	"context"
	"testing"

	xprotocol "github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/proxy/orbit/internal/connectionkey"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

func d11OrbitGenerationFixture(t *testing.T) (*Server, *xprotocol.MemoryUser, protocol.UserInfo) {
	t.Helper()
	id := d11OrbitNewIdentity(t)
	user := &xprotocol.User{Email: "same-key@example.invalid", Level: 7, Account: serial.ToTypedMessage(&Account{Key: id.key})}
	s, err := NewServer(context.Background(), &ServerConfig{Transport: "tcp", Users: []*xprotocol.User{user},
		Tls: &Certificate{Certificate: []string{id.certificate}, Key: []string{id.privateKey}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	memory, err := user.ToMemoryUser()
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := connectionkey.Decode(id.key)
	if err != nil {
		t.Fatal(err)
	}
	return s, memory, protocol.UserInfo{UID: c.UID, Token: c.Token, DeviceID: c.DeviceID}
}

func TestD11OrbitSameKeyReaddCannotAdmitEarlierAuthentication(t *testing.T) {
	s, user, wire := d11OrbitGenerationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	run := &serverRun{cancel: cancel}
	s.mu.Lock()
	s.active[run] = struct{}{}
	s.mu.Unlock()
	t.Cleanup(func() { s.mu.Lock(); delete(s.active, run); s.mu.Unlock() })
	// Pause an actual registered handshake run at the boundary between its
	// successful credential check and admission into an authenticated session.
	earlier, err := s.authorize(wire)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveUser(ctx, user.Email); err != nil {
		t.Fatal(err)
	}
	// Re-adding exactly the same credentials must create a distinct admission
	// generation; changing only the password would not exercise this race.
	if err := s.AddUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	current, err := s.authorize(wire)
	if err != nil {
		t.Fatal(err)
	}
	if earlier == current {
		t.Fatal("same-key re-add reused revoked account generation")
	}
	if _, err := s.admit(run, wire, earlier); err == nil {
		t.Fatal("handshake authenticated before revocation joined the replacement account")
	}
	if admitted, err := s.admit(run, wire, current); err != nil || admitted != current {
		t.Fatal("fresh authentication could not join the replacement account", err)
	}
	if err := s.RemoveUser(ctx, user.Email); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() != context.Canceled {
		t.Fatal("revocation did not cancel the newly admitted generation")
	}
}

type d11OrbitGenerationPeer struct {
	serverPeer // Unused operations intentionally have no implementation.
	wire       protocol.UserInfo
	id         [16]byte
}

func (p *d11OrbitGenerationPeer) User() protocol.UserInfo { return p.wire }
func (p *d11OrbitGenerationPeer) ChannelID() [16]byte     { return p.id }

func TestD11OrbitSameKeyReaddCannotReuseRevokedChannel(t *testing.T) {
	s, user, wire := d11OrbitGenerationFixture(t)
	ctx := context.Background()
	earlier, err := s.authorize(wire)
	if err != nil {
		t.Fatal(err)
	}
	id := [16]byte{1, 2, 3, 4}
	oldPeer := &d11OrbitGenerationPeer{wire: wire, id: id}
	oldChannel := s.attachPeer(ctx, oldPeer, earlier)
	defer s.detachPeer(oldChannel, oldPeer)
	if err := s.RemoveUser(ctx, user.Email); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	current, err := s.authorize(wire)
	if err != nil {
		t.Fatal(err)
	}
	newPeer := &d11OrbitGenerationPeer{wire: wire, id: id}
	newChannel := s.attachPeer(ctx, newPeer, current)
	defer s.detachPeer(newChannel, newPeer)
	if newChannel == oldChannel || newChannel.user != current || oldChannel.user != earlier {
		t.Fatal("replacement account inherited the revoked generation's channel/UDP mappings")
	}
	// Ordinary rotation within the current generation must still share its
	// channel, preserving the existing connection-rotation behavior.
	rotatedPeer := &d11OrbitGenerationPeer{wire: wire, id: id}
	rotatedChannel := s.attachPeer(ctx, rotatedPeer, current)
	defer s.detachPeer(rotatedChannel, rotatedPeer)
	if rotatedChannel != newChannel {
		t.Fatal("current account generation could not share its channel")
	}
}
