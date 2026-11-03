// Package router encodes the recovered FlatBuffers discovery schema. Wire
// envelopes and userinfo encryption live in package protocol.
package router

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/xtls/xray-core/proxy/orbit/internal/protocol"
)

const MaxBufferSize = protocol.MaxRouterDecoded

var ErrMalformed = errors.New("router: malformed FlatBuffer")

type Request struct {
	Attempt  int32
	Group    string
	Metadata uint32
	Option   bool
}

// Metadata is an opaque four-byte value, not a proxy protocol identifier.
type NetworkAddress struct {
	Metadata uint32
	Port     uint16
	Kind     byte
	Address  []byte
}

func NetworkAddressFromProtocol(a protocol.Address, metadata uint32) NetworkAddress {
	n := 128
	switch a.Kind {
	case 1:
		n = 4
	case 2:
		n = 16
	default:
		if i := bytes.IndexByte(a.Storage[:], 0); i >= 0 {
			n = i
		}
	}
	return NetworkAddress{Metadata: metadata, Port: a.Port, Kind: a.Kind, Address: append([]byte(nil), a.Storage[:n]...)}
}

// ProtocolAddress matches parse_flat_address: zero the destination storage and
// copy no more than 127 bytes, regardless of the vector's encoded length.
func (a NetworkAddress) ProtocolAddress() protocol.Address {
	p := protocol.Address{Kind: a.Kind, Port: a.Port}
	copy(p.Storage[:127], a.Address)
	return p
}

type PingAddrInfo struct {
	Port                uint16
	Kind                byte
	Address, Parameters []byte
}
type PingPathInfo struct {
	Kind byte
	Info *PingAddrInfo
}
type AdPath struct {
	Addresses            []NetworkAddress
	TCPType, UDPType     uint16
	TCPParams, UDPParams []byte
	Field5, Field6       uint16
	Field7, Field8       []byte
	Flag9                bool
}
type Response struct {
	Status               uint16
	Addresses            []NetworkAddress
	TCPType, UDPType     uint16
	TCPParams, UDPParams []byte
	Field6, Field7       uint16 // TCP connection count and UDP enable count.
	Field8, Field9       []byte // Independent TCP and UDP proxy paths.
	PingPaths            []PingPathInfo
	Flag11               bool   // Prefer TCP when both transports are ready.
	Field12              uint16 // Member level copied into channel user info.
	AdPath               *AdPath
	ExtraAddress         *NetworkAddress
}

// ValidateUsable applies the observed discovery success condition, separately
// from FlatBuffer validity. A valid table alone does not represent a live path.
func (r Response) ValidateUsable() error {
	if r.Status != 1 {
		return fmt.Errorf("router: response status %d", r.Status)
	}
	if len(r.Addresses) == 0 {
		return errors.New("router: success response has no endpoints (reference status 509)")
	}
	for _, a := range r.Addresses {
		if a.Port == 0 {
			return errors.New("router: endpoint port is zero")
		}
		if _, err := a.ProtocolAddress().Host(); err != nil {
			return fmt.Errorf("router: endpoint address: %w", err)
		}
	}
	return nil
}
