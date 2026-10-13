package hw

import "errors"

var (
	// ErrNotSupported: the device or driver does not have the setting
	// (EOPNOTSUPP, or EINVAL on a get). The errno stays in the chain.
	ErrNotSupported = errors.New("not supported")
	// ErrBusy: the device refused for now (EBUSY). The errno stays in the
	// chain.
	ErrBusy = errors.New("device busy")
)

// DrvInfo is ETHTOOL_GDRVINFO.
type DrvInfo struct{ Driver, Version, Firmware, BusInfo string }

// Flow is an ethtool flow type for the RX flow hash.
type Flow uint32

const (
	FlowTCP4 Flow = 1 // TCP_V4_FLOW
	FlowUDP4 Flow = 2 // UDP_V4_FLOW
	FlowTCP6 Flow = 5 // TCP_V6_FLOW
	FlowUDP6 Flow = 6 // UDP_V6_FLOW
)

// String is the flow's key in NIC.Hash ("tcp4", "udp4", "tcp6", "udp6").
func (f Flow) String() string {
	switch f {
	case FlowTCP4:
		return "tcp4"
	case FlowUDP4:
		return "udp4"
	case FlowTCP6:
		return "tcp6"
	case FlowUDP6:
		return "udp6"
	}
	return "flow?"
}

// HashFlows are the flows NIC.Hash reports, in order.
var HashFlows = []Flow{FlowTCP4, FlowUDP4, FlowTCP6, FlowUDP6}

// Ethtool is the SIOCETHTOOL interface x-ui uses. Getters answer
// ErrNotSupported when the device does not have the setting.
type Ethtool interface {
	DrvInfo(dev string) (DrvInfo, error)
	Channels(dev string) (Channels, error)
	// SetChannels sets the queue counts. c is what Channels returned with
	// only the counts changed. Most drivers reset the link to do it.
	SetChannels(dev string, c Channels) error
	RxRings(dev string) (int, error)
	Indir(dev string) ([]uint32, error)
	// SetIndir writes the RSS indirection table; nil (size 0) restores the
	// driver's default and clears the "configured by the user" flag.
	SetIndir(dev string, table []uint32) error
	FlowHash(dev string, f Flow) (uint64, error)
	SetFlowHash(dev string, f Flow, bits uint64) error
	Stats(dev string) (map[string]uint64, error)
	Features(dev string) (map[string]bool, error)
}

// NoEthtool answers ErrNotSupported to everything: no device has ethtool
// settings (the default under a fake root).
type NoEthtool struct{}

func (NoEthtool) DrvInfo(string) (DrvInfo, error)          { return DrvInfo{}, ErrNotSupported }
func (NoEthtool) Channels(string) (Channels, error)        { return Channels{}, ErrNotSupported }
func (NoEthtool) SetChannels(string, Channels) error       { return ErrNotSupported }
func (NoEthtool) RxRings(string) (int, error)              { return 0, ErrNotSupported }
func (NoEthtool) Indir(string) ([]uint32, error)           { return nil, ErrNotSupported }
func (NoEthtool) SetIndir(string, []uint32) error          { return ErrNotSupported }
func (NoEthtool) FlowHash(string, Flow) (uint64, error)    { return 0, ErrNotSupported }
func (NoEthtool) SetFlowHash(string, Flow, uint64) error   { return ErrNotSupported }
func (NoEthtool) Stats(string) (map[string]uint64, error)  { return nil, ErrNotSupported }
func (NoEthtool) Features(string) (map[string]bool, error) { return nil, ErrNotSupported }
