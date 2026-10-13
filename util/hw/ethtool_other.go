//go:build !linux

package hw

// SystemEthtool has no devices to talk to outside Linux.
func SystemEthtool() Ethtool { return NoEthtool{} }
