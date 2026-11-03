//go:build !linux && !darwin

package openvpn

import (
	goerrors "errors"
	"syscall"
)

// setNotSentLowat is not available here: the socket keeps its default.
func setNotSentLowat(syscall.RawConn, int) error {
	return goerrors.New("TCP_NOTSENT_LOWAT is not supported on this system")
}
