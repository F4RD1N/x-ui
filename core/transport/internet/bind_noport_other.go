//go:build !linux

package internet

func setBindAddressNoPort(fd uintptr) error {
	return nil
}
