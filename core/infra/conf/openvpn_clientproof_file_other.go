//go:build !unix

package conf

import "os"

func openOpenVPNProofFile(name string) (*os.File, error) {
	// The caller also checks regular-file type and inode stability.
	return os.Open(name)
}
