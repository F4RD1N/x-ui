package trojan

import "github.com/google/uuid"

// uuidPrefixedKey keeps the ordinary 56-byte lowercase hexadecimal SHA224
// key, replacing its first 16 bytes with the raw UUID only when the original
// password parses as a UUID. Password spelling still participates in SHA224.
// Non-UUID passwords retain the ordinary key, matching the existing client.
func uuidPrefixedKey(password string) []byte {
	key := hexSha224(password)
	if id, err := uuid.Parse(password); err == nil {
		copy(key[:16], id[:])
	}
	return key
}
