package ss2022

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateKey generates a cryptographically random PSK of keySize bytes
// and returns it as a base64-encoded string ready for use.
// keySize must be 16 (for 2022-blake3-aes-128-gcm)
//             or 32 (for 2022-blake3-aes-256-gcm).
func GenerateKey(keySize int) (string, error) {
	if keySize != 16 && keySize != 32 {
		return "", fmt.Errorf("ss2022: key size must be 16 or 32, got %d", keySize)
	}
	raw := make([]byte, keySize)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// decodeKey decodes a base64 PSK string and checks the expected length.
// Internal helper shared across the package.
func decodeKey(b64Key string, expectedSize int) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(b64Key)
	if err != nil {
		return nil, fmt.Errorf("ss2022: base64 decode failed: %w", err)
	}
	if len(raw) != expectedSize {
		return nil, fmt.Errorf("ss2022: key must be %d bytes, got %d", expectedSize, len(raw))
	}
	return raw, nil
}
