package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateSecureRandomString generates a cryptographically secure random string of the specified length.
// The resulting string is URL-safe.
func GenerateSecureRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("error generating random bytes: %v", err)
	}

	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}
