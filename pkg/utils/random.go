package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateSecureRandomString generates a cryptographically secure random string of the specified length.
// The resulting string is URL-safe.
func GenerateSecureRandomString(length int) (string, error) {
	// Calculate the number of bytes needed to generate a string of the desired length
	// when encoded in base64.
	// base64 encoding: 4 characters for every 3 bytes
	byteLength := length * 3 / 4

	randomBytes := make([]byte, byteLength)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("error generating random bytes: %v", err)
	}

	// Encode the random bytes to base64
	encoded := base64.URLEncoding.EncodeToString(randomBytes)

	// Trim the encoded string to the desired length
	return encoded[:length], nil
}
