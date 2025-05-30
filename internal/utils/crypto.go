package utils

import (
	"crypto/rand"
	"encoding/base64"
	"net/mail"
	"regexp"
	"strings"
)

// Constants for validation
const (
	// MinPasswordLength is the minimum password length
	MinPasswordLength = 8
)

// IsValidEmail validates an email address
func IsValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

// IsStrongPassword checks if a password meets the minimum security requirements
func IsStrongPassword(password string) bool {
	if len(password) < MinPasswordLength {
		return false
	}

	// Check for at least one uppercase letter
	uppercase := regexp.MustCompile(`[A-Z]`)
	if !uppercase.MatchString(password) {
		return false
	}

	// Check for at least one lowercase letter
	lowercase := regexp.MustCompile(`[a-z]`)
	if !lowercase.MatchString(password) {
		return false
	}

	// Check for at least one number
	number := regexp.MustCompile(`[0-9]`)
	if !number.MatchString(password) {
		return false
	}

	// Check for at least one special character
	special := regexp.MustCompile(`[^A-Za-z0-9]`)
	if !special.MatchString(password) {
		return false
	}

	return true
}

// SanitizeUsername removes unwanted characters from a username
func SanitizeUsername(username string) string {
	// Replace spaces and special characters with underscores
	re := regexp.MustCompile(`[^a-zA-Z0-9_]`)
	sanitized := re.ReplaceAllString(username, "_")

	// Convert to lowercase
	sanitized = strings.ToLower(sanitized)

	return sanitized
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// GenerateRandomString generates a random string of the specified length
func GenerateRandomString(length int) (string, error) {
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// GenerateAPIKey generates a random API key
func GenerateAPIKey() (string, error) {
	// Generate 32 bytes (256 bits) of random data
	bytes, err := GenerateRandomBytes(32)
	if err != nil {
		return "", err
	}

	// Encode as base64
	key := base64.URLEncoding.EncodeToString(bytes)

	// Format the key as a UUID-like string for easier reading
	// Format: XXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
	formattedKey := key[:4] + "-" + key[4:8] + "-" + key[8:12] + "-" + key[12:16] + "-" + key[16:28]

	return formattedKey, nil
}
