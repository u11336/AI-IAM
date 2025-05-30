package utils_test

import (
	"testing"

	"github.com/u11336/ai-iam/internal/utils"
)

func TestIsValidEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected bool
	}{
		{"user@example.com", true},
		{"user.name@example.com", true},
		{"user+tag@example.com", true},
		{"user@sub.example.com", true},
		{"user@example.co.uk", true},
		{"", false},
		{"user", false},
		{"user@", false},
		{"@example.com", false},
		{"user@.com", false},
		{"user@example", false},
		{"user@example.", false},
		{"user@exam ple.com", false},
	}

	for _, test := range tests {
		t.Run(test.email, func(t *testing.T) {
			result := utils.IsValidEmail(test.email)
			if result != test.expected {
				t.Errorf("IsValidEmail(%q) = %v, expected %v", test.email, result, test.expected)
			}
		})
	}
}

func TestIsStrongPassword(t *testing.T) {
	tests := []struct {
		password string
		expected bool
	}{
		{"", false},
		{"password", false},        // No uppercase, digits, or special chars
		{"Password", false},        // No digits or special chars
		{"Password1", false},       // No special chars
		{"password1!", false},      // No uppercase
		{"PASSWORD1!", false},      // No lowercase
		{"Password!", false},       // No digits
		{"Pa1!", false},            // Too short
		{"Password1!", true},       // Valid
		{"StrongP@ssw0rd", true},   // Valid
		{"C0mpl3x!P@ssw0rd", true}, // Valid
	}

	for _, test := range tests {
		t.Run(test.password, func(t *testing.T) {
			result := utils.IsStrongPassword(test.password)
			if result != test.expected {
				t.Errorf("IsStrongPassword(%q) = %v, expected %v", test.password, result, test.expected)
			}
		})
	}
}

func TestSanitizeUsername(t *testing.T) {
	tests := []struct {
		username string
		expected string
	}{
		{"user", "user"},
		{"User", "user"},
		{"user_name", "user_name"},
		{"user.name", "user_name"},
		{"user-name", "user_name"},
		{"user@name", "user_name"},
		{"user name", "user_name"},
		{"user+name", "user_name"},
		{"user123", "user123"},
		{"123user", "123user"},
		{"user!@#$%^&*()", "user__________"},
	}

	for _, test := range tests {
		t.Run(test.username, func(t *testing.T) {
			result := utils.SanitizeUsername(test.username)
			if result != test.expected {
				t.Errorf("SanitizeUsername(%q) = %q, expected %q", test.username, result, test.expected)
			}
		})
	}
}

func TestGenerateRandomString(t *testing.T) {
	lengths := []int{8, 16, 32, 64}

	for _, length := range lengths {
		t.Run("Length_"+string(rune(length)), func(t *testing.T) {
			result, err := utils.GenerateRandomString(length)
			if err != nil {
				t.Fatalf("GenerateRandomString(%d) returned error: %v", length, err)
			}

			if len(result) != length {
				t.Errorf("GenerateRandomString(%d) returned string of length %d, expected %d", length, len(result), length)
			}

			// Generate another string to ensure they're different (check for randomness)
			result2, err := utils.GenerateRandomString(length)
			if err != nil {
				t.Fatalf("Second GenerateRandomString(%d) returned error: %v", length, err)
			}

			if result == result2 {
				t.Errorf("Generated strings are identical: %q and %q. Expected different values", result, result2)
			}
		})
	}
}

func TestGenerateAPIKey(t *testing.T) {
	key, err := utils.GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey() returned error: %v", err)
	}

	// Check format: XXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
	if len(key) != 33 { // 32 chars + 4 hyphens
		t.Errorf("Generated API key has incorrect length: %d, expected 33", len(key))
	}

	if key[4] != '-' || key[9] != '-' || key[14] != '-' || key[19] != '-' {
		t.Errorf("Generated API key has incorrect format: %s", key)
	}

	// Generate another key to ensure they're different
	key2, err := utils.GenerateAPIKey()
	if err != nil {
		t.Fatalf("Second GenerateAPIKey() returned error: %v", err)
	}

	if key == key2 {
		t.Errorf("Generated API keys are identical: %q and %q. Expected different values", key, key2)
	}
}
