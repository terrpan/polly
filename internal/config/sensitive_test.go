package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureString(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected string
	}{
		{
			name:     "empty string",
			value:    "",
			expected: "[REDACTED]",
		},
		{
			name:     "short string",
			value:    "abc",
			expected: "[REDACTED]",
		},
		{
			name:     "normal password",
			value:    "my-secret-password",
			expected: "[REDACTED]",
		},
		{
			name:     "long token",
			value:    "ghp_1234567890abcdef1234567890abcdef12345678",
			expected: "[REDACTED]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secureStr := NewSecureString(tt.value)

			// String() method should always return [REDACTED]
			assert.Equal(t, tt.expected, secureStr.String())

			// Value() method should return the original value
			assert.Equal(t, tt.value, secureStr.Value())
		})
	}
}

func TestSecureString_JSONMarshaling(t *testing.T) {
	tests := []struct {
		name             string
		value            string
		expectedJSON     string
		shouldContain    []string
		shouldNotContain []string
	}{
		{
			name:             "empty string",
			value:            "",
			expectedJSON:     `"[REDACTED]"`,
			shouldContain:    []string{"REDACTED"},
			shouldNotContain: []string{``}, // empty string should not appear
		},
		{
			name:             "password",
			value:            "secret123",
			expectedJSON:     `"[REDACTED]"`,
			shouldContain:    []string{"REDACTED"},
			shouldNotContain: []string{"secret123"},
		},
		{
			name:             "github token",
			value:            "ghp_abcd1234",
			expectedJSON:     `"[REDACTED]"`,
			shouldContain:    []string{"REDACTED"},
			shouldNotContain: []string{"ghp_", "abcd1234"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secureStr := NewSecureString(tt.value)

			// Test direct marshaling
			jsonBytes, err := json.Marshal(secureStr)
			require.NoError(t, err)

			jsonStr := string(jsonBytes)
			assert.Equal(t, tt.expectedJSON, jsonStr)

			// Verify sensitive data is not present in JSON
			for _, shouldContain := range tt.shouldContain {
				assert.Contains(t, jsonStr, shouldContain)
			}

			for _, shouldNotContain := range tt.shouldNotContain {
				if shouldNotContain != "" { // Skip empty string check
					assert.NotContains(t, jsonStr, shouldNotContain)
				}
			}
		})
	}
}

func TestSecureString_InStructMarshaling(t *testing.T) {
	type TestConfig struct {
		Username string       `json:"username"`
		Password SecureString `json:"password"`
		Token    SecureString `json:"token"`
	}

	config := TestConfig{
		Username: "admin",
		Password: NewSecureString("my-secret-password"),
		Token:    NewSecureString("ghp_1234567890abcdef"),
	}

	jsonBytes, err := json.Marshal(config)
	require.NoError(t, err)

	jsonStr := string(jsonBytes)

	// Should contain non-sensitive data
	assert.Contains(t, jsonStr, "admin")
	assert.Contains(t, jsonStr, "REDACTED")

	// Should not contain sensitive data
	assert.NotContains(t, jsonStr, "my-secret-password")
	assert.NotContains(t, jsonStr, "ghp_1234567890abcdef")

	// Verify JSON structure
	var unmarshaled map[string]interface{}
	err = json.Unmarshal(jsonBytes, &unmarshaled)
	require.NoError(t, err)

	assert.Equal(t, "admin", unmarshaled["username"])
	assert.Equal(t, "[REDACTED]", unmarshaled["password"])
	assert.Equal(t, "[REDACTED]", unmarshaled["token"])
}

func TestSecureString_EdgeCases(t *testing.T) {
	t.Run("zero value handling", func(t *testing.T) {
		var secureStr SecureString

		// These should not panic
		assert.Equal(t, "[REDACTED]", secureStr.String())
		assert.Equal(t, "", secureStr.Value())

		// JSON marshaling of zero value should work
		jsonBytes, err := json.Marshal(secureStr)
		require.NoError(t, err)
		assert.Equal(t, `"[REDACTED]"`, string(jsonBytes))
	})

	t.Run("unicode and special characters", func(t *testing.T) {
		testCases := []string{
			"pässwörd123",
			"🔑secret🔐",
			"密码123",
			"пароль456",
			"contraseña789",
			"password\nwith\nnewlines",
			"password\twith\ttabs",
		}

		for _, testCase := range testCases {
			secureStr := NewSecureString(testCase)

			// Should always redact, regardless of content
			assert.Equal(t, "[REDACTED]", secureStr.String())
			assert.Equal(t, testCase, secureStr.Value())

			// JSON marshaling should not leak sensitive data
			jsonBytes, err := json.Marshal(secureStr)
			require.NoError(t, err)
			assert.Equal(t, `"[REDACTED]"`, string(jsonBytes))
			assert.NotContains(t, string(jsonBytes), testCase)
		}
	})
}

func TestSecureString_ZeroValue(t *testing.T) {
	var secureStr SecureString

	// Zero value should behave consistently
	assert.Equal(t, "[REDACTED]", secureStr.String())
	assert.Equal(t, "", secureStr.Value())

	// JSON marshaling of zero value
	jsonBytes, err := json.Marshal(secureStr)
	require.NoError(t, err)
	assert.Equal(t, `"[REDACTED]"`, string(jsonBytes))
}

func TestNewSecureString(t *testing.T) {
	value := "test-password"
	secureStr := NewSecureString(value)

	// Should not be nil
	assert.NotNil(t, secureStr)

	// Should store the value correctly
	assert.Equal(t, value, secureStr.Value())
	assert.Equal(t, "[REDACTED]", secureStr.String())
}

// TestSecureString_RealWorldScenarios tests realistic usage patterns
func TestSecureString_RealWorldScenarios(t *testing.T) {
	t.Run("database configuration", func(t *testing.T) {
		type DBConfig struct {
			Host     string       `json:"host"`
			Port     int          `json:"port"`
			Username string       `json:"username"`
			Password SecureString `json:"password"`
		}

		config := DBConfig{
			Host:     "localhost",
			Port:     5432,
			Username: "postgres",
			Password: NewSecureString("super-secret-db-password"),
		}

		// Serialize to JSON (e.g., for logging or config export)
		configJSON, err := json.Marshal(config)
		require.NoError(t, err)

		configStr := string(configJSON)

		// Verify non-sensitive data is present
		assert.Contains(t, configStr, "localhost")
		assert.Contains(t, configStr, "5432")
		assert.Contains(t, configStr, "postgres")

		// Verify sensitive data is redacted
		assert.Contains(t, configStr, "[REDACTED]")
		assert.NotContains(t, configStr, "super-secret-db-password")
	})

	t.Run("github client configuration", func(t *testing.T) {
		type GitHubConfig struct {
			BaseURL string       `json:"base_url"`
			Token   SecureString `json:"token"`
			Timeout int          `json:"timeout"`
		}

		config := GitHubConfig{
			BaseURL: "https://api.github.com",
			Token:   NewSecureString("ghp_abcdef1234567890"),
			Timeout: 30,
		}

		configJSON, err := json.Marshal(config)
		require.NoError(t, err)

		configStr := string(configJSON)

		// Non-sensitive data should be present
		assert.Contains(t, configStr, "https://api.github.com")
		assert.Contains(t, configStr, "30")

		// Sensitive token should be redacted
		assert.Contains(t, configStr, "[REDACTED]")
		assert.NotContains(t, configStr, "ghp_")
		assert.NotContains(t, configStr, "abcdef1234567890")
	})
}
