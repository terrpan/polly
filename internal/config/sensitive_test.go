package config

import (
	"encoding/json"
	"fmt"
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
			Username string       `json:"username"`
			Password SecureString `json:"password"`
			Port     int          `json:"port"`
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

// TestSensitivePatternDetection tests the pattern-based sensitive data detection
func TestSensitivePatternDetection(t *testing.T) {
	t.Run("isSensitiveField detects various patterns", func(t *testing.T) {
		testCases := []struct {
			name      string
			value     string
			sensitive bool
		}{
			// Password patterns
			{"password field", "password", true},
			{"Password field", "Password", true},
			{"PASSWORD field", "PASSWORD", true},
			{"userPassword", "userPassword", true},
			{"db_password", "db_password", true},
			{"passwordHash", "passwordHash", true},

			// Secret patterns
			{"secret field", "secret", true},
			{"Secret field", "Secret", true},
			{"SECRET field", "SECRET", true},
			{"apiSecret", "apiSecret", true},
			{"client_secret", "client_secret", true},
			{"secretKey", "secretKey", true},

			// Key patterns
			{"key field", "key", true},
			{"Key field", "Key", true},
			{"KEY field", "KEY", true},
			{"privateKey", "privateKey", true},
			{"api_key", "api_key", true},
			{"keyPair", "keyPair", true},

			// Token patterns
			{"token field", "token", true},
			{"Token field", "Token", true},
			{"TOKEN field", "TOKEN", true},
			{"accessToken", "accessToken", true},
			{"auth_token", "auth_token", true},
			{"tokenValue", "tokenValue", true},

			// PEM private key pattern
			{"PEM private key", "-----BEGIN PRIVATE KEY-----", true},
			{"RSA private key", "-----BEGIN RSA PRIVATE KEY-----", true},
			{"EC private key", "-----BEGIN EC PRIVATE KEY-----", true},

			// Non-sensitive patterns
			{"username", "username", false},
			{"email", "email", false},
			{"hostname", "hostname", false},
			{"port", "port", false},
			{"timeout", "timeout", false},
			{"empty string", "", false},
			{"random text", "hello world", false},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := isSensitiveField(tc.value)
				assert.Equal(
					t,
					tc.sensitive,
					result,
					"Pattern '%s' should be sensitive=%t but got %t",
					tc.value,
					tc.sensitive,
					result,
				)
			})
		}
	})
}

// TestSanitizeConfigForLogging tests configuration sanitization
func TestSanitizeConfigForLogging(t *testing.T) {
	t.Run("sanitizes sensitive fields in config", func(t *testing.T) {
		// Create a test config with various field types
		testConfig := &Config{
			Logger: LoggerConfig{
				Level: "info",
			},
			GitHubApp: GitHubAppConfig{
				PrivateKey: NewSecureString("test-private-key"),
			},
			GitHubToken: NewSecureString("ghp_test_token"),
			Storage: StorageConfig{
				Type: "valkey",
				Valkey: ValkeyConfig{
					Address:  "localhost:6379",
					Password: NewSecureString("redis_password"),
				},
			},
		}

		result := SanitizeConfigForLogging(testConfig)

		// Verify structure is present
		require.NotNil(t, result)
		require.Contains(t, result, "Logger")
		require.Contains(t, result, "GitHubApp")
		require.Contains(t, result, "Storage")

		// Verify non-sensitive data is preserved
		loggerMap := result["Logger"].(map[string]interface{})
		assert.Equal(t, "info", loggerMap["Level"])

		// Verify SecureString fields are handled properly
		githubAppMap := result["GitHubApp"].(map[string]interface{})
		// SecureString should be handled by its own MarshalJSON method
		assert.NotContains(t, fmt.Sprintf("%v", githubAppMap), "test-private-key")

		// Verify GitHubToken field is handled
		assert.NotContains(t, fmt.Sprintf("%v", result), "ghp_test_token")
	})
}

// TestSanitizeError tests error message sanitization
func TestSanitizeError(t *testing.T) {
	testCases := []struct {
		name             string
		inputError       error
		shouldContain    []string
		shouldNotContain []string
	}{
		{
			name:             "nil error",
			inputError:       nil,
			shouldContain:    nil,
			shouldNotContain: nil,
		},
		{
			name: "error with password parameter",
			inputError: fmt.Errorf(
				"connection failed: redis://user:password=secret123@localhost:6379",
			),
			shouldContain: []string{
				"connection failed",
				"redis://",
				"@localhost:6379",
				"password=[REDACTED]",
			},
			shouldNotContain: []string{"secret123", "password=secret123"},
		},
		{
			name: "error with token parameter",
			inputError: fmt.Errorf(
				"API request failed: GET /api/data?token=ghp_abcdef123456",
			),
			shouldContain:    []string{"API request failed", "GET /api/data", "token=[REDACTED]"},
			shouldNotContain: []string{"ghp_abcdef123456", "token=ghp_abcdef123456"},
		},
		{
			name:             "error with key parameter",
			inputError:       fmt.Errorf("encryption failed with key=mySecretKey123"),
			shouldContain:    []string{"encryption failed", "key=[REDACTED]"},
			shouldNotContain: []string{"mySecretKey123", "key=mySecretKey123"},
		},
		{
			name:             "error with secret parameter",
			inputError:       fmt.Errorf("auth failed: secret=topsecret456"),
			shouldContain:    []string{"auth failed", "secret=[REDACTED]"},
			shouldNotContain: []string{"topsecret456", "secret=topsecret456"},
		},
		{
			name: "error with PEM private key",
			inputError: fmt.Errorf(
				"key parsing failed: -----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+\n-----END PRIVATE KEY-----",
			),
			shouldContain: []string{"key parsing failed", "[REDACTED_PRIVATE_KEY]"},
			shouldNotContain: []string{
				"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC+",
				"BEGIN PRIVATE KEY",
			},
		},
		{
			name:             "error without sensitive data",
			inputError:       fmt.Errorf("connection timeout: could not reach localhost:8080"),
			shouldContain:    []string{"connection timeout", "localhost:8080"},
			shouldNotContain: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := SanitizeError(tc.inputError)

			if tc.inputError == nil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			resultStr := result.Error()

			for _, shouldContain := range tc.shouldContain {
				assert.Contains(t, resultStr, shouldContain,
					"Sanitized error should contain '%s' but got: %s", shouldContain, resultStr)
			}

			for _, shouldNotContain := range tc.shouldNotContain {
				assert.NotContains(
					t,
					resultStr,
					shouldNotContain,
					"Sanitized error should NOT contain '%s' but got: %s",
					shouldNotContain,
					resultStr,
				)
			}
		})
	}
}

// TestSanitizeString tests string sanitization patterns
func TestSanitizeString(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		expectedOutput   string
		shouldContain    []string
		shouldNotContain []string
	}{
		{
			name:           "multiple sensitive parameters",
			input:          "failed to connect: redis://user:password=secret123@host?token=abc&key=def&secret=ghi",
			expectedOutput: "failed to connect: redis://user:password=[REDACTED]@host?token=[REDACTED]&key=[REDACTED]&secret=[REDACTED]",
			shouldContain: []string{
				"password=[REDACTED]",
				"token=[REDACTED]",
				"key=[REDACTED]",
				"secret=[REDACTED]",
			},
			shouldNotContain: []string{"secret123", "abc", "def", "ghi"},
		},
		{
			name:             "PEM private key in log message",
			input:            "failed to parse: -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA123...\n-----END RSA PRIVATE KEY-----",
			expectedOutput:   "failed to parse: [REDACTED_PRIVATE_KEY]",
			shouldContain:    []string{"failed to parse", "[REDACTED_PRIVATE_KEY]"},
			shouldNotContain: []string{"BEGIN RSA PRIVATE KEY", "MIIEpAIBAAKCAQEA123"},
		},
		{
			name:           "URL with password",
			input:          "database connection string: postgresql://user:password=dbpass123@localhost:5432/mydb",
			expectedOutput: "database connection string: postgresql://user:password=[REDACTED]@localhost:5432/mydb",
			shouldContain: []string{
				"postgresql://user:",
				"password=[REDACTED]",
				"@localhost:5432/mydb",
			},
			shouldNotContain: []string{"dbpass123", "password=dbpass123"},
		},
		{
			name:             "no sensitive data",
			input:            "regular log message with hostname=localhost port=8080 status=ok",
			expectedOutput:   "regular log message with hostname=localhost port=8080 status=ok",
			shouldContain:    []string{"hostname=localhost", "port=8080", "status=ok"},
			shouldNotContain: nil,
		},
		{
			name:             "empty string",
			input:            "",
			expectedOutput:   "",
			shouldContain:    nil,
			shouldNotContain: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := sanitizeString(tc.input)
			assert.Equal(t, tc.expectedOutput, result)

			for _, shouldContain := range tc.shouldContain {
				assert.Contains(t, result, shouldContain)
			}

			for _, shouldNotContain := range tc.shouldNotContain {
				assert.NotContains(t, result, shouldNotContain)
			}
		})
	}
}
