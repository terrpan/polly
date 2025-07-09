package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Structure(t *testing.T) {
	cfg := &Config{
		Port: 8080,
		GitHubApp: GitHubAppConfig{
			AppID:          12345,
			InstallationID: 67890,
			PrivateKeyPath: "/path/to/key",
		},
		GitHubToken: "test-token",
		Version:     "1.0.0",
		Commit:      "abc123",
		BuildTime:   "2025-01-01T00:00:00Z",
	}

	assert.Equal(t, 8080, cfg.Port)
	assert.Equal(t, int64(12345), cfg.GitHubApp.AppID)
	assert.Equal(t, "test-token", cfg.GitHubToken)
	assert.Equal(t, "1.0.0", cfg.Version)
}

func TestGitHubAppConfig_Structure(t *testing.T) {
	githubConfig := GitHubAppConfig{
		AppID:          123,
		InstallationID: 456,
		PrivateKeyPath: "/path/to/private/key",
		PrivateKey:     "-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----",
	}

	assert.Equal(t, int64(123), githubConfig.AppID)
	assert.Equal(t, int64(456), githubConfig.InstallationID)
	assert.Equal(t, "/path/to/private/key", githubConfig.PrivateKeyPath)
	assert.Contains(t, githubConfig.PrivateKey, "PRIVATE KEY")
}

func TestGetDefaultConfig(t *testing.T) {
	cfg := GetDefaultConfig()

	require.NotNil(t, cfg)
	assert.Equal(t, 8080, cfg.Port)
	assert.Equal(t, "debug", cfg.Logger.Level)
	assert.True(t, cfg.Logger.JSONOutput)
}

func TestGetBuildInfo(t *testing.T) {
	version, commit, buildTime := GetBuildInfo()

	// These values are set at build time, so they may be empty in tests
	assert.IsType(t, "", version)
	assert.IsType(t, "", commit)
	assert.IsType(t, "", buildTime)
}

func TestLoggerConfig_Structure(t *testing.T) {
	loggerConfig := LoggerConfig{
		Level:      "debug",
		JSONOutput: true,
		AddSource:  false,
	}

	assert.Equal(t, "debug", loggerConfig.Level)
	assert.True(t, loggerConfig.JSONOutput)
	assert.False(t, loggerConfig.AddSource)
}

func TestOpaConfig_Structure(t *testing.T) {
	opaConfig := OpaConfig{
		ServerURL:  "http://localhost:8181",
		PolicyPath: "/v1/policies",
	}

	assert.Equal(t, "http://localhost:8181", opaConfig.ServerURL)
	assert.Equal(t, "/v1/policies", opaConfig.PolicyPath)
}

func TestOTLPConfig_Structure(t *testing.T) {
	otlpConfig := OTLPConfig{
		EnableOTLP: true,
		OTLPStdOut: false,
	}

	assert.True(t, otlpConfig.EnableOTLP)
	assert.False(t, otlpConfig.OTLPStdOut)
}

func TestIsGitHubAppConfigured(t *testing.T) {
	// Save original AppConfig to restore later
	originalAppConfig := AppConfig
	defer func() {
		AppConfig = originalAppConfig
	}()
	
	tests := []struct {
		name     string
		setup    func()
		expected bool
	}{
		{
			name: "app configured with all required fields",
			setup: func() {
				AppConfig = &Config{
					GitHubApp: GitHubAppConfig{
						AppID:          123,
						InstallationID: 456,
						PrivateKey:     "test-key",
					},
				}
			},
			expected: true,
		},
		{
			name: "app not configured - missing app id",
			setup: func() {
				AppConfig = &Config{
					GitHubApp: GitHubAppConfig{
						AppID:          0,
						InstallationID: 456,
						PrivateKey:     "test-key",
					},
				}
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setup()
			result := IsGitHubAppConfigured()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_DefaultValues(t *testing.T) {
	// Test that default configuration values are reasonable
	cfg := GetDefaultConfig()
	
	assert.Equal(t, 8080, cfg.Port)
	assert.Equal(t, "v0.0.1", cfg.Version)
	assert.Equal(t, "debug", cfg.Logger.Level)
	assert.True(t, cfg.Logger.JSONOutput)
	assert.False(t, cfg.Logger.AddSource)
	assert.Equal(t, "http://localhost:8181", cfg.Opa.ServerURL)
	assert.Equal(t, "/v1/policies", cfg.Opa.PolicyPath)
	assert.True(t, cfg.OTLP.EnableOTLP)
	assert.False(t, cfg.OTLP.OTLPStdOut)
}

func TestConfig_FieldValidation(t *testing.T) {
	// Test config field validation
	cfg := &Config{
		Port: 8080,
		GitHubToken: "test-token",
		Version: "1.0.0",
	}
	
	assert.Greater(t, cfg.Port, 0)
	assert.NotEmpty(t, cfg.GitHubToken)
	assert.NotEmpty(t, cfg.Version)
}

func TestLoadGitHubAppConfig_PrivateKeyHandling(t *testing.T) {
	// Save original AppConfig to restore later
	originalAppConfig := AppConfig
	defer func() {
		AppConfig = originalAppConfig
	}()
	
	// Test with missing AppID
	AppConfig = &Config{
		GitHubApp: GitHubAppConfig{
			AppID: 0,
		},
	}
	
	_, err := LoadGitHubAppConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GITHUB_APP_ID is required")
}

// Integration test examples - these would require environment setup
func TestConfig_IntegrationExamples(t *testing.T) {
	t.Skip("Integration tests require environment variable setup")

	// Example of how integration tests would look:
	// 1. Set environment variables
	// 2. Call InitConfig()
	// 3. Verify config values are loaded correctly
	// 4. Test GitHub App config loading
	// 5. Clean up environment
}
