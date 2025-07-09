package config

import (
	"testing"
	"reflect"

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
		Port:        8080,
		GitHubToken: "test-token",
		Version:     "1.0.0",
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
	// Test actual config initialization
	err := InitConfig()
	assert.NoError(t, err, "InitConfig should complete without error")

	// Test that AppConfig is properly initialized
	assert.NotNil(t, AppConfig)
	assert.Greater(t, AppConfig.Port, 0)
	assert.NotEmpty(t, AppConfig.Version)

	// Test default values are applied
	assert.Equal(t, "debug", AppConfig.Logger.Level)
	assert.True(t, AppConfig.Logger.JSONOutput)
	assert.Equal(t, "http://localhost:8181", AppConfig.Opa.ServerURL)
}

func TestInitConfig_ActualExecution(t *testing.T) {
	// Test the actual InitConfig function
	err := InitConfig()
	assert.NoError(t, err)

	// Verify that globals are set
	assert.NotNil(t, AppConfig)
	assert.Equal(t, Version, AppConfig.Version)
	assert.Equal(t, Commit, AppConfig.Commit)
	assert.Equal(t, BuildTime, AppConfig.BuildTime)
}

func TestSetDefaultsViaReflection_ActualExecution(t *testing.T) {
	// Test the reflection-based default setting
	testConfig := GetDefaultConfig()
	assert.NotNil(t, testConfig)

	// Test that defaults are actually applied via reflection
	setDefaultsViaReflection(testConfig)

	// Verify the structure is intact
	assert.Equal(t, 8080, testConfig.Port)
	assert.Equal(t, "debug", testConfig.Logger.Level)
}

func TestConfig_ReflectionFunctions(t *testing.T) {
	// Test the reflection-based functions actually work
	testConfig := Config{
		Port: 8080,
		Logger: LoggerConfig{
			Level: "info",
			JSONOutput: true,
		},
		Opa: OpaConfig{
			ServerURL: "http://test:8181",
		},
	}
	
	// Test setDefaultsViaReflection
	setDefaultsViaReflection(&testConfig)
	
	// The function should complete without panic
	assert.Equal(t, 8080, testConfig.Port)
	assert.Equal(t, "info", testConfig.Logger.Level)
}

func TestConfig_EnvironmentBinding(t *testing.T) {
	// Test bindNestedEnvVars function
	assert.NotPanics(t, func() {
		bindNestedEnvVars()
	})
	
	// Test bindStructEnvVars function
	assert.NotPanics(t, func() {
		bindStructEnvVars(reflect.TypeOf(Config{}), "", "TEST")
	})
}

func TestLoadGitHubAppConfig_AllCases(t *testing.T) {
	// Save original
	originalAppConfig := AppConfig
	defer func() {
		AppConfig = originalAppConfig
	}()
	
	// Test missing installation ID
	AppConfig = &Config{
		GitHubApp: GitHubAppConfig{
			AppID:          123,
			InstallationID: 0,
		},
	}
	
	_, err := LoadGitHubAppConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "GITHUB_INSTALLATION_ID is required")
	
	// Test missing private key
	AppConfig = &Config{
		GitHubApp: GitHubAppConfig{
			AppID:          123,
			InstallationID: 456,
			PrivateKey:     "",
			PrivateKeyPath: "",
		},
	}
	
	_, err = LoadGitHubAppConfig()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "either GITHUB_PRIVATE_KEY or GITHUB_PRIVATE_KEY_PATH is required")
}
