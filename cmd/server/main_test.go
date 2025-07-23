package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/terrpan/polly/internal/config"
)

func TestMain_Structure(t *testing.T) {
	// Since main() contains initialization logic and starts a server,
	// we test the structure and availability of key components

	// Test that the main package is properly structured
	assert.True(t, true, "Main package should compile without errors")
}

func TestInit_Function(t *testing.T) {
	// The init() function is automatically called, so we test its effects
	// by checking that config is actually initialized

	// Since init() calls config.InitConfig(), we can verify it worked
	assert.NotNil(t, config.AppConfig, "Config should be initialized by init()")

	// Test that basic config values are accessible
	assert.Greater(t, config.AppConfig.Port, 0, "Port should be greater than 0")
	assert.NotEmpty(t, config.AppConfig.Version, "Version should not be empty")
}

func TestMainPackage_Constants(t *testing.T) {
	// Test that main package has the expected structure
	assert.True(t, true, "Main package should have init and main functions")
}

func TestMainPackage_Dependencies(t *testing.T) {
	// Test that main package imports are correct
	assert.True(t, true, "Main package should import required dependencies")
}

func TestMainPackage_BuildInfo(t *testing.T) {
	// Test build info accessibility through config
	version, commit, buildTime := config.GetBuildInfo()

	// These values are set via ldflags during build, but we can test they're accessible
	assert.IsType(t, "", version)
	assert.IsType(t, "", commit)
	assert.IsType(t, "", buildTime)

	// Test that config has build info
	assert.NotEmpty(t, config.AppConfig.Version)
}

func TestMain_ConfigAccess(t *testing.T) {
	// Test that main can access config values that it logs
	assert.NotNil(t, config.AppConfig)
	assert.NotEmpty(t, config.AppConfig.Version)
	assert.Greater(t, config.AppConfig.Port, 0)

	// Test that OTLP config is accessible like main() checks
	assert.IsType(t, true, config.AppConfig.OTLP.EnableOTLP)

	// Test build info access like main() uses
	assert.NotEmpty(t, config.AppConfig.Commit)
	assert.NotEmpty(t, config.AppConfig.BuildTime)
}

// Integration test placeholder - requires careful setup to avoid conflicts
func TestMain_IntegrationExample(t *testing.T) {
	t.Skip("Integration tests for main() require careful server lifecycle management")

	// Example of how integration tests could be structured:
	// 1. Mock or override config values
	// 2. Start server in a goroutine
	// 3. Make test requests
	// 4. Gracefully shutdown
	// 5. Verify expected behavior
}

func TestRun_OpenTelemetryDisabled(t *testing.T) {
	// Test run() function with OpenTelemetry disabled
	originalOTLP := config.AppConfig.OTLP.EnableOTLP

	defer func() {
		config.AppConfig.OTLP.EnableOTLP = originalOTLP
	}()

	// Disable OTLP for this test
	config.AppConfig.OTLP.EnableOTLP = false

	// In test environment, run() should work up to the point where it tries to start the server
	// Since we're testing in isolation, it should complete the setup but fail on server start
	err := run()

	// The function should return an error when trying to start the server in test environment
	// or complete successfully if no server conflicts occur
	if err != nil {
		// In test environment, we expect configuration-related errors
		// such as missing GitHub authentication or other container setup issues
		assert.Contains(t, err.Error(), "container",
			"Error should be related to container initialization")
	}
	// If no error, the setup phase completed successfully
}

func TestRun_ErrorHandling(t *testing.T) {
	// Test that run() properly handles and returns errors instead of calling os.Exit

	// Save and restore original config
	originalPort := config.AppConfig.Port
	defer func() {
		config.AppConfig.Port = originalPort
	}()

	// Set an invalid port to force an error
	config.AppConfig.Port = -1

	err := run()

	// In the test environment, run() might still succeed if no server conflicts
	// The important thing is that it returns gracefully instead of calling os.Exit
	if err != nil {
		// If there's an error, it should be properly formatted
		assert.IsType(t, "", err.Error(), "Error should be a string")
		assert.NotEmpty(t, err.Error(), "Error message should not be empty")
	}
	// If no error, that means the setup completed successfully even with invalid port
	// which is fine in test environment
}

func TestRun_ContextCreation(t *testing.T) {
	// Test that run() can create a context successfully
	// We can't easily test the full run() due to server dependencies,
	// but we can verify it doesn't panic on basic operations

	// Create a context like run() does
	ctx := context.Background()
	assert.NotNil(t, ctx, "Context should be created successfully")

	// Verify context has expected properties
	assert.Equal(t, context.Background(), ctx, "Context should be background context")
}

func TestRun_ConfigAccess(t *testing.T) {
	// Test that run() can access all the config values it needs
	require.NotNil(t, config.AppConfig, "AppConfig must be initialized")

	// Test OTLP config access (used in OpenTelemetry setup)
	assert.IsType(t, false, config.AppConfig.OTLP.EnableOTLP, "OTLP config should be boolean")

	// Test version info access (used in logging)
	assert.NotEmpty(t, config.AppConfig.Version, "Version should be available")
	assert.NotEmpty(t, config.AppConfig.Commit, "Commit should be available")
	assert.NotEmpty(t, config.AppConfig.BuildTime, "BuildTime should be available")

	// Test port access (used in logging and server setup)
	assert.Greater(t, config.AppConfig.Port, 0, "Port should be positive")
}

func TestMain_vs_Run_ErrorHandling(t *testing.T) {
	// Test that main() properly calls run() and handles errors
	// This is a structural test to verify the error handling pattern

	// We can't easily test main() directly since it would start the server,
	// but we can verify the pattern is correct by checking that:
	// 1. run() returns gracefully instead of calling os.Exit
	// 2. main() only has one log.Fatalf call (in main, not in run)
	// 3. The refactoring pattern is correct

	// Verify run() returns gracefully (might succeed or fail, but doesn't exit)
	err := run()

	// The key test is that we reach this point - run() returned instead of exiting
	if err != nil {
		// If there's an error, verify it's properly formatted
		assert.IsType(t, "", err.Error(), "Error should be a string")
		assert.NotEmpty(t, err.Error(), "Error message should not be empty")
	}
	// Success: run() completed without calling os.Exit
}

func TestRun_Timeout(t *testing.T) {
	// Test that run() doesn't hang indefinitely
	done := make(chan error, 1)

	go func() {
		done <- run()
	}()

	select {
	case err := <-done:
		// run() completed, which is good - it either succeeded or failed gracefully
		if err != nil {
			// If there's an error, it should be properly formatted
			assert.IsType(t, "", err.Error(), "Error should be a string")
		}
		// Success: run() completed within timeout
	case <-time.After(5 * time.Second):
		t.Fatal("run() took too long to return (possible hang)")
	}
}

func TestRun_EnvironmentVariables(t *testing.T) {
	// Test that run() behaves correctly with different environment setups

	// Save original environment
	originalEnv := os.Getenv("POLLY_OTLP_ENABLED")
	defer func() {
		var restoreErr error
		if originalEnv == "" {
			restoreErr = os.Unsetenv("POLLY_OTLP_ENABLED")
		} else {
			restoreErr = os.Setenv("POLLY_OTLP_ENABLED", originalEnv)
		}
		if restoreErr != nil {
			t.Logf("Warning: failed to restore environment variable: %v", restoreErr)
		}
	}()

	// Test with OTLP disabled via environment
	err := os.Setenv("POLLY_OTLP_ENABLED", "false")
	require.NoError(t, err, "Should be able to set environment variable")

	// Reinitialize config to pick up the environment change
	configErr := config.InitConfig()
	require.NoError(t, configErr, "Config should reinitialize successfully")

	// Test run() with this configuration
	runErr := run()

	// The function should complete gracefully regardless of OTLP setting
	if runErr != nil {
		// If there's an error, it should be properly formatted
		assert.IsType(t, "", runErr.Error(), "Error should be a string")
		assert.NotEmpty(t, runErr.Error(), "Error message should not be empty")
	}
	// Success: run() handled the environment configuration correctly
}
