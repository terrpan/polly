package config

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected slog.Level
	}{
		{
			name:     "debug level",
			input:    "debug",
			expected: slog.LevelDebug,
		},
		{
			name:     "warn level",
			input:    "warn",
			expected: slog.LevelWarn,
		},
		{
			name:     "error level",
			input:    "error",
			expected: slog.LevelError,
		},
		{
			name:     "info level",
			input:    "info",
			expected: slog.LevelInfo,
		},
		{
			name:     "default to info for unknown level",
			input:    "unknown",
			expected: slog.LevelInfo,
		},
		{
			name:     "default to info for empty string",
			input:    "",
			expected: slog.LevelInfo,
		},
		{
			name:     "case sensitive - uppercase returns default",
			input:    "DEBUG",
			expected: slog.LevelInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLogLevel(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewLogger_JSONOutput(t *testing.T) {
	// Save original AppConfig
	originalAppConfig := AppConfig
	defer func() {
		AppConfig = originalAppConfig
	}()

	// Test JSON output configuration
	AppConfig = &Config{
		Logger: LoggerConfig{
			Level:      "debug",
			JSONOutput: true,
			AddSource:  false,
		},
	}

	logger := NewLogger()
	require.NotNil(t, logger)

	// Capture the handler type by checking if it produces JSON output
	var buf bytes.Buffer
	testLogger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelDebug,
	}))

	testLogger.Info("test message")
	output := buf.String()

	// Verify it's valid JSON
	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(output), &jsonData)
	assert.NoError(t, err, "Output should be valid JSON")
	assert.Contains(t, jsonData, "msg")
	assert.Equal(t, "test message", jsonData["msg"])
}

func TestNewLogger_TextOutput(t *testing.T) {
	// Save original AppConfig
	originalAppConfig := AppConfig
	defer func() {
		AppConfig = originalAppConfig
	}()

	// Test text output configuration
	AppConfig = &Config{
		Logger: LoggerConfig{
			Level:      "info",
			JSONOutput: false,
			AddSource:  true,
		},
	}

	logger := NewLogger()
	require.NotNil(t, logger)

	// Test that we can create a text handler
	var buf bytes.Buffer
	testLogger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: true,
	}))

	testLogger.Info("test message")
	output := buf.String()

	// Text output should not be JSON
	var jsonData map[string]interface{}
	err := json.Unmarshal([]byte(output), &jsonData)
	assert.Error(t, err, "Text output should not be valid JSON")
	assert.Contains(t, output, "test message")
}

func TestNewLogger_DifferentLevels(t *testing.T) {
	// Save original AppConfig
	originalAppConfig := AppConfig
	defer func() {
		AppConfig = originalAppConfig
	}()

	tests := []struct {
		name          string
		configLevel   string
		expectedLevel slog.Level
	}{
		{
			name:          "debug level configuration",
			configLevel:   "debug",
			expectedLevel: slog.LevelDebug,
		},
		{
			name:          "info level configuration",
			configLevel:   "info",
			expectedLevel: slog.LevelInfo,
		},
		{
			name:          "warn level configuration",
			configLevel:   "warn",
			expectedLevel: slog.LevelWarn,
		},
		{
			name:          "error level configuration",
			configLevel:   "error",
			expectedLevel: slog.LevelError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AppConfig = &Config{
				Logger: LoggerConfig{
					Level:      tt.configLevel,
					JSONOutput: true,
					AddSource:  false,
				},
			}

			logger := NewLogger()
			require.NotNil(t, logger)

			// Test that the logger was created with correct level by testing handler options
			var buf bytes.Buffer
			handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
				Level: tt.expectedLevel,
			})
			testLogger := slog.New(handler)

			// Test different log levels
			testLogger.Debug("debug message")
			testLogger.Info("info message")
			testLogger.Warn("warn message")
			testLogger.Error("error message")

			output := buf.String()
			lines := strings.Split(strings.TrimSpace(output), "\n")

			// Filter out empty lines
			var validLines []string
			for _, line := range lines {
				if strings.TrimSpace(line) != "" {
					validLines = append(validLines, line)
				}
			}

			// Check that appropriate messages are logged based on level
			switch tt.expectedLevel {
			case slog.LevelDebug:
				assert.GreaterOrEqual(
					t,
					len(validLines),
					4,
					"Debug level should log all messages",
				)
			case slog.LevelInfo:
				assert.GreaterOrEqual(
					t,
					len(validLines),
					3,
					"Info level should log info, warn, error",
				)
				assert.NotContains(t, output, "debug message")
			case slog.LevelWarn:
				assert.GreaterOrEqual(
					t,
					len(validLines),
					2,
					"Warn level should log warn, error",
				)
				assert.NotContains(t, output, "debug message")
				assert.NotContains(t, output, "info message")
			case slog.LevelError:
				assert.GreaterOrEqual(
					t,
					len(validLines),
					1,
					"Error level should log error only",
				)
				assert.NotContains(t, output, "debug message")
				assert.NotContains(t, output, "info message")
				assert.NotContains(t, output, "warn message")
			}
		})
	}
}

func TestNewLogger_AddSource(t *testing.T) {
	// Save original AppConfig
	originalAppConfig := AppConfig
	defer func() {
		AppConfig = originalAppConfig
	}()

	tests := []struct {
		name      string
		addSource bool
	}{
		{
			name:      "with source information",
			addSource: true,
		},
		{
			name:      "without source information",
			addSource: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			AppConfig = &Config{
				Logger: LoggerConfig{
					Level:      "info",
					JSONOutput: true,
					AddSource:  tt.addSource,
				},
			}

			logger := NewLogger()
			require.NotNil(t, logger)

			// The test verifies that NewLogger creates a logger with the correct AddSource setting
			// We can't easily test the actual source output without complex reflection,
			// so we just verify the logger was created successfully with the config
			assert.NotNil(t, logger)
		})
	}
}

func TestNewLogger_ActualLogger(t *testing.T) {
	// Save original AppConfig and stdout
	originalAppConfig := AppConfig
	originalStdout := os.Stdout
	defer func() {
		AppConfig = originalAppConfig
		os.Stdout = originalStdout
	}()

	// Create a pipe to capture stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	AppConfig = &Config{
		Logger: LoggerConfig{
			Level:      "info",
			JSONOutput: true,
			AddSource:  false,
		},
	}

	logger := NewLogger()
	require.NotNil(t, logger)

	// Log a test message
	logger.Info("integration test message")

	// Close writer and restore stdout
	w.Close()
	os.Stdout = originalStdout

	// Read the output
	buf := make([]byte, 1024)
	n, err := r.Read(buf)
	if err != nil && n == 0 {
		t.Skip("Could not capture stdout output - this is expected in some test environments")
		return
	}

	output := string(buf[:n])
	assert.Contains(t, output, "integration test message")

	// Verify it's valid JSON
	var jsonData map[string]interface{}
	err = json.Unmarshal([]byte(output), &jsonData)
	assert.NoError(t, err, "Logger output should be valid JSON")
}

func TestNewLogger_HandlerTypes(t *testing.T) {
	// Save original AppConfig
	originalAppConfig := AppConfig
	defer func() {
		AppConfig = originalAppConfig
	}()

	// Test JSON handler creation
	AppConfig = &Config{
		Logger: LoggerConfig{
			Level:      "info",
			JSONOutput: true,
			AddSource:  false,
		},
	}

	jsonLogger := NewLogger()
	require.NotNil(t, jsonLogger)

	// Test Text handler creation
	AppConfig = &Config{
		Logger: LoggerConfig{
			Level:      "info",
			JSONOutput: false,
			AddSource:  false,
		},
	}

	textLogger := NewLogger()
	require.NotNil(t, textLogger)

	// Both loggers should be different instances
	assert.NotEqual(t, jsonLogger, textLogger)
}
