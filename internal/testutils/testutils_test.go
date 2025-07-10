package testutils

import (
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTestLogger(t *testing.T) {
	logger := NewTestLogger()

	assert.NotNil(t, logger)

	// Test that logger can be used without panicking
	assert.NotPanics(t, func() {
		logger.Info("test info message")
		logger.Error("test error message")
		logger.Debug("test debug message")
	})

	// Test that it's the expected type
	assert.IsType(t, (*slog.Logger)(nil), logger)
}