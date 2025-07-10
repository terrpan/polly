package testutils

import (
	"log/slog"
	"os"
)

// NewTestLogger creates a new slog.Logger configured for testing.
// It uses a text handler with error level logging to reduce noise during tests.
func NewTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}