package config

import (
	"log/slog"
	"os"
)

// NewLogger creates a new slog.Logger based on the application configuration.
func NewLogger() *slog.Logger {
	level := parseLogLevel(AppConfig.Logger.Level)

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: AppConfig.Logger.AddSource,
	}

	var handler slog.Handler
	if AppConfig.Logger.JSONOutput {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(handler)

}

// parseLogLevel parses the log level from a string and returns the corresponding slog.Level.
// It supports "debug", "warn", "error", and defaults to "info" if the level is not recognized.
func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
