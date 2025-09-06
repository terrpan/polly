// Package config provides configuration settings for the application.
// This file contains the logger configuration.
package config

import (
	"context"
	"log/slog"
	"os"
	"sync"
)

var (
	baseLogger *slog.Logger
	loggerOnce sync.Once
)

// getBaseLogger returns a singleton base logger instance
func getBaseLogger() *slog.Logger {
	loggerOnce.Do(func() {
		baseLogger = createLogger()
	})

	return baseLogger
}

// createLogger creates a new slog.Logger based on application config
func createLogger() *slog.Logger {
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

// NewLogger returns the base logger instance
func NewLogger() *slog.Logger {
	return getBaseLogger()
}

// Logger returns a context-aware logger with automatic request ID correlation
func Logger(ctx context.Context) *slog.Logger {
	baseLogger := getBaseLogger()

	// Only add request ID if the feature is enabled and ID is available
	if AppConfig.Logger.EnableRequestID {
		if requestID := ctx.Value("request_id"); requestID != nil {
			return baseLogger.With("request_id", requestID)
		}
	}

	return baseLogger
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
