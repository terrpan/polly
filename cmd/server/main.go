package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/terrpan/polly/internal/app"
	"github.com/terrpan/polly/internal/config"
	"github.com/terrpan/polly/internal/otel"
)

func init() {
	// initialize the config package
	if err := config.InitConfig(); err != nil {
		log.Fatalf("Failed to initialize config: %v", err)
	}
}

func main() {
	if err := run(); err != nil {
		log.Printf("polly terminated with error: %v", err)
		os.Exit(1) // exit only after defers in run() have executed
	}
}

// run encapsulates the application lifecycle and returns an error so that
// defers execute (satisfying exitAfterDefer lint) before process exit.
func run() error {
	ctx := context.Background()

	// Setup OpenTelemetry (optional)
	var otelShutdown func(context.Context) error

	if config.AppConfig.OTLP.EnableOTLP {
		shutdown, err := otel.SetupOTelSDK(ctx, "polly")
		if err != nil {
			return fmt.Errorf("setup OpenTelemetry: %w", err)
		}

		otelShutdown = shutdown

		defer func() {
			if err := otelShutdown(ctx); err != nil {
				log.Printf("Error shutting down OpenTelemetry: %v", err)
			}
		}()
	}

	// Initialize the application container
	container, err := app.NewContainer(ctx)
	if err != nil {
		return fmt.Errorf("initialize application container: %w", err)
	}

	defer func() {
		// Use a fresh timeout context for container shutdown
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := container.Shutdown(shutdownCtx); err != nil {
			container.Logger().Error("Failed to shutdown container", "error", err)
		}
	}()

	// Log application version and build info
	container.Logger().Info("Starting polly server",
		"version", config.AppConfig.Version,
		"commit", config.AppConfig.Commit,
		"build_time", config.AppConfig.BuildTime,
		"port", config.AppConfig.Port,
	)

	// Set up HTTP server
	server := app.NewServer(container)

	// Channel for server errors
	serverErrCh := make(chan error, 1)

	// Start the server in a goroutine so it doesn't block
	go func() {
		if err := server.Start(); err != nil {
			serverErrCh <- err
		}

		close(serverErrCh)
	}()

	// Wait for interrupt signal or server start error
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		container.Logger().Info("Shutdown signal received", "signal", sig.String())
	case err := <-serverErrCh:
		if err != nil { // non-nil means server failed unexpectedly
			container.Logger().Error("Server error", "error", err)
			// attempt graceful shutdown below; propagate error
			return fmt.Errorf("server error: %w", err)
		}
		// channel closed with nil error => normal server stop; continue to clean shutdown
		container.Logger().Info("Server stopped gracefully")
	}

	// Graceful server shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		container.Logger().Error("Server forced to shutdown", "error", err)
	}

	container.Logger().Info("Server exited")

	return nil
}
