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
		log.Fatalf("Application failed: %v", err)
	}
}

func run() error {
	ctx := context.Background()

	// Setup OpenTelemetry
	var shutdown func(context.Context) error
	if config.AppConfig.OTLP.EnableOTLP {
		var err error

		shutdown, err = otel.SetupOTelSDK(ctx, "polly")
		if err != nil {
			return fmt.Errorf("failed to setup OpenTelemetry: %w", err)
		}

		defer func() {
			if err := shutdown(ctx); err != nil {
				log.Printf("Error shutting down OpenTelemetry: %v", err)
			}
		}()
	}

	// Initialize the application container
	container, err := app.NewContainer(ctx)
	if err != nil {
		return fmt.Errorf("failed to initialize application container: %w", err)
	}

	// Log application version and build info
	container.Logger.Info("Starting polly server",
		"version", config.AppConfig.Version,
		"commit", config.AppConfig.Commit,
		"build_time", config.AppConfig.BuildTime,
		"port", config.AppConfig.Port,
	)

	// Set up HTTP server
	server := app.NewServer(container)

	// Channel to capture server start errors
	serverErrors := make(chan error, 1)

	// Start the server in a goroutine so it doesn't block
	go func() {
		if err := server.Start(); err != nil {
			container.Logger.Error("Failed to start server", "error", err)

			serverErrors <- err
		}
	}()

	// Wait for interrupt signal to gracefully shutdown or server error
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		container.Logger.Info("Shutting down server...")
	case err := <-serverErrors:
		return fmt.Errorf("server failed to start: %w", err)
	}

	// Shutdown the server gracefully
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown server
	if err := server.Shutdown(shutdownCtx); err != nil {
		container.Logger.Error("Server forced to shutdown", "error", err)
	}

	// Shutdown application container
	if err := container.Shutdown(shutdownCtx); err != nil {
		container.Logger.Error("Failed to shutdown container", "error", err)
	}

	container.Logger.Info("Server exited")

	return nil
}
