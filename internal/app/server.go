// Package app provides the application and dependency injection container.
// It is responsible for initializing and wiring together all components of the application.
package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"

	"github.com/terrpan/polly/internal/config"
)

// Server wraps the HTTP server with our container
type Server struct {
	httpServer *http.Server
	container  *Container
}

// NewServer creates a new HTTP server with all routes configured
func NewServer(container *Container) *Server {
	mux := http.NewServeMux()

	// Setup all routes
	setupRoutes(mux, container)

	httpServer := &http.Server{
		Addr: fmt.Sprintf(":%d", config.AppConfig.Port),
		// Handler:      mux,
		Handler:      otelhttp.NewHandler(mux, "polly-server"), // Auto-instrumentation
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return &Server{
		httpServer: httpServer,
		container:  container,
	}
}

// Start runs the HTTP server
func (s *Server) Start() error {
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		s.container.Logger().Error("Failed to start server", "error", err)
		return err
	}

	return nil
}

// Shutdown gracefully shuts down the HTTP server
func (s *Server) Shutdown(ctx context.Context) error {
	s.container.Logger().Info("Stopping server")

	if err := s.httpServer.Shutdown(ctx); err != nil {
		s.container.Logger().Error("Failed to shut down server", "error", err)
		return err
	}

	s.container.Logger().Info("Server shut down successfully")

	return nil
}
