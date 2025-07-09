package services

import (
	"testing"
	"log/slog"
	"os"

	"github.com/stretchr/testify/assert"
	"github.com/terrpan/polly/internal/clients"
)

func TestNewHealthService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")

	service := NewHealthService(logger, opaClient)

	assert.NotNil(t, service)
	assert.Equal(t, opaClient, service.opaClient)
	assert.Equal(t, logger, service.logger)
}

func TestHealthService_Structure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	service := NewHealthService(logger, opaClient)

	// Test that service has the expected structure
	assert.NotNil(t, service.opaClient)
	assert.NotNil(t, service.logger)
	
	// Note: We can't test actual health checks without real external dependencies
	// This would require integration testing with real or stubbed services
}
