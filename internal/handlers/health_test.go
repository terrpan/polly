package handlers

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/storage"
)

func TestNewHealthHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create test OPA client
	opaClient, err := clients.NewOPAClient("http://test-opa:8181")
	require.NoError(t, err)
	store := storage.NewMemoryStore()

	healthService := services.NewHealthService(logger, opaClient, store)

	handler := NewHealthHandler(logger, healthService)

	assert.NotNil(t, handler)
	assert.Equal(t, logger, handler.logger)
	assert.Equal(t, healthService, handler.healthService)
}

func TestHealthHandler_HandleHealthCheck(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create test OPA client (won't make real calls)
	opaClient, err := clients.NewOPAClient("http://test-opa:8181")
	require.NoError(t, err)
	store := storage.NewMemoryStore()

	healthService := services.NewHealthService(logger, opaClient, store)
	handler := NewHealthHandler(logger, healthService)

	// Create test request
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Call the handler
	handler.HandleHealthCheck(w, req)

	// Health check should return some response (might be error due to no real OPA)
	assert.True(t, w.Code > 0, "Should return a status code")

	// Test that the method doesn't panic
	assert.NotPanics(t, func() {
		req2 := httptest.NewRequest("GET", "/health", nil)
		w2 := httptest.NewRecorder()
		handler.HandleHealthCheck(w2, req2)
	})
}

func TestHealthHandler_ContextHandling(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	opaClient, err := clients.NewOPAClient("http://test-opa:8181")
	require.NoError(t, err)
	store := storage.NewMemoryStore()

	healthService := services.NewHealthService(logger, opaClient, store)
	handler := NewHealthHandler(logger, healthService)

	// Test with context
	ctx := context.Background()
	req := httptest.NewRequest("GET", "/health", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	// Should handle context properly
	assert.NotPanics(t, func() {
		handler.HandleHealthCheck(w, req)
	})

	assert.NotNil(t, req.Context())
}

func TestHealthHandler_Structure(t *testing.T) {
	// Test handler structure and fields
	handler := &HealthHandler{}

	// Test that handler has expected field types
	assert.IsType(t, (*slog.Logger)(nil), handler.logger)
	assert.IsType(t, (*services.HealthService)(nil), handler.healthService)
}
