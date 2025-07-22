package services

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/config"
	"github.com/terrpan/polly/internal/storage"
)

func TestNewHealthService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	store := storage.NewMemoryStore()

	service := NewHealthService(logger, opaClient, store)

	assert.NotNil(t, service)
	assert.Equal(t, opaClient, service.opaClient)
	assert.Equal(t, logger, service.logger)
	assert.Equal(t, store, service.store)
}

func TestHealthService_Structure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	store := storage.NewMemoryStore()
	service := NewHealthService(logger, opaClient, store)

	// Test that service has the expected structure
	assert.NotNil(t, service.opaClient)
	assert.NotNil(t, service.logger)
	assert.NotNil(t, service.store)

	// Note: We can't test actual health checks without real external dependencies
	// This would require integration testing with real or stubbed services
}

func TestHealthService_CheckHealth_Execution(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, err := clients.NewOPAClient("http://test-opa:8181")
	require.NoError(t, err)
	store := storage.NewMemoryStore()

	service := NewHealthService(logger, opaClient, store)
	ctx := context.Background()

	// Test that CheckHealth can be called and returns a response
	response := service.CheckHealth(ctx)

	// Should return some response (might be unhealthy due to test OPA URL)
	if response != nil {
		assert.NotEmpty(t, response.ServiceName)
		assert.NotEmpty(t, response.Status)
		assert.NotEmpty(t, response.Version)
		assert.Contains(t, response.Dependencies, "storage")
		assert.Equal(t, "healthy", response.Dependencies["storage"].Status)
	}

	// Test that method doesn't panic
	assert.NotPanics(t, func() {
		service.CheckHealth(context.Background())
	})
}

func TestHealthService_ContextHandling(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, err := clients.NewOPAClient("http://test-opa:8181")
	require.NoError(t, err)
	store := storage.NewMemoryStore()

	service := NewHealthService(logger, opaClient, store)

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should handle cancelled context gracefully
	assert.NotPanics(t, func() {
		response := service.CheckHealth(ctx)
		_ = response // May be nil or error due to cancelled context
	})
}

func TestHealthService_OPAClientIntegration(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, err := clients.NewOPAClient("http://test-opa:8181")
	require.NoError(t, err)
	store := storage.NewMemoryStore()

	service := NewHealthService(logger, opaClient, store)

	// Test that service has proper OPA client and store
	assert.Equal(t, opaClient, service.opaClient)
	assert.Equal(t, store, service.store)

	// Test health check with context
	ctx := context.Background()
	response := service.CheckHealth(ctx)

	// Response format validation (if not nil)
	if response != nil {
		assert.IsType(t, "", response.ServiceName)
		assert.IsType(t, "", response.Status)
		assert.IsType(t, "", response.Version)
		assert.Contains(t, response.Dependencies, "storage")
		assert.Contains(t, response.Dependencies, "opa")
	}
}

// Storage-specific health check tests
func TestHealthService_StorageHealthCheck_Memory(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	memoryStore := storage.NewMemoryStore()

	service := NewHealthService(logger, opaClient, memoryStore)
	ctx := context.Background()

	// Test storage health check specifically
	storageCheck := service.checkStorageHealth(ctx)

	assert.Equal(t, "healthy", storageCheck.Status)
	assert.Contains(t, storageCheck.Message, "responding")
	assert.GreaterOrEqual(t, storageCheck.Duration, int64(0))
}

func TestHealthService_StorageHealthCheck_Valkey_Success(t *testing.T) {
	// Skip if no Valkey server is available
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")

	// Try to create a Valkey store - this will only succeed if a server is running
	valkeyStore, err := storage.NewValkeyStore(config.ValkeyConfig{
		Address: "localhost:6379",
		DB:      0,
	})
	if err != nil {
		t.Skip("Skipping Valkey health test - no server available:", err)
		return
	}
	defer valkeyStore.Close()

	service := NewHealthService(logger, opaClient, valkeyStore)
	ctx := context.Background()

	// Test storage health check specifically
	storageCheck := service.checkStorageHealth(ctx)

	assert.Equal(t, "healthy", storageCheck.Status)
	assert.Contains(t, storageCheck.Message, "responding")
	assert.GreaterOrEqual(t, storageCheck.Duration, int64(0))
}

func TestHealthService_StorageHealthCheck_Valkey_Failure(t *testing.T) {
	// Try to create a Valkey store with invalid config - this should fail
	_, err := storage.NewValkeyStore(config.ValkeyConfig{
		Address: "localhost:16379", // Port with no server
		DB:      0,
	})

	// We expect this to fail during construction due to our connection test
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connect")
}

func TestHealthService_FullHealthCheck_WithStorage(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	memoryStore := storage.NewMemoryStore()

	service := NewHealthService(logger, opaClient, memoryStore)
	ctx := context.Background()

	// Test full health check
	response := service.CheckHealth(ctx)

	require.NotNil(t, response)
	assert.Equal(t, "polly", response.ServiceName)
	assert.Contains(t, response.Dependencies, "opa")
	assert.Contains(t, response.Dependencies, "storage")

	// Storage should be healthy (memory store always works)
	storageStatus := response.Dependencies["storage"]
	assert.Equal(t, "healthy", storageStatus.Status)
	assert.Contains(t, storageStatus.Message, "responding")
}
