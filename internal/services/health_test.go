package services

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/testutils"
)

func TestNewHealthService(t *testing.T) {
	logger := testutils.NewTestLogger()
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")

	service := NewHealthService(logger, opaClient)

	assert.NotNil(t, service)
	assert.Equal(t, opaClient, service.opaClient)
	assert.Equal(t, logger, service.logger)
}

func TestHealthService_Structure(t *testing.T) {
	logger := testutils.NewTestLogger()
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	service := NewHealthService(logger, opaClient)

	// Test that service has the expected structure
	assert.NotNil(t, service.opaClient)
	assert.NotNil(t, service.logger)

	// Note: We can't test actual health checks without real external dependencies
	// This would require integration testing with real or stubbed services
}

func TestHealthService_CheckHealth_Execution(t *testing.T) {
	logger := testutils.NewTestLogger()
	opaClient, err := clients.NewOPAClient("http://test-opa:8181")
	require.NoError(t, err)

	service := NewHealthService(logger, opaClient)
	ctx := context.Background()

	// Test that CheckHealth can be called and returns a response
	response := service.CheckHealth(ctx)

	// Should return some response (might be unhealthy due to test OPA URL)
	if response != nil {
		assert.NotEmpty(t, response.ServiceName)
		assert.NotEmpty(t, response.Status)
		assert.NotEmpty(t, response.Version)
	}

	// Test that method doesn't panic
	assert.NotPanics(t, func() {
		service.CheckHealth(context.Background())
	})
}

func TestHealthService_ContextHandling(t *testing.T) {
	logger := testutils.NewTestLogger()
	opaClient, err := clients.NewOPAClient("http://test-opa:8181")
	require.NoError(t, err)

	service := NewHealthService(logger, opaClient)

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
	logger := testutils.NewTestLogger()
	opaClient, err := clients.NewOPAClient("http://test-opa:8181")
	require.NoError(t, err)

	service := NewHealthService(logger, opaClient)

	// Test that service has proper OPA client
	assert.Equal(t, opaClient, service.opaClient)

	// Test health check with context
	ctx := context.Background()
	response := service.CheckHealth(ctx)

	// Response format validation (if not nil)
	if response != nil {
		assert.IsType(t, "", response.ServiceName)
		assert.IsType(t, "", response.Status)
		assert.IsType(t, "", response.Version)
	}
}
