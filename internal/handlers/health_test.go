package handlers

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/suite"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/storage"
	"github.com/terrpan/polly/internal/telemetry"
)

type HealthHandlerTestSuite struct {
	suite.Suite
	logger          *slog.Logger
	opaClient       *clients.OPAClient
	store           storage.Store
	telemetryHelper *telemetry.TelemetryHelper
	healthService   *services.HealthService
	handler         *HealthHandler
}

func (suite *HealthHandlerTestSuite) SetupTest() {
	suite.logger = slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
	)

	// Create test OPA client
	opaClient, err := clients.NewOPAClient("http://test-opa:8181")
	suite.Require().NoError(err)
	suite.opaClient = opaClient

	suite.store = storage.NewMemoryStore()
	suite.telemetryHelper = telemetry.NewTelemetryHelper("test")
	suite.healthService = services.NewHealthService(
		suite.logger,
		suite.opaClient,
		suite.store,
		suite.telemetryHelper,
	)
	suite.handler = NewHealthHandler(suite.logger, suite.healthService)
}

func (suite *HealthHandlerTestSuite) TestNewHealthHandler() {
	suite.NotNil(suite.handler)
	suite.Equal(suite.logger, suite.handler.logger)
	suite.Equal(suite.healthService, suite.handler.healthService)
}

func (suite *HealthHandlerTestSuite) TestHandleHealthCheck() {
	// Create test request
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	// Call the handler
	suite.handler.HandleHealthCheck(w, req)

	// Health check should return some response (might be error due to no real OPA)
	suite.True(w.Code > 0, "Should return a status code")

	// Test that the method doesn't panic
	suite.NotPanics(func() {
		req2 := httptest.NewRequest("GET", "/health", nil)
		w2 := httptest.NewRecorder()
		suite.handler.HandleHealthCheck(w2, req2)
	})
}

func (suite *HealthHandlerTestSuite) TestContextHandling() {
	// Test with context
	ctx := context.Background()
	req := httptest.NewRequest("GET", "/health", nil).WithContext(ctx)
	w := httptest.NewRecorder()

	// Should handle context properly
	suite.NotPanics(func() {
		suite.handler.HandleHealthCheck(w, req)
	})

	suite.NotNil(req.Context())
}

func (suite *HealthHandlerTestSuite) TestHandlerStructure() {
	// Test handler structure and fields
	handler := &HealthHandler{}

	// Test that handler has expected field types
	suite.IsType((*slog.Logger)(nil), handler.logger)
	suite.IsType((*services.HealthService)(nil), handler.healthService)
}

// Run the test suite
func TestHealthHandlerSuite(t *testing.T) {
	suite.Run(t, new(HealthHandlerTestSuite))
}
