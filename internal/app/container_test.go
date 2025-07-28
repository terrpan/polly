package app

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/config"
	"github.com/terrpan/polly/internal/handlers"
	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/storage"
)

// ContainerTestSuite provides a test suite for container initialization tests
type ContainerTestSuite struct {
	suite.Suite
	originalOpaURL      string
	originalStorageType string
	originalGitHubToken string
	originalAppID       int64
}

// SetupSuite runs once before all tests in the suite
func (suite *ContainerTestSuite) SetupSuite() {
	// Initialize config if not already done
	if config.AppConfig == nil {
		err := config.InitConfig()
		suite.Require().NoError(err, "Config should initialize for test suite")
	}

	// Ensure config is not nil after initialization
	suite.Require().NotNil(config.AppConfig, "Config should not be nil after initialization")

	// Save original config values
	suite.originalStorageType = config.AppConfig.Storage.Type
	suite.originalGitHubToken = config.AppConfig.GitHubToken
	suite.originalAppID = config.AppConfig.GitHubApp.AppID
	suite.originalOpaURL = config.AppConfig.Opa.ServerURL
}

// TearDownSuite runs once after all tests in the suite
func (suite *ContainerTestSuite) TearDownSuite() {
	// Restore original config values
	config.AppConfig.Storage.Type = suite.originalStorageType
	config.AppConfig.GitHubToken = suite.originalGitHubToken
	config.AppConfig.GitHubApp.AppID = suite.originalAppID
	config.AppConfig.Opa.ServerURL = suite.originalOpaURL
}

// SetupTest runs before each test
func (suite *ContainerTestSuite) SetupTest() {
	// Reset to default values for each test
	config.AppConfig.Storage.Type = "memory"
	config.AppConfig.GitHubToken = ""
	config.AppConfig.GitHubApp.AppID = 0
	config.AppConfig.Opa.ServerURL = "http://localhost:8181"
}

// createTestContainer creates a basic container for testing
func (suite *ContainerTestSuite) createTestContainer() *Container {
	return &Container{
		Logger: slog.New(slog.NewTextHandler(
			os.Stdout,
			&slog.HandlerOptions{Level: slog.LevelError},
		)),
	}
}

// TestContainerSuite runs the container test suite
func TestContainerSuite(t *testing.T) {
	suite.Run(t, new(ContainerTestSuite))
}

func TestContainer_Structure(t *testing.T) {
	container := &Container{
		Logger: slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
		),
	}

	assert.NotNil(t, container)
	assert.NotNil(t, container.Logger)

	// Test that container has the expected structure for dependency injection
	assert.IsType(t, (*Container)(nil), container)
}

func TestNewContainer_Structure(t *testing.T) {
	t.Skip("Integration test requires proper config setup")

	// This would be an integration test requiring:
	// 1. Proper config initialization
	// 2. Valid GitHub credentials or mocked clients
	// 3. Valid OPA client configuration

	// Example of how integration test would work:
	// ctx := context.Background()
	// container, err := NewContainer(ctx)
	// require.NoError(t, err)
	// assert.NotNil(t, container)
	// assert.NotNil(t, container.Logger)
	// assert.NotNil(t, container.GitHubClient)
	// assert.NotNil(t, container.OpaClient)
}

func TestContainer_Shutdown(t *testing.T) {
	container := &Container{
		Logger: slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
		),
	}

	ctx := context.Background()
	err := container.Shutdown(ctx)

	// Shutdown should complete without error even with minimal container
	assert.NoError(t, err)
}

func TestContainer_DependencyInjection(t *testing.T) {
	// Test that container properly holds all expected dependency types
	container := &Container{}

	// Verify container has fields for all major components
	assert.IsType(t, (*slog.Logger)(nil), container.Logger)

	// Note: Other fields would be nil in this unit test, but we verify
	// the structure supports dependency injection pattern
	assert.NotPanics(t, func() {
		_ = container.GitHubClient
		_ = container.OpaClient
		_ = container.CommentService
		_ = container.HealthService
		_ = container.CheckService
		_ = container.PolicyService
		_ = container.SecurityService
		_ = container.WebhookRouter
		_ = container.HealthHandler
		_ = container.StateService
	})
}

func TestContainer_FieldTypes(t *testing.T) {
	// Test that all container fields have correct types
	container := &Container{}

	assert.IsType(t, (*slog.Logger)(nil), container.Logger)
	assert.IsType(t, (*clients.GitHubClient)(nil), container.GitHubClient)
	assert.IsType(t, (*clients.OPAClient)(nil), container.OpaClient)
	assert.IsType(t, (*services.CommentService)(nil), container.CommentService)
	assert.IsType(t, (*services.HealthService)(nil), container.HealthService)
	assert.IsType(t, (*services.CheckService)(nil), container.CheckService)
	assert.IsType(t, (*services.PolicyService)(nil), container.PolicyService)
	assert.IsType(t, (*services.SecurityService)(nil), container.SecurityService)
	assert.IsType(t, (*handlers.WebhookRouter)(nil), container.WebhookRouter)
	assert.IsType(t, (*handlers.HealthHandler)(nil), container.HealthHandler)
	assert.IsType(t, (*services.StateService)(nil), container.StateService)
}

func TestContainer_ZeroValue(t *testing.T) {
	// Test container zero value behavior
	var container Container

	assert.Nil(t, container.Logger)
	assert.Nil(t, container.GitHubClient)
	assert.Nil(t, container.OpaClient)
	assert.Nil(t, container.CommentService)
	assert.Nil(t, container.HealthService)
	assert.Nil(t, container.CheckService)
	assert.Nil(t, container.PolicyService)
	assert.Nil(t, container.SecurityService)
	assert.Nil(t, container.WebhookRouter)
	assert.Nil(t, container.HealthHandler)
	assert.Nil(t, container.StateService)
}

func TestContainer_Logger_Creation(t *testing.T) {
	// Test that we can create and use the logger
	container := &Container{}

	// Test logger creation from config
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	container.Logger = logger

	assert.NotNil(t, container.Logger)

	// Test that logger can be used
	assert.NotPanics(t, func() {
		container.Logger.Info("test message")
	})
}

func TestContainer_Shutdown_WithLogger(t *testing.T) {
	// Test shutdown with actual logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	container := &Container{
		Logger: logger,
	}

	ctx := context.Background()
	err := container.Shutdown(ctx)

	// Shutdown should log and complete without error
	assert.NoError(t, err)

	// Verify logger is still accessible after shutdown
	assert.NotNil(t, container.Logger)
}

func TestContainer_NewLogger(t *testing.T) {
	// Test creating a logger like NewContainer does
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	assert.NotNil(t, logger)

	// Test that we can use the logger
	assert.NotPanics(t, func() {
		logger.Info("Test message")
		logger.Error("Test error")
		logger.Debug("Test debug")
	})
}

func TestContainer_ErrorHandling(t *testing.T) {
	// Test container creation logic without external dependencies
	ctx := context.Background()

	// Test that context is valid
	assert.NotNil(t, ctx)

	// Test that we can create a basic container structure
	container := &Container{
		Logger: slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
		),
	}

	// Test that basic operations work
	assert.NotNil(t, container.Logger)

	// Test error handling for nil services
	assert.Nil(t, container.GitHubClient)
	assert.Nil(t, container.OpaClient)
}

// Tests for the refactored initialization functions

func (suite *ContainerTestSuite) TestInitializeStorage() {
	container := suite.createTestContainer()

	err := container.initializeStorage()

	// Should succeed with memory storage
	suite.Require().NoError(err, "Storage initialization should succeed with memory type")
	suite.Assert().NotNil(container.Store, "Store should be initialized")
	suite.Assert().Implements(
		(*storage.Store)(nil),
		container.Store,
		"Store should implement Store interface",
	)
}

func (suite *ContainerTestSuite) TestInitializeStorage_InvalidType() {
	// Test with invalid storage type
	config.AppConfig.Storage.Type = "invalid-type"

	container := suite.createTestContainer()

	err := container.initializeStorage()

	// Should fail with invalid storage type
	suite.Assert().Error(err, "Storage initialization should fail with invalid type")
	suite.Assert().Contains(
		err.Error(),
		"failed to initialize storage",
		"Error should mention storage initialization",
	)
	suite.Assert().Nil(container.Store, "Store should not be initialized on error")
}

func (suite *ContainerTestSuite) TestInitializeOPAClient() {
	container := suite.createTestContainer()

	err := container.initializeOPAClient()

	// Should succeed with valid URL (even if server is not reachable)
	suite.Require().NoError(err, "OPA client initialization should succeed with valid URL")
	suite.Assert().NotNil(container.OpaClient, "OPA client should be initialized")
	suite.Assert().IsType(
		(*clients.OPAClient)(nil),
		container.OpaClient,
		"Should be OPA client type",
	)
}

func (suite *ContainerTestSuite) TestInitializeOPAClient_InvalidURL() {
	// Test with invalid OPA URL
	config.AppConfig.Opa.ServerURL = "invalid-url"

	container := suite.createTestContainer()

	err := container.initializeOPAClient()

	// Should succeed with any non-empty URL (validation happens on actual requests)
	suite.Assert().NoError(err, "OPA client initialization should succeed with any non-empty URL")
	suite.Assert().NotNil(container.OpaClient, "OPA client should be initialized")
}

func (suite *ContainerTestSuite) TestInitializeGitHubClient_InvalidToken() {
	// Set invalid token
	config.AppConfig.GitHubToken = "invalid-token"
	config.AppConfig.GitHubApp.AppID = 0

	container := suite.createTestContainer()

	ctx := context.Background()
	err := container.initializeGitHubClient(ctx)

	// Should succeed during initialization (token validation happens on API calls)
	suite.Assert().NoError(
		err,
		"GitHub client initialization should succeed with any non-empty token",
	)
	suite.Assert().NotNil(container.GitHubClient, "GitHub client should be initialized")
}

func (suite *ContainerTestSuite) TestInitializeGitHubClient_NoAuth() {
	container := suite.createTestContainer()

	ctx := context.Background()
	err := container.initializeGitHubClient(ctx)

	// Should fail with no authentication configured
	suite.Assert().Error(err, "GitHub client initialization should fail with no authentication")
	suite.Assert().Contains(
		err.Error(),
		"no GitHub authentication configured",
		"Error should mention missing authentication",
	)
	suite.Assert().Nil(container.GitHubClient, "GitHub client should not be initialized on error")
}

func (suite *ContainerTestSuite) TestInitializeServices() {
	// Create container with required dependencies
	container := suite.createTestContainer()
	container.GitHubClient = &clients.GitHubClient{} // Mock client
	container.OpaClient = &clients.OPAClient{}       // Mock client
	container.Store = &storage.MemoryStore{}         // Mock store

	// Initialize services
	container.initializeServices()

	// Verify all services are initialized
	suite.Assert().NotNil(container.CommentService, "Comment service should be initialized")
	suite.Assert().NotNil(container.HealthService, "Health service should be initialized")
	suite.Assert().NotNil(container.CheckService, "Check service should be initialized")
	suite.Assert().NotNil(container.PolicyService, "Policy service should be initialized")
	suite.Assert().NotNil(container.SecurityService, "Security service should be initialized")
	suite.Assert().NotNil(container.StateService, "State service should be initialized")

	// Verify service types
	suite.Assert().IsType((*services.CommentService)(nil), container.CommentService)
	suite.Assert().IsType((*services.HealthService)(nil), container.HealthService)
	suite.Assert().IsType((*services.CheckService)(nil), container.CheckService)
	suite.Assert().IsType((*services.PolicyService)(nil), container.PolicyService)
	suite.Assert().IsType((*services.SecurityService)(nil), container.SecurityService)
	suite.Assert().IsType((*services.StateService)(nil), container.StateService)
}

func (suite *ContainerTestSuite) TestInitializeHandlers() {
	// Create container with required dependencies
	container := suite.createTestContainer()

	// Initialize services (required for handlers)
	container.CommentService = services.NewCommentService(nil, container.Logger)
	container.HealthService = services.NewHealthService(container.Logger, nil, nil)
	container.CheckService = services.NewCheckService(nil, container.Logger)
	container.PolicyService = services.NewPolicyService(nil, container.Logger)
	container.SecurityService = services.NewSecurityService(nil, container.Logger)
	container.StateService = services.NewStateService(nil, container.Logger)

	// Initialize handlers
	err := container.initializeHandlers()

	// Should succeed with valid services
	suite.Require().NoError(err, "Handler initialization should succeed")
	suite.Assert().NotNil(container.WebhookHandler, "Webhook handler should be initialized")
	suite.Assert().NotNil(container.HealthHandler, "Health handler should be initialized")

	// Verify handler types
	suite.Assert().IsType((*handlers.WebhookHandler)(nil), container.WebhookHandler)
	suite.Assert().IsType((*handlers.HealthHandler)(nil), container.HealthHandler)
}

func (suite *ContainerTestSuite) TestInitializeClients() {
	container := suite.createTestContainer()

	ctx := context.Background()
	err := container.initializeClients(ctx)

	// Should fail due to missing GitHub authentication
	suite.Assert().Error(err, "Client initialization should fail with missing GitHub auth")
	suite.Assert().Contains(
		err.Error(),
		"no GitHub authentication configured",
		"Error should mention GitHub authentication",
	)
}

func (suite *ContainerTestSuite) TestModularInitialization_Benefits() {
	// Test that the modular approach allows for isolated testing
	container := suite.createTestContainer()

	// Test storage initialization in isolation
	err := container.initializeStorage()
	suite.Assert().NoError(err, "Storage should initialize independently")

	// Test services initialization with mock dependencies
	container.GitHubClient = &clients.GitHubClient{}
	container.OpaClient = &clients.OPAClient{}
	container.Store = storage.NewMemoryStore()

	// Should not panic and should initialize all services
	suite.Assert().NotPanics(func() {
		container.initializeServices()
	}, "Services should initialize with dependencies")

	// Verify modular benefits
	suite.Assert().NotNil(container.Store, "Storage initialized independently")
	suite.Assert().NotNil(container.CommentService, "Services initialized with dependencies")
}
