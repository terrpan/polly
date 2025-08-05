package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/config"
	"github.com/terrpan/polly/internal/handlers"
	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/storage"
	"github.com/terrpan/polly/internal/telemetry"
)

// Container holds all application dependencies
type Container struct {
	Logger *slog.Logger

	// Storage
	Store        storage.Store
	StateService *services.StateService

	// Clients
	GitHubClient *clients.GitHubClient
	OpaClient    *clients.OPAClient

	// Services
	CommentService     *services.CommentService
	HealthService      *services.HealthService
	CheckService       *services.CheckService
	PolicyService      *services.PolicyService
	PolicyCacheService *services.PolicyCacheService
	SecurityService    *services.SecurityService

	// Handlers
	WebhookRouter *handlers.WebhookRouter
	HealthHandler *handlers.HealthHandler
}

// NewContainer initializes a new Container with all dependencies
func NewContainer(ctx context.Context) (*Container, error) {
	c := &Container{}

	c.Logger = config.NewLogger()
	c.Logger.Info("Initializing application container")

	var err error
	c.Logger.Info("Initializing storage", "type", config.AppConfig.Storage.Type)
	c.Store, err = storage.NewStore(config.AppConfig.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Initialize clients
	if config.IsGitHubAppConfigured() {
		c.Logger.Info("Using GitHub App authentication")
		githubConfig, err := config.LoadGitHubAppConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to load GitHub App config: %w", err)
		}

		c.GitHubClient, err = clients.NewGitHubAppClient(ctx, *githubConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create GitHub App client: %w", err)
		}
	} else if config.AppConfig.GitHubToken != "" {
		c.Logger.Info("Using Personal Access Token authentication")
		c.GitHubClient = clients.NewGitHubClient(ctx)
		if err := c.GitHubClient.Authenticate(ctx, config.AppConfig.GitHubToken); err != nil {
			return nil, fmt.Errorf("failed to authenticate GitHub client: %w", err)
		}
	} else {
		return nil, fmt.Errorf("no GitHub authentication configured (need either GitHub App or PAT)")
	}

	c.Logger.Info("GitHub client initialized")

	// Initialize OPA client
	c.OpaClient, err = clients.NewOPAClient(config.AppConfig.Opa.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OPA client: %w", err)
	}
	c.Logger.Info("OPA client initialized")
	commentTelemetry := telemetry.NewTelemetryHelper("polly/comment")
	healthTelemetry := telemetry.NewTelemetryHelper("polly/health")
	checksTelemetry := telemetry.NewTelemetryHelper("polly/checks")
	policyTelemetry := telemetry.NewTelemetryHelper("polly/policy")
	securityTelemetry := telemetry.NewTelemetryHelper("polly/security")
	stateTelemetry := telemetry.NewTelemetryHelper("polly/state")
	cacheTelemetry := telemetry.NewTelemetryHelper("polly/cache")

	// Create telemetry helpers for each service
	c.Logger.Info("Initializing telemetry helpers")

	// Initialize services
	c.CommentService = services.NewCommentService(c.GitHubClient, c.Logger, commentTelemetry)
	c.HealthService = services.NewHealthService(c.Logger, c.OpaClient, c.Store, healthTelemetry)
	c.CheckService = services.NewCheckService(c.GitHubClient, c.Logger, checksTelemetry)

	// Create PolicyService with factory pattern
	c.PolicyService = services.NewPolicyService(c.OpaClient, c.Logger, policyTelemetry, nil)
	evaluators := services.NewStandardEvaluators(c.PolicyService)
	c.PolicyService = services.NewPolicyService(c.OpaClient, c.Logger, policyTelemetry, evaluators)

	// Create SecurityService with explicit detector configuration
	securityDetectors := []services.ContentDetector{
		&services.SPDXDetector{},
		&services.TrivyJSONDetector{},
		&services.SARIFDetector{},
	}
	c.SecurityService = services.NewSecurityService(c.GitHubClient, c.Logger, securityTelemetry, securityDetectors...)
	c.StateService = services.NewStateService(c.Store, c.Logger, stateTelemetry)
	c.PolicyCacheService = services.NewPolicyCacheService(c.PolicyService, c.StateService, c.Logger, cacheTelemetry)
	c.Logger.Info("Services initialized",
		"comment_service", c.CommentService,
		"health_service", c.HealthService,
		"check_service", c.CheckService,
		"policy_service", c.PolicyService,
		"policy_cache_service", c.PolicyCacheService,
		"security_service", c.SecurityService,
	)

	// Initialize handlers
	c.WebhookRouter, err = handlers.NewWebhookRouter(
		c.Logger,
		c.CommentService,
		c.CheckService,
		c.PolicyService,
		c.PolicyCacheService,
		c.SecurityService,
		c.StateService,
	)
	if err != nil {
		c.Logger.Error("Failed to create webhook router", "error", err)
		return nil, err
	}
	c.HealthHandler = handlers.NewHealthHandler(c.Logger, c.HealthService)
	c.Logger.Info("Handlers initialized", "webhook_router", c.WebhookRouter, "health_handler", c.HealthHandler)
	return c, nil
}

// Shutdown gracefully stops the container and its dependencies
func (c *Container) Shutdown(ctx context.Context) error {
	c.Logger.Info("Shutting down application container")

	// Perform any necessary cleanup for services or clients here
	// For example, if the GitHub client has a close method, call it

	c.Logger.Info("Application container shutdown complete")
	return nil
}
