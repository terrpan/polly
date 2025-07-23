// Package app provides the application container and dependency injection system.
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
)

// Container holds all application dependencies using dependency injection pattern.
type Container struct {
	Logger *slog.Logger

	// Storage layer
	Store        storage.Store
	StateService *services.StateService

	// External service clients
	GitHubClient *clients.GitHubClient
	OpaClient    *clients.OPAClient

	// Business logic services
	CommentService  *services.CommentService
	HealthService   *services.HealthService
	CheckService    *services.CheckService
	PolicyService   *services.PolicyService
	SecurityService *services.SecurityService

	// HTTP request handlers
	WebhookHandler *handlers.WebhookHandler
	HealthHandler  *handlers.HealthHandler
}

// NewContainer initializes a new Container with all dependencies.
func NewContainer(ctx context.Context) (*Container, error) {
	c := &Container{}

	c.Logger = config.NewLogger()
	c.Logger.Info("Initializing application container")

	var err error

	// Initialize storage
	if err = c.initializeStorage(); err != nil {
		return nil, err
	}

	// Initialize clients
	if err = c.initializeClients(ctx); err != nil {
		return nil, err
	}

	// Initialize services
	c.initializeServices()

	// Initialize handlers
	if err = c.initializeHandlers(); err != nil {
		return nil, err
	}

	return c, nil
}

// initializeStorage sets up the storage layer based on configuration.
func (c *Container) initializeStorage() error {
	c.Logger.Info("Initializing storage", "type", config.AppConfig.Storage.Type)

	var err error

	c.Store, err = storage.NewStore(config.AppConfig.Storage)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}

	return nil
}

// initializeClients sets up external service clients.
func (c *Container) initializeClients(ctx context.Context) error {
	// Initialize GitHub client
	if err := c.initializeGitHubClient(ctx); err != nil {
		return err
	}

	// Initialize OPA client
	if err := c.initializeOPAClient(); err != nil {
		return err
	}

	return nil
}

// initializeGitHubClient sets up GitHub authentication and client.
func (c *Container) initializeGitHubClient(ctx context.Context) error {
	switch {
	case config.IsGitHubAppConfigured():
		c.Logger.Info("Using GitHub App authentication")

		githubConfig, err := config.LoadGitHubAppConfig()
		if err != nil {
			return fmt.Errorf("failed to load GitHub App config: %w", err)
		}

		c.GitHubClient, err = clients.NewGitHubAppClient(ctx, *githubConfig)
		if err != nil {
			return fmt.Errorf("failed to create GitHub App client: %w", err)
		}
	case config.AppConfig.GitHubToken != "":
		c.Logger.Info("Using Personal Access Token authentication")

		c.GitHubClient = clients.NewGitHubClient(ctx)
		if err := c.GitHubClient.Authenticate(ctx, config.AppConfig.GitHubToken); err != nil {
			return fmt.Errorf("failed to authenticate GitHub client: %w", err)
		}
	default:
		return fmt.Errorf(
			"no GitHub authentication configured (need either GitHub App or PAT)",
		)
	}

	c.Logger.Info("GitHub client initialized")

	return nil
}

// initializeOPAClient sets up the OPA (Open Policy Agent) policy client.
// It creates a client configured to communicate with the OPA server.
func (c *Container) initializeOPAClient() error {
	var err error

	c.OpaClient, err = clients.NewOPAClient(config.AppConfig.Opa.ServerURL)
	if err != nil {
		return fmt.Errorf("failed to create OPA client: %w", err)
	}

	c.Logger.Info("OPA client initialized")

	return nil
}

// initializeServices sets up all business logic services.
// Services handle the core application logic and depend on the previously initialized clients and storage.
func (c *Container) initializeServices() {
	c.CommentService = services.NewCommentService(c.GitHubClient, c.Logger)
	c.HealthService = services.NewHealthService(c.Logger, c.OpaClient, c.Store)
	c.CheckService = services.NewCheckService(c.GitHubClient, c.Logger)
	c.PolicyService = services.NewPolicyService(c.OpaClient, c.Logger)
	c.SecurityService = services.NewSecurityService(c.GitHubClient, c.Logger)
	c.StateService = services.NewStateService(c.Store, c.Logger)

	c.Logger.Info("Services initialized",
		"comment_service", c.CommentService,
		"health_service", c.HealthService,
		"check_service", c.CheckService,
		"policy_service", c.PolicyService,
		"security_service", c.SecurityService,
	)
}

// initializeHandlers sets up HTTP request handlers.
// Handlers manage HTTP request/response processing and depend on the previously initialized services.
func (c *Container) initializeHandlers() error {
	var err error

	c.WebhookHandler, err = handlers.NewWebhookHandler(
		c.Logger,
		c.CommentService,
		c.CheckService,
		c.PolicyService,
		c.SecurityService,
		c.StateService,
	)
	if err != nil {
		c.Logger.Error("Failed to create webhook handler", "error", err)
		return err
	}

	c.HealthHandler = handlers.NewHealthHandler(c.Logger, c.HealthService)

	c.Logger.Info(
		"Handlers initialized",
		"webhook_handler",
		c.WebhookHandler,
		"health_handler",
		c.HealthHandler,
	)

	return nil
}

// Shutdown gracefully stops the container and its dependencies.
// This method provides a clean shutdown mechanism for the application.
func (c *Container) Shutdown(ctx context.Context) error {
	c.Logger.Info("Shutting down application container")

	// Perform any necessary cleanup for services or clients here
	// For example, if the GitHub client has a close method, call it

	c.Logger.Info("Application container shutdown complete")

	return nil
}
