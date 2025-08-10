// Package app provides the application and dependency injection container.
// This file initializes and wires together all components of the application.
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

// serviceRegistration defines how to create and register services
type serviceRegistration struct {
	init func(*Container) error
	name string
}

// Container holds all application dependencies
type Container struct {
	logger *slog.Logger

	// Storage
	store        storage.Store
	stateService *services.StateService

	// Clients
	gitHubClient *clients.GitHubClient
	opaClient    *clients.OPAClient

	// Services
	commentService     *services.CommentService
	healthService      *services.HealthService
	checkService       *services.CheckService
	policyService      *services.PolicyService
	policyCacheService *services.PolicyCacheService
	securityService    *services.SecurityService

	// Handlers - only these need external access
	WebhookRouter *handlers.WebhookRouter
	HealthHandler *handlers.HealthHandler

	// Telemetry helpers cache
	telemetryHelpers map[string]*telemetry.TelemetryHelper
}

// Logger returns the container's logger
func (c *Container) Logger() *slog.Logger {
	return c.logger
}

// NewContainer initializes a new Container with all dependencies
func NewContainer(ctx context.Context) (*Container, error) {
	c := &Container{
		logger:           config.NewLogger(),
		telemetryHelpers: make(map[string]*telemetry.TelemetryHelper),
	}
	c.logger.Info("Initializing application container")

	if err := c.initStorage(); err != nil {
		return nil, err
	}

	if err := c.initClients(ctx); err != nil {
		return nil, err
	}

	if err := c.initServices(); err != nil {
		return nil, err
	}

	if err := c.initHandlers(); err != nil {
		return nil, err
	}

	c.logger.Info("Application container initialized successfully")

	return c, nil
}

// getTelemetryHelper returns cached telemetry helper or creates new one
func (c *Container) getTelemetryHelper(name string) *telemetry.TelemetryHelper {
	if helper, exists := c.telemetryHelpers[name]; exists {
		return helper
	}

	helper := telemetry.NewTelemetryHelper(name)
	c.telemetryHelpers[name] = helper

	return helper
}

// initStorage initializes the storage layer
func (c *Container) initStorage() error {
	c.logger.Info("Initializing storage", "type", config.AppConfig.Storage.Type)

	store, err := storage.NewStore(config.AppConfig.Storage)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %w", err)
	}

	c.store = store

	return nil
}

// initClients initializes the clients
func (c *Container) initClients(ctx context.Context) error {
	c.logger.Info("Initializing clients")

	if err := c.initGitHubClient(ctx); err != nil {
		return err
	}

	opaClient, err := clients.NewOPAClient(config.AppConfig.Opa.ServerURL)
	if err != nil {
		return fmt.Errorf("failed to create OPA client: %w", err)
	}

	c.opaClient = opaClient

	c.logger.Info("Clients initialized successfully")

	return nil
}

func (c *Container) initGitHubClient(ctx context.Context) error {
	switch {
	case config.IsGitHubAppConfigured():
		c.logger.Info("Using GitHub App authentication")

		githubConfig, err := config.LoadGitHubAppConfig()
		if err != nil {
			return fmt.Errorf("failed to load GitHub App config: %w", err)
		}

		c.gitHubClient, err = clients.NewGitHubAppClient(ctx, *githubConfig)
		if err != nil {
			return fmt.Errorf("failed to create GitHub App client: %w", err)
		}
	case config.AppConfig.GitHubToken != "":
		c.logger.Info("Using Personal Access Token authentication")

		c.gitHubClient = clients.NewGitHubClient(ctx)
		if err := c.gitHubClient.Authenticate(ctx, config.AppConfig.GitHubToken); err != nil {
			return fmt.Errorf("failed to authenticate GitHub client: %w", err)
		}
	default:
		return fmt.Errorf("no GitHub authentication configured (need either GitHub App or PAT)")
	}

	c.logger.Info("GitHub client initialized")

	return nil
}

func (c *Container) createServiceRegistrations() []serviceRegistration {
	return []serviceRegistration{
		{
			name: "StateService",
			init: func(c *Container) error {
				c.stateService = services.NewStateService(
					c.store,
					c.logger,
					c.getTelemetryHelper("polly/state"),
				)
				return nil
			},
		},
		{
			name: "CommentService",
			init: func(c *Container) error {
				c.commentService = services.NewCommentService(
					c.gitHubClient,
					c.logger,
					c.getTelemetryHelper("polly/comment"),
				)
				return nil
			},
		},
		{
			name: "HealthService",
			init: func(c *Container) error {
				c.healthService = services.NewHealthService(
					c.logger,
					c.opaClient,
					c.store,
					c.getTelemetryHelper("polly/health"),
				)
				return nil
			},
		},
		{
			name: "CheckService",
			init: func(c *Container) error {
				c.checkService = services.NewCheckService(
					c.gitHubClient,
					c.logger,
					c.getTelemetryHelper("polly/checks"),
				)
				return nil
			},
		},
		{
			name: "PolicyService",
			init: func(c *Container) error {
				c.policyService = services.NewPolicyService(
					c.opaClient,
					c.logger,
					c.getTelemetryHelper("polly/policy"),
					nil,
				)
				evaluators := services.NewStandardEvaluators(c.policyService)
				c.policyService = services.NewPolicyService(
					c.opaClient,
					c.logger,
					c.getTelemetryHelper("polly/policy"),
					evaluators,
				)
				return nil
			},
		},
		{
			name: "SecurityService",
			init: func(c *Container) error {
				securityDetectors := []services.ContentDetector{
					&services.SPDXDetector{},
					&services.TrivyJSONDetector{},
					&services.SARIFDetector{},
				}
				c.securityService = services.NewSecurityService(
					c.gitHubClient,
					c.logger,
					c.getTelemetryHelper("polly/security"),
					securityDetectors...,
				)
				return nil
			},
		},
		{
			name: "PolicyCacheService",
			init: func(c *Container) error {
				c.policyCacheService = services.NewPolicyCacheService(
					c.policyService,
					c.stateService,
					c.logger,
					c.getTelemetryHelper("polly/cache"),
				)
				return nil
			},
		},
	}
}

func (c *Container) initServices() error {
	registrations := c.createServiceRegistrations()
	for _, registration := range registrations {
		c.logger.Info("Initializing service", "name", registration.name)

		if err := registration.init(c); err != nil {
			return fmt.Errorf("failed to initialize %s: %w", registration.name, err)
		}
	}

	c.logger.Info("Services initialized successfully")

	return nil
}

func (c *Container) initHandlers() error {
	webhookRouter, err := handlers.NewWebhookRouter(
		c.logger,
		c.commentService,
		c.checkService,
		c.policyService,
		c.policyCacheService,
		c.securityService,
		c.stateService,
	)
	if err != nil {
		c.logger.Error("Failed to create webhook router", "error", err)
		return err
	}

	c.WebhookRouter = webhookRouter

	c.HealthHandler = handlers.NewHealthHandler(c.logger, c.healthService)

	c.logger.Info("Handlers initialized successfully")

	return nil
}

// Shutdown gracefully stops the container and its dependencies
func (c *Container) Shutdown(ctx context.Context) error {
	c.logger.Info("Shutting down application container")
	c.logger.Info("Application container shutdown complete")

	return nil
}
