# Container Development Guide

## Overview
This guide explains how to work with Polly's dependency injection container using the Service Registry Pattern implemented in `internal/app/container.go`.

## Architecture Overview

The container uses a **Service Registry Pattern** that simplifies adding new services while maintaining type safety and proper encapsulation.

### Key Components

1. **Container Struct**: Holds all application dependencies
2. **Service Registry**: Centralized service registration and initialization
3. **Private Encapsulation**: Internal services are private, only handlers exported
4. **Type Safety**: All dependencies are concrete types with compile-time checking

## Container Structure

```go
type Container struct {
    logger *slog.Logger

    // Storage
    store        storage.Store
    stateService *services.StateService

    // Clients (private)
    gitHubClient *clients.GitHubClient
    opaClient    *clients.OPAClient

    // Services (private)
    commentService     *services.CommentService
    healthService      *services.HealthService
    checkService       *services.CheckService
    policyService      *services.PolicyService
    policyCacheService *services.PolicyCacheService
    securityService    *services.SecurityService

    // Handlers - only these are exported for external access
    WebhookRouter *handlers.WebhookRouter
    HealthHandler *handlers.HealthHandler

    // Telemetry helpers cache
    telemetryHelpers map[string]*telemetry.TelemetryHelper
}
```

## Adding a New Service

Adding a new service requires only one change in one place:

### 1. Add Service Field to Container
```go
type Container struct {
    // ... existing fields ...

    // Add your new service as a private field
    awesomeService *services.AwesomeService
}
```

### 2. Add Service Registration
In `createServiceRegistrations()`, add your service to the registry:

```go
func (c *Container) createServiceRegistrations() []serviceRegistration {
    return []serviceRegistration{
        // ... existing services ...

        {
            name: "AwesomeService",
            init: func(c *Container) error {
                c.awesomeService = services.NewAwesomeService(
                    c.gitHubClient,           // Dependencies
                    c.logger,
                    c.getTelemetryHelper("polly/awesome"),
                )
                return nil
            },
        },
    }
}
```

That's it! The service will be automatically:
- Initialized in dependency order
- Logged during startup
- Available to handlers that need it

### 3. Using the Service in Handlers
If a handler needs the new service, add it to the handler's constructor:

```go
func NewWebhookRouter(
    logger *slog.Logger,
    // ... existing services ...
    awesomeService *services.AwesomeService,  // Add new service
) (*WebhookRouter, error) {
    // Use the service
}
```

And update the container's `initHandlers()` method:

```go
func (c *Container) initHandlers() error {
    webhookRouter, err := handlers.NewWebhookRouter(
        c.logger,
        // ... existing services ...
        c.awesomeService,  // Pass the new service
    )
    // ...
}
```

## Service Dependencies

Services are initialized in the order they appear in the registry, so dependencies must be declared before dependents:

```go
{
    name: "BaseService",        // Must come first
    init: func(c *Container) error {
        c.baseService = services.NewBaseService(c.gitHubClient, c.logger, telemetry)
        return nil
    },
},
{
    name: "DependentService",   // Can use BaseService
    init: func(c *Container) error {
        c.dependentService = services.NewDependentService(
            c.baseService,      // Dependency on BaseService
            c.logger,
            telemetry,
        )
        return nil
    },
},
```

## Telemetry Integration

Every service should use telemetry for observability:

```go
{
    name: "MyService",
    init: func(c *Container) error {
        c.myService = services.NewMyService(
            c.gitHubClient,
            c.logger,
            c.getTelemetryHelper("polly/my-service"),  // Consistent naming
        )
        return nil
    },
},
```

Telemetry helper naming convention: `"polly/{service-name}"`

## Error Handling

Service initialization errors are automatically wrapped with context:

```go
{
    name: "MyService",
    init: func(c *Container) error {
        service, err := services.NewMyService(deps...)
        if err != nil {
            return fmt.Errorf("failed to initialize MyService: %w", err)
        }
        c.myService = service
        return nil
    },
},
```

The container will log the error and fail gracefully if any service fails to initialize.

## Accessing Services

### From External Code (Server, Main)
Only use the exported handlers:
```go
container, err := app.NewContainer(ctx)
if err != nil {
    log.Fatal(err)
}

// ✅ Correct - use exported handlers
server := app.NewServer(container.WebhookRouter, container.HealthHandler)

// ✅ Correct - use Logger() method
container.Logger().Info("Starting server")

// ❌ Wrong - don't access private services
// container.gitHubClient // This won't compile
```

### From Tests
For unit tests, create minimal containers or use mocks:
```go
func TestMyHandler(t *testing.T) {
    container := &app.Container{
        // Only set what you need for the test
    }

    // Or create a real container for integration tests
    container, err := app.NewContainer(ctx)
    require.NoError(t, err)
}
```

## Best Practices

### 1. Keep Services Private
Only export what external components need (handlers for HTTP server).

### 2. Use Constructor Pattern
All services should use `NewXxxService()` constructors.

### 3. Dependency Injection Only
Don't access global variables or singletons from within services.

### 4. Error Handling
Always wrap initialization errors with meaningful context.

### 5. Telemetry
Every service should have telemetry for observability.

### 6. Type Safety
Use concrete types, avoid `interface{}` or runtime type assertions.

## Examples

### Simple Service
```go
{
    name: "NotificationService",
    init: func(c *Container) error {
        c.notificationService = services.NewNotificationService(
            c.gitHubClient,
            c.logger,
            c.getTelemetryHelper("polly/notification"),
        )
        return nil
    },
},
```

### Service with Complex Dependencies
```go
{
    name: "AnalyticsService",
    init: func(c *Container) error {
        c.analyticsService = services.NewAnalyticsService(
            c.gitHubClient,
            c.store,
            c.policyService,        // Depends on policy service
            c.logger,
            c.getTelemetryHelper("polly/analytics"),
        )
        return nil
    },
},
```

### Service with Configuration
```go
{
    name: "CacheService",
    init: func(c *Container) error {
        config := services.CacheConfig{
            TTL:     config.AppConfig.CacheTTL,
            MaxSize: config.AppConfig.CacheMaxSize,
        }
        c.cacheService = services.NewCacheService(
            config,
            c.logger,
            c.getTelemetryHelper("polly/cache"),
        )
        return nil
    },
},
```

## Troubleshooting

### Service Not Available
If you get "undefined field" errors, check:
1. Is the service field added to the Container struct?
2. Is the service registered in `createServiceRegistrations()`?
3. Are you trying to access a private field from external code?

### Initialization Order Issues
If a service fails to initialize due to missing dependencies:
1. Check the order in `createServiceRegistrations()`
2. Ensure dependencies come before dependents
3. Verify all required dependencies are available

### Function Length Warning
The `createServiceRegistrations()` function is allowed to exceed 80 lines as it's pure configuration. This is explicitly ignored in the linter configuration.

## Related Documentation
- [ADR-010: Container Service Registry Pattern](./ADR-010-container-service-registry-pattern.md)
- [Architecture Overview](./ARCHITECTURE.md)
- [Testing Guide](./TESTING.md)
