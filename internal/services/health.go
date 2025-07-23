package services

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"runtime"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/config"
	"github.com/terrpan/polly/internal/storage"
)

type HealthService struct {
	logger    *slog.Logger
	opaClient *clients.OPAClient
	store     storage.Store
}

type HealthServiceResponse struct {
	ServiceName  string                     `json:"service_name"`
	Status       string                     `json:"status"`
	OS           string                     `json:"os"`
	Arch         string                     `json:"architecture"`
	Version      string                     `json:"version"`
	Commit       string                     `json:"commit"`
	BuildTime    string                     `json:"build_time"`
	GoVersion    string                     `json:"go_version"`
	Dependencies map[string]DependencyCheck `json:"dependencies,omitempty"` // Optional field for dependencies status
	Timestamp    time.Time                  `json:"timestamp"`
}

type DependencyCheck struct {
	Status    string    `json:"status"`
	Message   string    `json:"message,omitempty"` // Optional message for the dependency status
	Duration  int64     `json:"duration_ms"`
	Timestamp time.Time `json:"timestamp"`
}

// NewHealthService initializes a new HealthService with the provided logger.
func NewHealthService(
	logger *slog.Logger,
	opaClient *clients.OPAClient,
	store storage.Store,
) *HealthService {
	return &HealthService{
		logger:    logger,
		opaClient: opaClient,
		store:     store,
	}
}

// CheckHealth performs a health check and returns a status message.
func (s *HealthService) CheckHealth(ctx context.Context) *HealthServiceResponse {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "health.check")
	defer span.End()

	s.logger.DebugContext(ctx, "Performing health check")

	dependencies := make(map[string]DependencyCheck)
	dependencies["opa"] = s.checkOPAHealth(ctx)
	dependencies["storage"] = s.checkStorageHealth(ctx)

	overallStatus := s.getOverallStatus(dependencies)
	s.logger.DebugContext(ctx, "Overall health status", "status", overallStatus)

	// Fetching build information dynamically
	version, commit, buildTime := config.GetBuildInfo()
	return &HealthServiceResponse{
		ServiceName:  "polly",
		Status:       overallStatus,
		OS:           runtime.GOOS,      // This could be dynamically fetched using runtime.GOOS
		Arch:         runtime.GOARCH,    // This could be dynamically fetched using runtime.GOARCH
		Version:      version,           // This should be dynamically fetched from build info
		Commit:       commit,            // This should be dynamically fetched from build info
		BuildTime:    buildTime,         // This should be dynamically fetched from build info
		GoVersion:    runtime.Version(), // This should be dynamically fetched using runtime.Version()
		Timestamp:    time.Now().UTC(),
		Dependencies: dependencies,
	}

}

// checkStorageHealth checks the health of the storage service.
func (s *HealthService) checkStorageHealth(ctx context.Context) DependencyCheck {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "health.check_storage")
	defer span.End()

	start := time.Now()

	if s.store == nil {
		span.SetAttributes(attribute.String("error", "Storage not initialized"))
		s.logger.WarnContext(ctx, "Storage is not initialized")
		return DependencyCheck{
			Status:    "error",
			Message:   "Storage not initialized",
			Duration:  time.Since(start).Milliseconds(),
			Timestamp: time.Now().UTC(),
		}
	}

	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	span.SetAttributes(attribute.String("storage.timeout", "3s"))
	response, err := s.store.Ping(checkCtx)

	if err != nil {
		span.SetAttributes(
			attribute.String("storage.status", "error"),
			attribute.String("error", err.Error()),
		)
		s.logger.ErrorContext(ctx, "Failed to ping storage", "error", err)
		return DependencyCheck{
			Status:    "error",
			Message:   "Failed to connect to storage: " + err.Error(),
			Duration:  time.Since(start).Milliseconds(),
			Timestamp: time.Now().UTC(),
		}
	}

	span.SetAttributes(
		attribute.String("storage.status", "healthy"),
		attribute.String("storage.response", response),
	)
	s.logger.DebugContext(ctx, "Storage health check passed", "response", response)
	return DependencyCheck{
		Status:    "healthy",
		Message:   "Storage service is responding: " + response,
		Duration:  time.Since(start).Milliseconds(),
		Timestamp: time.Now().UTC(),
	}
}

// checkOpaHealth checks the health of the OPA service.
func (s *HealthService) checkOPAHealth(ctx context.Context) DependencyCheck {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "health.check_opa")
	defer span.End()

	start := time.Now()

	if s.opaClient == nil {
		span.SetAttributes(attribute.String("error", "OPA client not initialized"))
		s.logger.WarnContext(ctx, "OPA client is not initialized")
		return DependencyCheck{
			Status:    "error",
			Message:   "OPA client is not initialized",
			Duration:  time.Since(start).Milliseconds(),
			Timestamp: time.Now().UTC(),
		}
	}

	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	span.SetAttributes(attribute.String("opa.timeout", "5s"))
	resp, err := s.opaClient.GetOpaHealth(checkCtx)

	if err != nil {
		span.SetAttributes(
			attribute.String("opa.status", "error"),
			attribute.String("error", err.Error()),
		)
		s.logger.ErrorContext(ctx, "Failed to get OPA health", "error", err)
		return DependencyCheck{
			Status:    "error",
			Message:   "Failed to connect to OPA: " + err.Error(),
			Duration:  time.Since(start).Milliseconds(),
			Timestamp: time.Now().UTC(),
		}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		span.SetAttributes(
			attribute.String("opa.status", "healthy"),
			attribute.Int("opa.response_code", resp.StatusCode),
		)
		s.logger.DebugContext(ctx, "OPA health check passed")
		return DependencyCheck{
			Status:    "healthy",
			Message:   "OPA service is responding",
			Duration:  time.Since(start).Milliseconds(),
			Timestamp: time.Now().UTC(),
		}
	} else {
		span.SetAttributes(
			attribute.String("opa.status", "degraded"),
			attribute.Int("opa.response_code", resp.StatusCode),
		)
		s.logger.WarnContext(ctx, "OPA health check returned non-200 status",
			"status_code", resp.StatusCode)
		return DependencyCheck{
			Status:    "degraded",
			Message:   fmt.Sprintf("OPA returned status code: %d", resp.StatusCode),
			Duration:  time.Since(start).Milliseconds(),
			Timestamp: time.Now().UTC(),
		}
	}
}

// getOverallStatus aggregates the health status of all dependencies.
func (s *HealthService) getOverallStatus(dependencies map[string]DependencyCheck) string {
	hasError := false
	hasDegraded := false

	for _, dep := range dependencies {
		switch dep.Status {
		case "error":
			hasError = true
		case "degraded":
			hasDegraded = true
		}
	}
	if hasError {
		return "error"
	}
	if hasDegraded {
		return "degraded"
	}
	return "healthy"
}
