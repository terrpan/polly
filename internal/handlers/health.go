package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/terrpan/polly/internal/services"
)

type HealthHandler struct {
	logger        *slog.Logger
	healthService *services.HealthService
}

// NewHealthHandler initializes a new HealthHandler with the provided logger and health service.
func NewHealthHandler(logger *slog.Logger, healthService *services.HealthService) *HealthHandler {
	return &HealthHandler{
		logger:        logger,
		healthService: healthService,
	}
}

// HandleHealthCheck processes health check requests and returns the health status.
func (h *HealthHandler) HandleHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tracer := otel.Tracer("polly/handlers")
	ctx, span := tracer.Start(ctx, "health.handle")
	defer span.End()

	h.logger.InfoContext(ctx, "Received health check request")

	response := h.healthService.CheckHealth(ctx)
	if response == nil {
		span.SetAttributes(attribute.String("error", "health check failed"))
		h.logger.ErrorContext(ctx, "Health check failed")
		http.Error(w, "Health check failed", http.StatusInternalServerError)
		return
	}

	span.SetAttributes(
		attribute.String("health.status", response.Status),
		attribute.String("service.name", response.ServiceName),
		attribute.String("service.version", response.Version),
	)

	if response.Status != "healthy" {
		h.logger.WarnContext(ctx, "Health check indicates issues", "status", response.Status)
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		h.logger.InfoContext(ctx, "Health check successful", "status", response.Status)
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		h.logger.ErrorContext(ctx, "Failed to encode health response", "error", err)
		http.Error(w, "Failed to encode health response", http.StatusInternalServerError)
	}
}
