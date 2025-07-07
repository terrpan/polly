package app

import "net/http"

// setupRoutes configures all HTTP routes for the application.
func setupRoutes(mux *http.ServeMux, container *Container) {
	// Register the webhook handler
	mux.HandleFunc("/webhook", jsonContentTypeMiddleware(container.WebhookHandler.HandleWebhook))

	// Register the health check handler
	mux.HandleFunc("/health", jsonContentTypeMiddleware(container.HealthHandler.HandleHealthCheck))
	// Add any additional routes here as needed
	// e.g., mux.HandleFunc("/api/v1/resource", jsonContentTypeMiddleware(container.ResourceHandler.HandleResource))
}
