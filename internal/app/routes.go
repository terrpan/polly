// Package app provides the application and dependency injection container.
// This file configures the HTTP routes for the application.
package app

import "net/http"

// setupRoutes configures all HTTP routes for the application.
func setupRoutes(mux *http.ServeMux, container *Container) {
	// Register webhook routes with request ID correlation and JSON content type
	mux.HandleFunc("/webhook", withMiddleware(
		requestIDMiddleware,
		jsonContentTypeMiddleware,
	)(container.WebhookRouter.HandleWebhook))

	// Register health routes with no middleware for maximum performance
	mux.HandleFunc("/health", withMiddleware(
		requestIDMiddleware,
		jsonContentTypeMiddleware,
	)(container.HealthHandler.HandleHealthCheck))

	// Example of future API routes with different middleware combinations
	// mux.HandleFunc("/api/v1/resource", withMiddleware(
	//     authMiddleware,
	//     requestIDMiddleware,
	//     jsonContentTypeMiddleware,
	// )(container.ResourceHandler.HandleResource))
}
