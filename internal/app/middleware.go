// Package app provides the application and dependency injection container.
// This file contains HTTP middleware for the application.
package app

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/terrpan/polly/internal/config"
)

// jsonContentType is a constant for the Content-Type header value used in the middleware
const jsonContent = "application/json"

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

// requestIDKey is the context key for storing request IDs
const requestIDKey contextKey = "request_id"

// Middleware represents a standard middleware function
type Middleware func(http.HandlerFunc) http.HandlerFunc

// jsonContentTypeMiddleware sets the Content-Type header to application/json
func jsonContentTypeMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", jsonContent)
		next.ServeHTTP(w, r)
	}
}

// requestIDMiddleware adds request ID correlation to HTTP requests
func requestIDMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip if feature is disabled
		if !config.AppConfig.Logger.EnableRequestID {
			next.ServeHTTP(w, r)
			return
		}

		ctx := r.Context()
		// 1. Check for existing request ID from load balancer/proxy
		requestID := r.Header.Get("X-Request-Id")
		if requestID == "" {
			requestID = r.Header.Get("X-Trace-Id")
		}
		// 2. Generate UUID if no external ID (independent of tracing)
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// 3. Store in context for use throughout the request
		ctx = context.WithValue(ctx, requestIDKey, requestID)

		// 4. Return in response header for debugging
		w.Header().Set("X-Request-Id", requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// withMiddleware applies a variadic list of middleware to a handler
// Usage: withMiddleware(middleware1, middleware2, handler)
func withMiddleware(middlewares ...Middleware) func(http.HandlerFunc) http.HandlerFunc {
	return func(handler http.HandlerFunc) http.HandlerFunc {
		// Apply middleware in reverse order so they execute in the correct order
		for i := len(middlewares) - 1; i >= 0; i-- {
			handler = middlewares[i](handler)
		}

		return handler
	}
}

// GetRequestID extracts the request ID from context
func GetRequestID(ctx context.Context) string {
	if requestID := ctx.Value(requestIDKey); requestID != nil {
		if id, ok := requestID.(string); ok {
			return id
		}
	}

	return ""
}
