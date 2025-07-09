package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJsonContentTypeMiddleware(t *testing.T) {
	// Create a test handler that will be wrapped by the middleware
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("test response"))
	})

	// Wrap the handler with the middleware
	wrappedHandler := jsonContentTypeMiddleware(testHandler)

	// Create a test request
	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()

	// Call the wrapped handler
	wrappedHandler.ServeHTTP(w, req)

	// Verify the Content-Type header is set correctly
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "test response", w.Body.String())
}

func TestJsonContentMiddleware_Constants(t *testing.T) {
	// Test that the constant is properly defined
	assert.Equal(t, "application/json", jsonContent)
}

func TestSetupRoutes_Structure(t *testing.T) {
	mux := http.NewServeMux()
	container := &Container{
		// Note: In a unit test, handlers can be nil since we're just testing route setup
		WebhookHandler: nil,
		HealthHandler:  nil,
	}

	// This tests that setupRoutes doesn't panic when called
	assert.NotPanics(t, func() {
		setupRoutes(mux, container)
	})
}

func TestSetupRoutes_Integration(t *testing.T) {
	t.Skip("Integration test requires fully initialized container with handlers")

	// Example of how integration test would work:
	// 1. Create container with real handlers
	// 2. Setup routes
	// 3. Make test requests to each route
	// 4. Verify responses and middleware behavior
}
