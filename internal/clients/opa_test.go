package clients

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEvaluatePolicy_SetsContentTypeHeader(t *testing.T) {
	// Create a test server to capture the request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the Content-Type header is set correctly
		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected Content-Type: application/json, got: %s", contentType)
		}
		
		// Verify it's a POST request
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST request, got: %s", r.Method)
		}
		
		// Return a simple response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": true}`))
	}))
	defer server.Close()

	// Create OPA client with test server URL
	client, err := NewOPAClient(server.URL)
	if err != nil {
		t.Fatalf("Failed to create OPA client: %v", err)
	}

	// Test payload
	payload := map[string]interface{}{
		"input": map[string]string{
			"message": "test",
		},
	}

	// Call EvaluatePolicy
	ctx := context.Background()
	resp, err := client.EvaluatePolicy(ctx, "/v1/data/test/policy", payload)
	if err != nil {
		t.Fatalf("EvaluatePolicy failed: %v", err)
	}
	defer resp.Body.Close()

	// Verify response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code 200, got: %d", resp.StatusCode)
	}
}