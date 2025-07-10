package clients

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOPAClient(t *testing.T) {
	tests := []struct {
		name          string
		baseURL       string
		expectedError bool
		errorMessage  string
	}{
		{
			name:          "valid base URL",
			baseURL:       "http://localhost:8181",
			expectedError: false,
		},
		{
			name:          "empty base URL",
			baseURL:       "",
			expectedError: true,
			errorMessage:  "base URL cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewOPAClient(tt.baseURL)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Equal(t, tt.errorMessage, err.Error())
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, tt.baseURL, client.BaseURL)
				assert.NotNil(t, client.HTTPClient)
				assert.Equal(t, 30*time.Second, client.HTTPClient.Timeout)
			}
		})
	}
}

func TestOPAClient_Do(t *testing.T) {
	// Mock server to test different HTTP scenarios
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/test/success":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result": true}`))
		case "/test/not-found":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message": "Not Found"}`))
		case "/test/server-error":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message": "Internal Server Error"}`))
		case "/test/post":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"result": "created"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, err := NewOPAClient(server.URL)
	require.NoError(t, err)

	tests := []struct {
		name           string
		method         string
		path           string
		body           string
		expectedStatus int
		expectedError  bool
	}{
		{
			name:           "successful GET request",
			method:         http.MethodGet,
			path:           "/test/success",
			body:           "",
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:           "successful POST request",
			method:         http.MethodPost,
			path:           "/test/post",
			body:           `{"input": "test"}`,
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
		{
			name:           "not found",
			method:         http.MethodGet,
			path:           "/test/not-found",
			body:           "",
			expectedStatus: http.StatusNotFound,
			expectedError:  false,
		},
		{
			name:           "server error",
			method:         http.MethodGet,
			path:           "/test/server-error",
			body:           "",
			expectedStatus: http.StatusInternalServerError,
			expectedError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			url := server.URL + tt.path

			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}

			resp, err := client.Do(ctx, tt.method, url, body)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tt.expectedStatus, resp.StatusCode)
				_ = resp.Body.Close()
			}
		})
	}
}

func TestOPAClient_GetOpaHealth(t *testing.T) {
	// Mock server to test health endpoint scenarios
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status": "ok"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tests := []struct {
		name           string
		baseURL        string
		expectedStatus int
		expectedError  bool
	}{
		{
			name:           "healthy OPA instance",
			baseURL:        server.URL,
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewOPAClient(tt.baseURL)
			require.NoError(t, err)

			ctx := context.Background()
			resp, err := client.GetOpaHealth(ctx)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tt.expectedStatus, resp.StatusCode)
				assert.Equal(t, http.MethodGet, resp.Request.Method)
				assert.Contains(t, resp.Request.URL.Path, "/health")
				_ = resp.Body.Close()
			}
		})
	}
}

func TestOPAClient_ContextCancellation(t *testing.T) {
	// Mock server that introduces delay to test context cancellation
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate slow response
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result": true}`))
	}))
	defer server.Close()

	client, err := NewOPAClient(server.URL)
	require.NoError(t, err)

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := client.Do(ctx, http.MethodGet, server.URL+"/test", nil)

		// Should get a context deadline exceeded error
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "context deadline exceeded")
	})
}

func TestOPAClient_InvalidURL(t *testing.T) {
	client, err := NewOPAClient("http://localhost:8181")
	require.NoError(t, err)

	t.Run("invalid URL in Do method", func(t *testing.T) {
		ctx := context.Background()

		// Test with invalid URL
		_, err := client.Do(ctx, http.MethodGet, "://invalid-url", nil)
		assert.Error(t, err)
	})
}

func TestOPAClient_HTTPClientConfiguration(t *testing.T) {
	baseURL := "http://localhost:8181"
	client, err := NewOPAClient(baseURL)
	require.NoError(t, err)

	t.Run("verify HTTP client configuration", func(t *testing.T) {
		assert.NotNil(t, client.HTTPClient)
		assert.Equal(t, 30*time.Second, client.HTTPClient.Timeout)

		// Verify that the transport is wrapped with OpenTelemetry
		assert.NotNil(t, client.HTTPClient.Transport)
	})
}
