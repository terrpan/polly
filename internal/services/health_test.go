package services

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Mock OPA Client for health service testing
type MockHealthOPAClient struct {
	mock.Mock
}

func (m *MockHealthOPAClient) GetOpaHealth(ctx context.Context) (*http.Response, error) {
	args := m.Called(ctx)
	return args.Get(0).(*http.Response), args.Error(1)
}

func (m *MockHealthOPAClient) Do(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	args := m.Called(ctx, method, url, body)
	return args.Get(0).(*http.Response), args.Error(1)
}

func TestNewHealthService(t *testing.T) {
	logger := slog.Default()
	mockOPAClient := &MockHealthOPAClient{}

	service := NewHealthService(logger, mockOPAClient)

	assert.NotNil(t, service)
	assert.Equal(t, logger, service.logger)
	assert.Equal(t, mockOPAClient, service.opaClient)
}

func TestHealthService_CheckHealth(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name                string
		opaHealthResponse   *http.Response
		opaHealthError      error
		expectedStatus      string
		expectedOPAStatus   string
		expectDependencies  bool
	}{
		{
			name: "healthy system with healthy OPA",
			opaHealthResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"status": "ok"}`)),
			},
			opaHealthError:     nil,
			expectedStatus:     "healthy",
			expectedOPAStatus:  "healthy",
			expectDependencies: true,
		},
		{
			name: "healthy system with unhealthy OPA",
			opaHealthResponse: &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(strings.NewReader(`{"error": "service unavailable"}`)),
			},
			opaHealthError:     nil,
			expectedStatus:     "healthy", // Main service is still healthy
			expectedOPAStatus:  "unhealthy",
			expectDependencies: true,
		},
		{
			name:               "healthy system with OPA connection error",
			opaHealthResponse:  nil,
			opaHealthError:     fmt.Errorf("connection refused"),
			expectedStatus:     "healthy", // Main service is still healthy
			expectedOPAStatus:  "unhealthy",
			expectDependencies: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockOPAClient := &MockHealthOPAClient{}
			service := NewHealthService(logger, mockOPAClient)

			if tt.opaHealthError != nil {
				mockOPAClient.On("GetOpaHealth", mock.Anything).Return((*http.Response)(nil), tt.opaHealthError)
			} else {
				mockOPAClient.On("GetOpaHealth", mock.Anything).Return(tt.opaHealthResponse, nil)
			}

			ctx := context.Background()
			response := service.CheckHealth(ctx)

			assert.NotNil(t, response)
			assert.Equal(t, tt.expectedStatus, response.Status)
			assert.Equal(t, "polly", response.ServiceName)
			assert.NotEmpty(t, response.OS)
			assert.NotEmpty(t, response.Arch)
			assert.NotEmpty(t, response.GoVersion)
			assert.NotZero(t, response.Timestamp)

			if tt.expectDependencies {
				assert.NotNil(t, response.Dependencies)
				opaStatus, exists := response.Dependencies["opa"]
				assert.True(t, exists)
				assert.Equal(t, tt.expectedOPAStatus, opaStatus.Status)
				assert.NotZero(t, opaStatus.Duration)
				assert.NotZero(t, opaStatus.Timestamp)
			}

			mockOPAClient.AssertExpectations(t)
		})
	}
}

func TestHealthService_CheckOPAHealth(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name                string
		opaHealthResponse   *http.Response
		opaHealthError      error
		expectedStatus      string
		expectedMessage     string
	}{
		{
			name: "OPA healthy",
			opaHealthResponse: &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"status": "ok"}`)),
			},
			opaHealthError:  nil,
			expectedStatus:  "healthy",
			expectedMessage: "",
		},
		{
			name: "OPA unhealthy - service unavailable",
			opaHealthResponse: &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       io.NopCloser(strings.NewReader(`{"error": "service unavailable"}`)),
			},
			opaHealthError:  nil,
			expectedStatus:  "unhealthy",
			expectedMessage: "OPA returned status code: 503",
		},
		{
			name: "OPA unhealthy - internal error",
			opaHealthResponse: &http.Response{
				StatusCode: http.StatusInternalServerError,
				Body:       io.NopCloser(strings.NewReader(`{"error": "internal error"}`)),
			},
			opaHealthError:  nil,
			expectedStatus:  "unhealthy",
			expectedMessage: "OPA returned status code: 500",
		},
		{
			name:            "OPA connection error",
			opaHealthResponse: nil,
			opaHealthError:  fmt.Errorf("connection refused"),
			expectedStatus:  "unhealthy",
			expectedMessage: "Failed to check OPA health: connection refused",
		},
		{
			name:            "OPA timeout error",
			opaHealthResponse: nil,
			opaHealthError:  fmt.Errorf("context deadline exceeded"),
			expectedStatus:  "unhealthy",
			expectedMessage: "Failed to check OPA health: context deadline exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockOPAClient := &MockHealthOPAClient{}
			service := NewHealthService(logger, mockOPAClient)

			if tt.opaHealthError != nil {
				mockOPAClient.On("GetOpaHealth", mock.Anything).Return((*http.Response)(nil), tt.opaHealthError)
			} else {
				mockOPAClient.On("GetOpaHealth", mock.Anything).Return(tt.opaHealthResponse, nil)
			}

			ctx := context.Background()
			start := time.Now()
			check := service.checkOPAHealth(ctx)
			duration := time.Since(start)

			assert.Equal(t, tt.expectedStatus, check.Status)
			assert.Equal(t, tt.expectedMessage, check.Message)
			assert.True(t, check.Duration >= 0)
			assert.True(t, check.Duration <= duration.Milliseconds()+10) // Allow some tolerance
			assert.NotZero(t, check.Timestamp)

			mockOPAClient.AssertExpectations(t)
		})
	}
}

func TestHealthService_CheckHealth_ServiceMetadata(t *testing.T) {
	logger := slog.Default()
	mockOPAClient := &MockHealthOPAClient{}
	service := NewHealthService(logger, mockOPAClient)

	// Mock OPA health check
	mockOPAClient.On("GetOpaHealth", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"status": "ok"}`)),
	}, nil)

	ctx := context.Background()
	response := service.CheckHealth(ctx)

	t.Run("service metadata validation", func(t *testing.T) {
		assert.Equal(t, "polly", response.ServiceName)
		assert.Equal(t, "healthy", response.Status)
		assert.NotEmpty(t, response.OS)
		assert.NotEmpty(t, response.Arch)
		assert.NotEmpty(t, response.GoVersion)
		assert.True(t, strings.HasPrefix(response.GoVersion, "go"))
	})

	t.Run("timestamp validation", func(t *testing.T) {
		now := time.Now()
		assert.True(t, response.Timestamp.Before(now) || response.Timestamp.Equal(now))
		assert.True(t, time.Since(response.Timestamp) < time.Second)
	})

	mockOPAClient.AssertExpectations(t)
}

func TestHealthService_ContextTimeout(t *testing.T) {
	logger := slog.Default()
	mockOPAClient := &MockHealthOPAClient{}
	service := NewHealthService(logger, mockOPAClient)

	t.Run("context timeout during OPA health check", func(t *testing.T) {
		// Create a context that times out quickly
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		// Mock OPA client to simulate slow response
		mockOPAClient.On("GetOpaHealth", mock.MatchedBy(func(ctx context.Context) bool {
			// Verify the context is passed through
			return ctx.Err() != nil || ctx.Deadline().Before(time.Now().Add(time.Second))
		})).Return((*http.Response)(nil), context.DeadlineExceeded)

		// Allow some time for the context to timeout
		time.Sleep(5 * time.Millisecond)

		response := service.CheckHealth(ctx)

		assert.NotNil(t, response)
		assert.Equal(t, "healthy", response.Status) // Main service is healthy
		
		// Check OPA dependency status
		assert.NotNil(t, response.Dependencies)
		opaStatus, exists := response.Dependencies["opa"]
		assert.True(t, exists)
		assert.Equal(t, "unhealthy", opaStatus.Status)
		assert.Contains(t, opaStatus.Message, "Failed to check OPA health")

		mockOPAClient.AssertExpectations(t)
	})
}

func TestHealthService_ConcurrentHealthChecks(t *testing.T) {
	logger := slog.Default()
	mockOPAClient := &MockHealthOPAClient{}
	service := NewHealthService(logger, mockOPAClient)

	// Setup mock to handle multiple concurrent calls
	mockOPAClient.On("GetOpaHealth", mock.Anything).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(`{"status": "ok"}`)),
	}, nil).Times(3) // Expect 3 calls

	ctx := context.Background()

	t.Run("concurrent health checks", func(t *testing.T) {
		// Run multiple health checks concurrently
		results := make(chan *HealthServiceResponse, 3)
		
		for i := 0; i < 3; i++ {
			go func() {
				response := service.CheckHealth(ctx)
				results <- response
			}()
		}

		// Collect all results
		var responses []*HealthServiceResponse
		for i := 0; i < 3; i++ {
			select {
			case response := <-results:
				responses = append(responses, response)
			case <-time.After(time.Second):
				t.Fatal("Timeout waiting for health check response")
			}
		}

		// Verify all responses are valid
		assert.Len(t, responses, 3)
		for i, response := range responses {
			assert.NotNil(t, response, "Response %d should not be nil", i)
			assert.Equal(t, "healthy", response.Status, "Response %d should be healthy", i)
			assert.Equal(t, "polly", response.ServiceName, "Response %d should have correct service name", i)
		}

		mockOPAClient.AssertExpectations(t)
	})
}

func TestHealthService_ErrorRecovery(t *testing.T) {
	logger := slog.Default()
	mockOPAClient := &MockHealthOPAClient{}
	service := NewHealthService(logger, mockOPAClient)

	ctx := context.Background()

	t.Run("service continues working after OPA errors", func(t *testing.T) {
		// First call fails
		mockOPAClient.On("GetOpaHealth", mock.Anything).Return((*http.Response)(nil), fmt.Errorf("network error")).Once()
		
		response1 := service.CheckHealth(ctx)
		assert.Equal(t, "healthy", response1.Status)
		assert.Equal(t, "unhealthy", response1.Dependencies["opa"].Status)

		// Second call succeeds
		mockOPAClient.On("GetOpaHealth", mock.Anything).Return(&http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"status": "ok"}`)),
		}, nil).Once()

		response2 := service.CheckHealth(ctx)
		assert.Equal(t, "healthy", response2.Status)
		assert.Equal(t, "healthy", response2.Dependencies["opa"].Status)

		mockOPAClient.AssertExpectations(t)
	})
}
