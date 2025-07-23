package clients

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

// OPAClientTestSuite provides a test suite for OPA client tests
type OPAClientTestSuite struct {
	suite.Suite
	ctx        context.Context
	mockServer *httptest.Server
	client     *OPAClient
}

// SetupSuite runs once before all tests in the suite
func (suite *OPAClientTestSuite) SetupSuite() {
	suite.ctx = context.Background()
}

// SetupTest runs before each test
func (suite *OPAClientTestSuite) SetupTest() {
	// Create mock server with OPA endpoints
	suite.mockServer = httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			suite.handleMockRequest(w, r)
		}),
	)

	// Create OPA client pointing to mock server
	var err error
	suite.client, err = NewOPAClient(suite.mockServer.URL)
	suite.Require().NoError(err)
}

// TearDownTest runs after each test
func (suite *OPAClientTestSuite) TearDownTest() {
	if suite.mockServer != nil {
		suite.mockServer.Close()
	}
}

// handleMockRequest handles all mock server requests
func (suite *OPAClientTestSuite) handleMockRequest(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/test/success":
		w.WriteHeader(http.StatusOK)
		writeTestResponse(w, []byte(`{"result": true}`))
	case "/test/not-found":
		w.WriteHeader(http.StatusNotFound)
		writeTestResponse(w, []byte(`{"message": "Not Found"}`))
	case "/test/server-error":
		w.WriteHeader(http.StatusInternalServerError)
		writeTestResponse(w, []byte(`{"message": "Internal Server Error"}`))
	case "/test/post":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusOK)
		writeTestResponse(w, []byte(`{"result": "created"}`))
	case "/health":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		writeTestResponse(w, []byte(`{"status": "ok"}`))
	case "/test":
		// For context cancellation test
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		writeTestResponse(w, []byte(`{"result": true}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (suite *OPAClientTestSuite) TestNewOPAClient() {
	tests := []struct {
		name          string
		baseURL       string
		errorMessage  string
		expectedError bool
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
		suite.Run(tt.name, func() {
			client, err := NewOPAClient(tt.baseURL)

			if tt.expectedError {
				suite.Assert().Error(err)
				suite.Assert().Equal(tt.errorMessage, err.Error())
				suite.Assert().Nil(client)
			} else {
				suite.Assert().NoError(err)
				suite.Assert().NotNil(client)
				suite.Assert().Equal(tt.baseURL, client.BaseURL)
				suite.Assert().NotNil(client.HTTPClient)
				suite.Assert().Equal(30*time.Second, client.HTTPClient.Timeout)
			}
		})
	}
}

func (suite *OPAClientTestSuite) TestDo() {
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
		suite.Run(tt.name, func() {
			url := suite.mockServer.URL + tt.path

			var body io.Reader
			if tt.body != "" {
				body = strings.NewReader(tt.body)
			}

			resp, err := suite.client.Do(suite.ctx, tt.method, url, body)

			if tt.expectedError {
				suite.Assert().Error(err)
				suite.Assert().Nil(resp)
			} else {
				suite.Assert().NoError(err)
				suite.Assert().NotNil(resp)
				suite.Assert().Equal(tt.expectedStatus, resp.StatusCode)
				if err := resp.Body.Close(); err != nil {
					suite.T().Logf("Failed to close response body: %v", err)
				}
			}
		})
	}
}

func (suite *OPAClientTestSuite) TestGetOpaHealth() {
	tests := []struct {
		name           string
		expectedStatus int
		expectedError  bool
	}{
		{
			name:           "healthy OPA instance",
			expectedStatus: http.StatusOK,
			expectedError:  false,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			resp, err := suite.client.GetOpaHealth(suite.ctx)

			if tt.expectedError {
				suite.Assert().Error(err)
				suite.Assert().Nil(resp)
			} else {
				suite.Assert().NoError(err)
				suite.Assert().NotNil(resp)
				suite.Assert().Equal(tt.expectedStatus, resp.StatusCode)
				suite.Assert().Equal(http.MethodGet, resp.Request.Method)
				suite.Assert().Contains(resp.Request.URL.Path, "/health")
				if err := resp.Body.Close(); err != nil {
					suite.T().Logf("Failed to close response body: %v", err)
				}
			}
		})
	}
}

func (suite *OPAClientTestSuite) TestContextCancellation() {
	suite.Run("context cancellation", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		_, err := suite.client.Do(ctx, http.MethodGet, suite.mockServer.URL+"/test", nil)

		// Should get a context deadline exceeded error
		suite.Assert().Error(err)
		suite.Assert().Contains(err.Error(), "context deadline exceeded")
	})
}

func (suite *OPAClientTestSuite) TestInvalidURL() {
	client, err := NewOPAClient("http://localhost:8181")
	suite.Require().NoError(err)

	suite.Run("invalid URL in Do method", func() {
		// Test with invalid URL
		_, err := client.Do(suite.ctx, http.MethodGet, "://invalid-url", nil)
		suite.Assert().Error(err)
	})
}

func (suite *OPAClientTestSuite) TestHTTPClientConfiguration() {
	baseURL := "http://localhost:8181"
	client, err := NewOPAClient(baseURL)
	suite.Require().NoError(err)

	suite.Run("verify HTTP client configuration", func() {
		suite.Assert().NotNil(client.HTTPClient)
		suite.Assert().Equal(30*time.Second, client.HTTPClient.Timeout)

		// Verify that the transport is wrapped with OpenTelemetry
		suite.Assert().NotNil(client.HTTPClient.Transport)
	})
}

// Run the test suite
func TestOPAClientTestSuite(t *testing.T) {
	suite.Run(t, new(OPAClientTestSuite))
}
