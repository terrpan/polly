package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/terrpan/polly/internal/clients"
)

// Mock OPA Client for testing
type MockOPAClient struct {
	mock.Mock
}

func (m *MockOPAClient) Do(ctx context.Context, method, url string, body io.Reader) (*http.Response, error) {
	args := m.Called(ctx, method, url, body)
	return args.Get(0).(*http.Response), args.Error(1)
}

func (m *MockOPAClient) GetOpaHealth(ctx context.Context) (*http.Response, error) {
	args := m.Called(ctx)
	return args.Get(0).(*http.Response), args.Error(1)
}

func TestNewPolicyService(t *testing.T) {
	logger := slog.Default()
	opaClient := &MockOPAClient{}

	policyService := NewPolicyService(opaClient, logger)

	assert.NotNil(t, policyService)
	assert.Equal(t, opaClient, policyService.opaClient)
	assert.Equal(t, logger, policyService.logger)
}

func TestPolicyService_EvaluateHelloPolicy(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name           string
		input          HelloInput
		mockResponse   string
		mockStatusCode int
		mockError      error
		expectedResult bool
		expectedError  bool
	}{
		{
			name:           "successful evaluation - true result",
			input:          HelloInput{Message: "Hello"},
			mockResponse:   `{"result": true}`,
			mockStatusCode: http.StatusOK,
			mockError:      nil,
			expectedResult: true,
			expectedError:  false,
		},
		{
			name:           "successful evaluation - false result",
			input:          HelloInput{Message: "Goodbye"},
			mockResponse:   `{"result": false}`,
			mockStatusCode: http.StatusOK,
			mockError:      nil,
			expectedResult: false,
			expectedError:  false,
		},
		{
			name:           "server error",
			input:          HelloInput{Message: "Hello"},
			mockResponse:   `{"error": "internal error"}`,
			mockStatusCode: http.StatusInternalServerError,
			mockError:      nil,
			expectedResult: false,
			expectedError:  true,
		},
		{
			name:           "network error",
			input:          HelloInput{Message: "Hello"},
			mockResponse:   "",
			mockStatusCode: 0,
			mockError:      fmt.Errorf("network error"),
			expectedResult: false,
			expectedError:  true,
		},
		{
			name:           "invalid JSON response",
			input:          HelloInput{Message: "Hello"},
			mockResponse:   `{invalid json}`,
			mockStatusCode: http.StatusOK,
			mockError:      nil,
			expectedResult: false,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockOPAClient := &MockOPAClient{}
			policyService := NewPolicyService(mockOPAClient, logger)

			if tt.mockError != nil {
				mockOPAClient.On("Do", mock.Anything, "POST", mock.Anything, mock.Anything).Return((*http.Response)(nil), tt.mockError)
			} else {
				resp := &http.Response{
					StatusCode: tt.mockStatusCode,
					Body:       io.NopCloser(bytes.NewBufferString(tt.mockResponse)),
				}
				mockOPAClient.On("Do", mock.Anything, "POST", mock.Anything, mock.Anything).Return(resp, nil)
			}

			ctx := context.Background()
			result, err := policyService.EvaluateHelloPolicy(ctx, tt.input)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}

			mockOPAClient.AssertExpectations(t)
		})
	}
}

func TestPolicyService_EvaluateLicensePolicy(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name           string
		input          map[string]interface{}
		mockResponse   string
		mockStatusCode int
		mockError      error
		expectedResult bool
		expectedError  bool
	}{
		{
			name: "successful evaluation - compliant",
			input: map[string]interface{}{
				"licenses": []string{"MIT", "Apache-2.0"},
			},
			mockResponse:   `{"result": true}`,
			mockStatusCode: http.StatusOK,
			mockError:      nil,
			expectedResult: true,
			expectedError:  false,
		},
		{
			name: "successful evaluation - non-compliant",
			input: map[string]interface{}{
				"licenses": []string{"GPL-3.0"},
			},
			mockResponse:   `{"result": false}`,
			mockStatusCode: http.StatusOK,
			mockError:      nil,
			expectedResult: false,
			expectedError:  false,
		},
		{
			name: "server error",
			input: map[string]interface{}{
				"licenses": []string{"MIT"},
			},
			mockResponse:   `{"error": "internal error"}`,
			mockStatusCode: http.StatusInternalServerError,
			mockError:      nil,
			expectedResult: false,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockOPAClient := &MockOPAClient{}
			policyService := NewPolicyService(mockOPAClient, logger)

			if tt.mockError != nil {
				mockOPAClient.On("Do", mock.Anything, "POST", mock.Anything, mock.Anything).Return((*http.Response)(nil), tt.mockError)
			} else {
				resp := &http.Response{
					StatusCode: tt.mockStatusCode,
					Body:       io.NopCloser(bytes.NewBufferString(tt.mockResponse)),
				}
				mockOPAClient.On("Do", mock.Anything, "POST", mock.Anything, mock.Anything).Return(resp, nil)
			}

			ctx := context.Background()
			result, err := policyService.EvaluateLicensePolicy(ctx, tt.input)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}

			mockOPAClient.AssertExpectations(t)
		})
	}
}

func TestPolicyService_EvaluateVulnerabilityPolicy(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name           string
		input          map[string]interface{}
		mockResponse   string
		mockStatusCode int
		mockError      error
		expectedResult *VulnerabilityPolicyResult
		expectedError  bool
	}{
		{
			name: "successful evaluation - compliant",
			input: map[string]interface{}{
				"vulnerabilities": []map[string]interface{}{
					{
						"id":        "CVE-2021-1234",
						"package":   "example-package",
						"version":   "1.0.0",
						"severity":  "LOW",
						"score":     2.5,
					},
				},
			},
			mockResponse: `{
				"result": {
					"compliant": true,
					"compliant_count": 1,
					"non_compliant_count": 0,
					"non_compliant_vulnerabilities": [],
					"total_vulnerabilities": 1
				}
			}`,
			mockStatusCode: http.StatusOK,
			mockError:      nil,
			expectedResult: &VulnerabilityPolicyResult{
				Compliant:                   true,
				CompliantCount:              1,
				NonCompliantCount:           0,
				NonCompliantVulnerabilities: []VulnerabilityPolicyVuln{},
				TotalVulnerabilities:        1,
			},
			expectedError: false,
		},
		{
			name: "successful evaluation - non-compliant",
			input: map[string]interface{}{
				"vulnerabilities": []map[string]interface{}{
					{
						"id":        "CVE-2021-5678",
						"package":   "vulnerable-package",
						"version":   "2.0.0",
						"severity":  "CRITICAL",
						"score":     9.8,
					},
				},
			},
			mockResponse: `{
				"result": {
					"compliant": false,
					"compliant_count": 0,
					"non_compliant_count": 1,
					"non_compliant_vulnerabilities": [
						{
							"id": "CVE-2021-5678",
							"package": "vulnerable-package",
							"version": "2.0.0",
							"severity": "CRITICAL",
							"score": 9.8,
							"fixed_version": "2.1.0"
						}
					],
					"total_vulnerabilities": 1
				}
			}`,
			mockStatusCode: http.StatusOK,
			mockError:      nil,
			expectedResult: &VulnerabilityPolicyResult{
				Compliant:         false,
				CompliantCount:    0,
				NonCompliantCount: 1,
				NonCompliantVulnerabilities: []VulnerabilityPolicyVuln{
					{
						ID:           "CVE-2021-5678",
						Package:      "vulnerable-package",
						Version:      "2.0.0",
						Severity:     "CRITICAL",
						Score:        9.8,
						FixedVersion: "2.1.0",
					},
				},
				TotalVulnerabilities: 1,
			},
			expectedError: false,
		},
		{
			name: "server error",
			input: map[string]interface{}{
				"vulnerabilities": []map[string]interface{}{},
			},
			mockResponse:   `{"error": "internal error"}`,
			mockStatusCode: http.StatusInternalServerError,
			mockError:      nil,
			expectedResult: nil,
			expectedError:  true,
		},
		{
			name: "invalid JSON response",
			input: map[string]interface{}{
				"vulnerabilities": []map[string]interface{}{},
			},
			mockResponse:   `{invalid json}`,
			mockStatusCode: http.StatusOK,
			mockError:      nil,
			expectedResult: nil,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockOPAClient := &MockOPAClient{}
			policyService := NewPolicyService(mockOPAClient, logger)

			if tt.mockError != nil {
				mockOPAClient.On("Do", mock.Anything, "POST", mock.Anything, mock.Anything).Return((*http.Response)(nil), tt.mockError)
			} else {
				resp := &http.Response{
					StatusCode: tt.mockStatusCode,
					Body:       io.NopCloser(bytes.NewBufferString(tt.mockResponse)),
				}
				mockOPAClient.On("Do", mock.Anything, "POST", mock.Anything, mock.Anything).Return(resp, nil)
			}

			ctx := context.Background()
			result, err := policyService.EvaluateVulnerabilityPolicy(ctx, tt.input)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}

			mockOPAClient.AssertExpectations(t)
		})
	}
}

func TestPolicyService_IntegrationWithRealOPAClient(t *testing.T) {
	t.Skip("Integration test - requires running OPA server")

	// This is an example of how you might write integration tests
	// that require a real OPA server running
	
	opaClient, err := clients.NewOPAClient("http://localhost:8181")
	require.NoError(t, err)

	logger := slog.Default()
	policyService := NewPolicyService(opaClient, logger)

	ctx := context.Background()

	t.Run("hello policy integration", func(t *testing.T) {
		input := HelloInput{Message: "Hello"}
		result, err := policyService.EvaluateHelloPolicy(ctx, input)
		assert.NoError(t, err)
		assert.True(t, result) // Assuming the policy returns true for "Hello"
	})
}

func TestPolicyService_PolicyPaths(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name         string
		method       string
		expectedPath string
	}{
		{
			name:         "hello policy path",
			method:       "EvaluateHelloPolicy",
			expectedPath: "/v1/data/playground/hello",
		},
		{
			name:         "license policy path", 
			method:       "EvaluateLicensePolicy",
			expectedPath: "/v1/data/playground/license",
		},
		{
			name:         "vulnerability policy path",
			method:       "EvaluateVulnerabilityPolicy", 
			expectedPath: "/v1/data/playground/vulnerability",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockOPAClient := &MockOPAClient{}
			policyService := NewPolicyService(mockOPAClient, logger)

			// Mock response
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(`{"result": true}`)),
			}

			// Set up expectation that captures the URL
			mockOPAClient.On("Do", mock.Anything, "POST", mock.MatchedBy(func(url string) bool {
				return strings.Contains(url, tt.expectedPath)
			}), mock.Anything).Return(resp, nil)

			ctx := context.Background()

			// Call the appropriate method
			switch tt.method {
			case "EvaluateHelloPolicy":
				_, err := policyService.EvaluateHelloPolicy(ctx, HelloInput{Message: "test"})
				assert.NoError(t, err)
			case "EvaluateLicensePolicy":
				_, err := policyService.EvaluateLicensePolicy(ctx, map[string]interface{}{"test": "data"})
				assert.NoError(t, err)
			case "EvaluateVulnerabilityPolicy":
				result := &PolicyCheckResult{Result: true}
				respData, _ := json.Marshal(map[string]interface{}{"result": result})
				resp.Body = io.NopCloser(bytes.NewBuffer(respData))
				_, err := policyService.EvaluateVulnerabilityPolicy(ctx, map[string]interface{}{"test": "data"})
				assert.NoError(t, err)
			}

			mockOPAClient.AssertExpectations(t)
		})
	}
}
