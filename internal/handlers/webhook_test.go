package handlers

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/testutils"
)

// Test helper to create test services
func createTestServices() (*services.CommentService, *services.CheckService, *services.PolicyService, *services.SecurityService) {
	logger := testutils.NewTestLogger()

	// Create test GitHub client (will not make real API calls in tests)
	githubClient := clients.NewGitHubClient(context.Background())

	// Create test OPA client
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")

	commentService := services.NewCommentService(githubClient, logger)
	checkService := services.NewCheckService(githubClient, logger)
	policyService := services.NewPolicyService(opaClient, logger)
	securityService := services.NewSecurityService(githubClient, logger)

	return commentService, checkService, policyService, securityService
}

func TestNewWebhookHandler(t *testing.T) {
	logger := testutils.NewTestLogger()
	commentService, checkService, policyService, securityService := createTestServices()

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)

	require.NoError(t, err)
	assert.NotNil(t, handler)
	assert.Equal(t, logger, handler.logger)
}

func TestWebhookHandler_Structure(t *testing.T) {
	logger := testutils.NewTestLogger()
	commentService, checkService, policyService, securityService := createTestServices()

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	// Test that handler has the expected structure
	assert.NotNil(t, handler.commentService)
	assert.NotNil(t, handler.checkService)
	assert.NotNil(t, handler.policyService)
	assert.NotNil(t, handler.securityService)
	assert.NotNil(t, handler.prContextStore)
	assert.NotNil(t, handler.vulnerabilityCheckStore)
}

func TestWebhookHandler_ServicesInitialization(t *testing.T) {
	logger := testutils.NewTestLogger()
	commentService, checkService, policyService, securityService := createTestServices()

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	// Verify all services are properly initialized
	assert.Same(t, commentService, handler.commentService)
	assert.Same(t, checkService, handler.checkService)
	assert.Same(t, policyService, handler.policyService)
	assert.Same(t, securityService, handler.securityService)
}

func TestWebhookHandler_HandleWebhook_Structure(t *testing.T) {
	logger := testutils.NewTestLogger()
	commentService, checkService, policyService, securityService := createTestServices()

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	// Test that HandleWebhook method exists and can be called
	req := httptest.NewRequest("POST", "/webhook", nil)
	w := httptest.NewRecorder()

	// Test with empty request (will likely fail parsing, but tests method signature)
	assert.NotPanics(t, func() {
		handler.HandleWebhook(w, req)
	})

	// Should get a 400 or similar for invalid webhook
	assert.True(t, w.Code >= 400, "Should return error status for invalid webhook")
}

func TestWebhookHandler_ContextStore(t *testing.T) {
	logger := testutils.NewTestLogger()
	commentService, checkService, policyService, securityService := createTestServices()

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	// Test that context stores are initialized
	assert.NotNil(t, handler.prContextStore)
	assert.NotNil(t, handler.vulnerabilityCheckStore)

	// Test that stores can be used
	handler.prContextStore["test-sha"] = 123
	handler.vulnerabilityCheckStore["test-sha"] = 456

	assert.Equal(t, int64(123), handler.prContextStore["test-sha"])
	assert.Equal(t, int64(456), handler.vulnerabilityCheckStore["test-sha"])
}

func TestWebhookHandler_Services(t *testing.T) {
	logger := testutils.NewTestLogger()
	commentService, checkService, policyService, securityService := createTestServices()

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	// Test that all services are properly assigned
	assert.Equal(t, commentService, handler.commentService)
	assert.Equal(t, checkService, handler.checkService)
	assert.Equal(t, policyService, handler.policyService)
	assert.Equal(t, securityService, handler.securityService)
}

func TestWebhookHandler_Mutexes(t *testing.T) {
	logger := testutils.NewTestLogger()
	commentService, checkService, policyService, securityService := createTestServices()

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	// Test that mutexes can be used for concurrent access
	assert.NotPanics(t, func() {
		handler.prContextMutex.Lock()
		handler.prContextStore["test"] = 1
		handler.prContextMutex.Unlock()
	})

	assert.NotPanics(t, func() {
		handler.vulnerabilityCheckMutex.Lock()
		handler.vulnerabilityCheckStore["test"] = 2
		handler.vulnerabilityCheckMutex.Unlock()
	})
}

// TestWebhookHandler_HandleWebhook_RequestParsing tests webhook request parsing
func TestWebhookHandler_HandleWebhook_RequestParsing(t *testing.T) {
	logger := testutils.NewTestLogger()
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	tests := []struct {
		name           string
		method         string
		body           string
		headers        map[string]string
		expectedStatus int
	}{
		{
			name:   "missing event header",
			method: "POST",
			body:   `{"action": "opened"}`,
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			expectedStatus: 400, // Bad Request due to missing X-GitHub-Event
		},
		{
			name:   "unsupported event type",
			method: "POST",
			body:   `{"action": "opened"}`,
			headers: map[string]string{
				"Content-Type":   "application/json",
				"X-GitHub-Event": "unsupported_event",
			},
			expectedStatus: 400, // Bad Request for unsupported event
		},
		{
			name:   "invalid JSON body",
			method: "POST",
			body:   `{invalid json}`,
			headers: map[string]string{
				"Content-Type":   "application/json",
				"X-GitHub-Event": "pull_request",
			},
			expectedStatus: 400, // Bad Request for invalid JSON
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/webhook", strings.NewReader(tt.body))
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			recorder := httptest.NewRecorder()
			handler.HandleWebhook(recorder, req)

			assert.Equal(t, tt.expectedStatus, recorder.Code)
		})
	}
}

// TestWebhookHandler_BuildCheckRunResult tests check run result building
func TestWebhookHandler_BuildCheckRunResult(t *testing.T) {
	logger := testutils.NewTestLogger()
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	tests := []struct {
		name          string
		policyPassed  bool
		policyError   error
		expectedConc  services.CheckRunConclusion
		expectedTitle string
	}{
		{
			name:          "policy passed",
			policyPassed:  true,
			policyError:   nil,
			expectedConc:  services.ConclusionSuccess,
			expectedTitle: "OPA Policy Check - Passed",
		},
		{
			name:          "policy failed",
			policyPassed:  false,
			policyError:   nil,
			expectedConc:  services.ConclusionFailure,
			expectedTitle: "OPA Policy Check - Failed",
		},
		{
			name:          "policy error",
			policyPassed:  false,
			policyError:   fmt.Errorf("validation error"),
			expectedConc:  services.ConclusionFailure,
			expectedTitle: "OPA Policy Check - Error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conclusion, result := handler.buildCheckRunResult(tt.policyPassed, tt.policyError)
			assert.Equal(t, tt.expectedConc, conclusion)
			assert.Equal(t, tt.expectedTitle, result.Title)
			assert.NotEmpty(t, result.Summary)
			assert.NotEmpty(t, result.Text)
		})
	}
}

// TestWebhookHandler_VulnerabilityCheckStore tests vulnerability check store operations
func TestWebhookHandler_VulnerabilityCheckStore(t *testing.T) {
	logger := testutils.NewTestLogger()
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	// Test storing and retrieving vulnerability check IDs
	sha := "test-sha"
	checkRunID := int64(12345)

	// Store a check run ID
	handler.vulnerabilityCheckMutex.Lock()
	handler.vulnerabilityCheckStore[sha] = checkRunID
	handler.vulnerabilityCheckMutex.Unlock()

	// Retrieve it
	foundID, err := handler.findVulnerabilityCheckRun(context.Background(), "owner", "repo", sha)
	assert.NoError(t, err)
	assert.Equal(t, checkRunID, foundID)

	// Test non-existent SHA
	notFoundID, err := handler.findVulnerabilityCheckRun(context.Background(), "owner", "repo", "non-existent")
	assert.NoError(t, err)
	assert.Equal(t, int64(0), notFoundID)
}

// TestWebhookHandler_BuildVulnerabilityViolationComment tests vulnerability comment building
func TestWebhookHandler_BuildVulnerabilityViolationComment(t *testing.T) {
	logger := testutils.NewTestLogger()
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	vulns := []services.VulnerabilityPolicyVuln{
		{
			ID:       "CVE-2024-1234",
			Package:  "lodash",
			Version:  "4.17.20",
			Severity: "HIGH",
			Score:    7.5,
		},
		{
			ID:       "CVE-2024-5678",
			Package:  "axios",
			Version:  "0.21.1",
			Severity: "CRITICAL",
			Score:    9.8,
		},
	}

	comment := handler.buildVulnerabilityViolationComment(vulns)

	assert.Contains(t, comment, "🚨 **Vulnerability Policy Violation - 2 vulnerabilities blocked**")
	assert.Contains(t, comment, "CVE-2024-1234")
	assert.Contains(t, comment, "CVE-2024-5678")
	assert.Contains(t, comment, "lodash")
	assert.Contains(t, comment, "axios")
	assert.Contains(t, comment, "HIGH")
	assert.Contains(t, comment, "CRITICAL")
	assert.Contains(t, comment, "7.5")
	assert.Contains(t, comment, "9.8")
	assert.Contains(t, comment, "<details>")
	assert.Contains(t, comment, "</details>")
}

// TestWebhookHandler_PRContextStore tests PR context store operations
func TestWebhookHandler_PRContextStore(t *testing.T) {
	logger := testutils.NewTestLogger()
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	// Test storing and retrieving PR context
	sha := "test-sha-pr"
	prNumber := int64(456)

	handler.prContextMutex.Lock()
	handler.prContextStore[sha] = prNumber
	handler.prContextMutex.Unlock()

	// Verify it was stored
	handler.prContextMutex.RLock()
	storedPR, exists := handler.prContextStore[sha]
	handler.prContextMutex.RUnlock()

	assert.True(t, exists)
	assert.Equal(t, prNumber, storedPR)

	// Test non-existent SHA
	handler.prContextMutex.RLock()
	_, notExists := handler.prContextStore["non-existent-sha"]
	handler.prContextMutex.RUnlock()

	assert.False(t, notExists)
}

// TestWebhookHandler_CompleteVulnerabilityCheckAsNeutral tests neutral completion
func TestWebhookHandler_CompleteVulnerabilityCheckAsNeutral(t *testing.T) {
	logger := testutils.NewTestLogger()
	commentService := &services.CommentService{}
	checkService := &services.CheckService{}
	policyService := &services.PolicyService{}
	securityService := &services.SecurityService{}

	handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
	require.NoError(t, err)

	// Test with no stored check run - should not error
	err = handler.completeVulnerabilityCheckAsNeutral(context.Background(), "owner", "repo", "no-check-sha")
	assert.NoError(t, err)

	// For the case where we would have a stored check run, we can't test it here
	// because it requires a properly configured GitHub client. We can test the
	// storage mechanism separately.
	sha := "test-sha-with-check"
	checkRunID := int64(789)

	handler.vulnerabilityCheckMutex.Lock()
	handler.vulnerabilityCheckStore[sha] = checkRunID
	handler.vulnerabilityCheckMutex.Unlock()

	// Verify the check run ID was stored
	foundID, err := handler.findVulnerabilityCheckRun(context.Background(), "owner", "repo", sha)
	assert.NoError(t, err)
	assert.Equal(t, checkRunID, foundID)
}
