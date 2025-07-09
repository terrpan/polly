package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-playground/webhooks/v6/github"
	gogithub "github.com/google/go-github/v72/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/terrpan/polly/internal/services"
	"log/slog"
)

// Mock services for testing
type MockCommentService struct {
	mock.Mock
}

func (m *MockCommentService) WriteComment(ctx context.Context, owner, repo string, prNumber int, comment string) error {
	args := m.Called(ctx, owner, repo, prNumber, comment)
	return args.Error(0)
}

type MockCheckService struct {
	mock.Mock
}

func (m *MockCheckService) CreatePolicyCheck(ctx context.Context, owner, repo, sha string) (*gogithub.CheckRun, error) {
	args := m.Called(ctx, owner, repo, sha)
	return args.Get(0).(*gogithub.CheckRun), args.Error(1)
}

func (m *MockCheckService) StartPolicyCheck(ctx context.Context, owner, repo string, checkRunID int64) error {
	args := m.Called(ctx, owner, repo, checkRunID)
	return args.Error(0)
}

func (m *MockCheckService) CompletePolicyCheck(ctx context.Context, owner, repo string, checkRunID int64, conclusion services.CheckRunConclusion, result services.CheckRunResult) error {
	args := m.Called(ctx, owner, repo, checkRunID, conclusion, result)
	return args.Error(0)
}

func (m *MockCheckService) CreateVulnerabilityCheck(ctx context.Context, owner, repo, sha string) (*gogithub.CheckRun, error) {
	args := m.Called(ctx, owner, repo, sha)
	return args.Get(0).(*gogithub.CheckRun), args.Error(1)
}

func (m *MockCheckService) StartVulnerabilityCheck(ctx context.Context, owner, repo string, checkRunID int64) error {
	args := m.Called(ctx, owner, repo, checkRunID)
	return args.Error(0)
}

func (m *MockCheckService) CompleteVulnerabilityCheck(ctx context.Context, owner, repo string, checkRunID int64, conclusion services.CheckRunConclusion, result services.CheckRunResult) error {
	args := m.Called(ctx, owner, repo, checkRunID, conclusion, result)
	return args.Error(0)
}

func (m *MockCheckService) CompleteVulnerabilityCheckWithNoArtifacts(ctx context.Context, owner, repo string, checkRunID int64) error {
	args := m.Called(ctx, owner, repo, checkRunID)
	return args.Error(0)
}

type MockPolicyService struct {
	mock.Mock
}

func (m *MockPolicyService) CheckHelloPolicy(ctx context.Context, input services.HelloInput) (bool, error) {
	args := m.Called(ctx, input)
	return args.Bool(0), args.Error(1)
}

func (m *MockPolicyService) CheckVulnerabilityPolicy(ctx context.Context, input *services.VulnerabilityPayload) (services.VulnerabilityPolicyResult, error) {
	args := m.Called(ctx, input)
	return args.Get(0).(services.VulnerabilityPolicyResult), args.Error(1)
}

type MockSecurityService struct {
	mock.Mock
}

func (m *MockSecurityService) ProcessWorkflowSecurityArtifacts(ctx context.Context, owner, repo, sha string, workflowID int64) ([]*services.VulnerabilityPayload, error) {
	args := m.Called(ctx, owner, repo, sha, workflowID)
	return args.Get(0).([]*services.VulnerabilityPayload), args.Error(1)
}

func createTestWebhookHandler(t *testing.T) (*WebhookHandler, *MockCommentService, *MockCheckService, *MockPolicyService, *MockSecurityService) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	
	mockComment := &MockCommentService{}
	mockCheck := &MockCheckService{}
	mockPolicy := &MockPolicyService{}
	mockSecurity := &MockSecurityService{}
	
	handler, err := NewWebhookHandler(logger, mockComment, mockCheck, mockPolicy, mockSecurity)
	require.NoError(t, err)
	
	return handler, mockComment, mockCheck, mockPolicy, mockSecurity
}

func TestNewWebhookHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(bytes.NewBuffer(nil), nil))
	mockComment := &MockCommentService{}
	mockCheck := &MockCheckService{}
	mockPolicy := &MockPolicyService{}
	mockSecurity := &MockSecurityService{}
	
	handler, err := NewWebhookHandler(logger, mockComment, mockCheck, mockPolicy, mockSecurity)
	
	assert.NoError(t, err)
	assert.NotNil(t, handler)
	assert.NotNil(t, handler.prContextStore)
	assert.NotNil(t, handler.vulnerabilityCheckStore)
}

func TestHandleWebhook_UnsupportedEvent(t *testing.T) {
	handler, _, _, _, _ := createTestWebhookHandler(t)
	
	req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString(`{"action": "opened"}`))
	req.Header.Set("X-GitHub-Event", "unsupported")
	req.Header.Set("Content-Type", "application/json")
	
	w := httptest.NewRecorder()
	handler.HandleWebhook(w, req)
	
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGetEventInfo_PullRequestPayload(t *testing.T) {
	payload := github.PullRequestPayload{
		Repository: github.Repository{
			Owner: github.User{Login: "testowner"},
			Name:  "testrepo",
		},
		PullRequest: github.PullRequest{
			ID: 123,
			Head: github.PullRequestBranch{
				Sha: "abc123",
			},
		},
	}
	
	owner, repo, sha, id := getEventInfo(payload)
	
	assert.Equal(t, "testowner", owner)
	assert.Equal(t, "testrepo", repo)
	assert.Equal(t, "abc123", sha)
	assert.Equal(t, int64(123), id)
}

func TestGetEventInfo_CheckRunPayload(t *testing.T) {
	payload := github.CheckRunPayload{
		Repository: github.Repository{
			Owner: github.User{Login: "testowner"},
			Name:  "testrepo",
		},
		CheckRun: github.CheckRun{
			ID:      456,
			HeadSHA: "def456",
		},
	}
	
	owner, repo, sha, id := getEventInfo(payload)
	
	assert.Equal(t, "testowner", owner)
	assert.Equal(t, "testrepo", repo)
	assert.Equal(t, "def456", sha)
	assert.Equal(t, int64(456), id)
}

func TestGetEventInfo_WorkflowRunPayload(t *testing.T) {
	payload := github.WorkflowRunPayload{
		Repository: github.Repository{
			Owner: github.User{Login: "testowner"},
			Name:  "testrepo",
		},
		WorkflowRun: github.WorkflowRun{
			ID:      789,
			HeadSha: "ghi789",
		},
	}
	
	owner, repo, sha, id := getEventInfo(payload)
	
	assert.Equal(t, "testowner", owner)
	assert.Equal(t, "testrepo", repo)
	assert.Equal(t, "ghi789", sha)
	assert.Equal(t, int64(789), id)
}

func TestBuildCheckRunResult_PolicyPassed(t *testing.T) {
	handler, _, _, _, _ := createTestWebhookHandler(t)
	
	conclusion, result := handler.buildCheckRunResult(true, nil)
	
	assert.Equal(t, services.ConclusionSuccess, conclusion)
	assert.Equal(t, "OPA Policy Check - Passed", result.Title)
	assert.Equal(t, "All policies passed", result.Summary)
}

func TestBuildCheckRunResult_PolicyFailed(t *testing.T) {
	handler, _, _, _, _ := createTestWebhookHandler(t)
	
	conclusion, result := handler.buildCheckRunResult(false, nil)
	
	assert.Equal(t, services.ConclusionFailure, conclusion)
	assert.Equal(t, "OPA Policy Check - Failed", result.Title)
	assert.Equal(t, "Policy validation failed", result.Summary)
}

func TestBuildCheckRunResult_PolicyError(t *testing.T) {
	handler, _, _, _, _ := createTestWebhookHandler(t)
	testError := assert.AnError
	
	conclusion, result := handler.buildCheckRunResult(false, testError)
	
	assert.Equal(t, services.ConclusionFailure, conclusion)
	assert.Equal(t, "OPA Policy Check - Error", result.Title)
	assert.Equal(t, "Policy validation failed due to error", result.Summary)
	assert.Contains(t, result.Text, testError.Error())
}

func TestHandlePullRequestEvent_IgnoreNonOpenedReopened(t *testing.T) {
	handler, _, _, _, _ := createTestWebhookHandler(t)
	
	event := github.PullRequestPayload{
		Action: "synchronize",
		Number: 1,
	}
	
	err := handler.handlePullRequestEvent(context.Background(), event)
	
	assert.NoError(t, err)
}

func TestHandlePullRequestEvent_Success(t *testing.T) {
	handler, _, mockCheck, mockPolicy, _ := createTestWebhookHandler(t)
	
	event := github.PullRequestPayload{
		Action: "opened",
		Number: 1,
		Repository: github.Repository{
			Owner: github.User{Login: "testowner"},
			Name:  "testrepo",
		},
		PullRequest: github.PullRequest{
			ID: 123,
			Head: github.PullRequestBranch{
				Sha: "abc123",
			},
		},
	}
	
	checkRun := &gogithub.CheckRun{ID: gogithub.Ptr(int64(456))}
	
	mockCheck.On("CreatePolicyCheck", mock.Anything, "testowner", "testrepo", "abc123").Return(checkRun, nil)
	mockCheck.On("StartPolicyCheck", mock.Anything, "testowner", "testrepo", int64(456)).Return(nil)
	mockPolicy.On("CheckHelloPolicy", mock.Anything, services.HelloInput{Message: "hello"}).Return(true, nil)
	mockCheck.On("CompletePolicyCheck", mock.Anything, "testowner", "testrepo", int64(456), services.ConclusionSuccess, mock.Anything).Return(nil)
	
	err := handler.handlePullRequestEvent(context.Background(), event)
	
	assert.NoError(t, err)
	mockCheck.AssertExpectations(t)
	mockPolicy.AssertExpectations(t)
	
	// Verify PR context was stored
	assert.Equal(t, int64(1), handler.prContextStore["abc123"])
}

func TestHandleWorkflowStarted_NoPRContext(t *testing.T) {
	handler, _, _, _, _ := createTestWebhookHandler(t)
	
	event := github.WorkflowRunPayload{
		Workflow: github.Workflow{Name: "test-workflow"},
	}
	
	err := handler.handleWorkflowStarted(context.Background(), event, "owner", "repo", "sha123", 789)
	
	assert.NoError(t, err)
}

func TestHandleWorkflowStarted_WithPRContext(t *testing.T) {
	handler, _, mockCheck, _, _ := createTestWebhookHandler(t)
	
	// Set up PR context
	handler.prContextStore["sha123"] = 42
	
	event := github.WorkflowRunPayload{
		Workflow: github.Workflow{Name: "test-workflow"},
	}
	
	checkRun := &gogithub.CheckRun{ID: gogithub.Ptr(int64(456))}
	
	mockCheck.On("CreateVulnerabilityCheck", mock.Anything, "owner", "repo", "sha123").Return(checkRun, nil)
	mockCheck.On("StartVulnerabilityCheck", mock.Anything, "owner", "repo", int64(456)).Return(nil)
	
	err := handler.handleWorkflowStarted(context.Background(), event, "owner", "repo", "sha123", 789)
	
	assert.NoError(t, err)
	mockCheck.AssertExpectations(t)
	
	// Verify vulnerability check context was stored
	assert.Equal(t, int64(456), handler.vulnerabilityCheckStore["sha123"])
}

func TestCompleteVulnerabilityCheckAsNeutral_NoCheckRun(t *testing.T) {
	handler, _, _, _, _ := createTestWebhookHandler(t)
	
	err := handler.completeVulnerabilityCheckAsNeutral(context.Background(), "owner", "repo", "sha123")
	
	assert.NoError(t, err)
}

func TestCompleteVulnerabilityCheckAsNeutral_WithCheckRun(t *testing.T) {
	handler, _, mockCheck, _, _ := createTestWebhookHandler(t)
	
	// Set up vulnerability check context
	handler.vulnerabilityCheckStore["sha123"] = 456
	
	mockCheck.On("CompleteVulnerabilityCheckWithNoArtifacts", mock.Anything, "owner", "repo", int64(456)).Return(nil)
	
	err := handler.completeVulnerabilityCheckAsNeutral(context.Background(), "owner", "repo", "sha123")
	
	assert.NoError(t, err)
	mockCheck.AssertExpectations(t)
}

func TestProcessVulnerabilityPayloads_PolicyCompliant(t *testing.T) {
	handler, _, mockCheck, mockPolicy, _ := createTestWebhookHandler(t)
	
	payload := &services.VulnerabilityPayload{
		Type: "vulnerability_json",
		Metadata: services.PayloadMetadata{
			ToolName:   "trivy",
			ScanTarget: "package.json",
		},
		Vulnerabilities: []services.Vulnerability{
			{
				ID:       "CVE-2021-1234",
				Severity: "HIGH",
				Package:  services.Package{Name: "test-package", Version: "1.0.0"},
			},
		},
		Summary: services.VulnerabilitySummary{
			TotalVulnerabilities: 1,
			High:                 1,
		},
	}
	
	policyResult := services.VulnerabilityPolicyResult{
		Compliant:             true,
		TotalVulnerabilities:  1,
		NonCompliantCount:     0,
		NonCompliantVulnerabilities: []services.VulnerabilityPolicyVuln{},
	}
	
	mockPolicy.On("CheckVulnerabilityPolicy", mock.Anything, payload).Return(policyResult, nil)
	mockCheck.On("CompleteVulnerabilityCheck", mock.Anything, "owner", "repo", int64(456), services.ConclusionSuccess, mock.Anything).Return(nil)
	
	err := handler.processVulnerabilityPayloads(context.Background(), []*services.VulnerabilityPayload{payload}, "owner", "repo", "sha123", 42, 456)
	
	assert.NoError(t, err)
	mockPolicy.AssertExpectations(t)
	mockCheck.AssertExpectations(t)
}

func TestProcessVulnerabilityPayloads_PolicyViolation(t *testing.T) {
	handler, mockComment, mockCheck, mockPolicy, _ := createTestWebhookHandler(t)
	
	payload := &services.VulnerabilityPayload{
		Type: "vulnerability_json",
		Metadata: services.PayloadMetadata{
			ToolName:   "trivy",
			ScanTarget: "package.json",
		},
		Vulnerabilities: []services.Vulnerability{
			{
				ID:       "CVE-2021-1234",
				Severity: "CRITICAL",
				Package:  services.Package{Name: "test-package", Version: "1.0.0"},
			},
		},
		Summary: services.VulnerabilitySummary{
			TotalVulnerabilities: 1,
			Critical:             1,
		},
	}
	
	policyResult := services.VulnerabilityPolicyResult{
		Compliant:         false,
		TotalVulnerabilities: 1,
		NonCompliantCount: 1,
		NonCompliantVulnerabilities: []services.VulnerabilityPolicyVuln{
			{
				ID:       "CVE-2021-1234",
				Package:  "test-package",
				Version:  "1.0.0",
				Severity: "CRITICAL",
				Score:    9.8,
			},
		},
	}
	
	mockPolicy.On("CheckVulnerabilityPolicy", mock.Anything, payload).Return(policyResult, nil)
	mockComment.On("WriteComment", mock.Anything, "owner", "repo", 42, mock.MatchedBy(func(comment string) bool {
		return bytes.Contains([]byte(comment), []byte("Vulnerability Policy Violation"))
	})).Return(nil)
	mockCheck.On("CompleteVulnerabilityCheck", mock.Anything, "owner", "repo", int64(456), services.ConclusionFailure, mock.Anything).Return(nil)
	
	err := handler.processVulnerabilityPayloads(context.Background(), []*services.VulnerabilityPayload{payload}, "owner", "repo", "sha123", 42, 456)
	
	assert.NoError(t, err)
	mockPolicy.AssertExpectations(t)
	mockComment.AssertExpectations(t)
	mockCheck.AssertExpectations(t)
}
