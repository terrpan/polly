package services

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/terrpan/polly/internal/clients"
)

func TestNewCheckService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()

	service := NewCheckService(mockClient, logger)

	assert.NotNil(t, service)
	assert.Equal(t, mockClient, service.githubClient)
	assert.Equal(t, logger, service.logger)
}

func TestCheckService_CreateCheckRun_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewCheckService(mockClient, logger)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "abc123"
	checkType := CheckRunTypePolicy

	// Execute the service method
	checkRun, err := service.CreateCheckRun(ctx, owner, repo, sha, checkType)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, checkRun)
	assert.Equal(t, int64(12345), *checkRun.ID)
	assert.Equal(t, string(checkType), *checkRun.Name)
	assert.Equal(t, sha, *checkRun.HeadSHA)
	
	// Verify the GitHub client was called correctly
	assert.Equal(t, 1, mockClient.GetCreateCheckRunCallCount())
	call := mockClient.CreateCheckRunCalls[0]
	assert.Equal(t, owner, call.Owner)
	assert.Equal(t, repo, call.Repo)
	assert.Equal(t, sha, call.SHA)
	assert.Equal(t, string(checkType), call.Name)
}

func TestCheckService_CreateCheckRun_Error(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewCheckService(mockClient, logger)

	// Configure mock to return an error
	expectedError := errors.New("GitHub API error")
	mockClient.SetCreateCheckRunError(expectedError)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "abc123"
	checkType := CheckRunTypePolicy

	// Execute the service method
	checkRun, err := service.CreateCheckRun(ctx, owner, repo, sha, checkType)

	// Verify error handling
	assert.Error(t, err)
	assert.Nil(t, checkRun)
	
	// Verify the GitHub client was called
	assert.Equal(t, 1, mockClient.GetCreateCheckRunCallCount())
}

func TestCheckService_CompleteCheckRun_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewCheckService(mockClient, logger)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	checkRunID := int64(12345)
	checkType := CheckRunTypePolicy
	conclusion := ConclusionSuccess
	result := CheckRunResult{
		Success: true,
		Title:   "Policy Check Passed",
		Summary: "All policies passed successfully",
		Text:    "Detailed results...",
	}

	// Execute the service method
	err := service.CompleteCheckRun(ctx, owner, repo, checkRunID, checkType, conclusion, result)

	// Verify results
	assert.NoError(t, err)
	
	// Verify the GitHub client was called correctly
	assert.Equal(t, 1, mockClient.GetUpdateCheckRunCallCount())
	call := mockClient.UpdateCheckRunCalls[0]
	assert.Equal(t, owner, call.Owner)
	assert.Equal(t, repo, call.Repo)
	assert.Equal(t, checkRunID, call.CheckRunID)
	assert.Equal(t, string(checkType), call.Name)
	assert.Equal(t, string(StatusCompleted), call.Status)
	assert.NotNil(t, call.Conclusion)
	assert.Equal(t, string(conclusion), *call.Conclusion)
	assert.NotNil(t, call.Output)
	assert.Equal(t, result.Title, *call.Output.Title)
	assert.Equal(t, result.Summary, *call.Output.Summary)
	assert.Equal(t, result.Text, *call.Output.Text)
}

func TestCheckService_CompleteCheckRun_Error(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewCheckService(mockClient, logger)

	// Configure mock to return an error
	expectedError := errors.New("GitHub API error")
	mockClient.SetUpdateCheckRunError(expectedError)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	checkRunID := int64(12345)
	checkType := CheckRunTypePolicy
	conclusion := ConclusionSuccess
	result := CheckRunResult{
		Success: true,
		Title:   "Policy Check Passed",
		Summary: "All policies passed successfully",
		Text:    "Detailed results...",
	}

	// Execute the service method
	err := service.CompleteCheckRun(ctx, owner, repo, checkRunID, checkType, conclusion, result)

	// Verify error handling
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	
	// Verify the GitHub client was called
	assert.Equal(t, 1, mockClient.GetUpdateCheckRunCallCount())
}

func TestCheckService_CheckRunTypes(t *testing.T) {
	tests := []struct {
		name         string
		checkType    CheckRunType
		expectedName string
	}{
		{
			name:         "policy check type",
			checkType:    CheckRunTypePolicy,
			expectedName: "OPA Policy Check",
		},
		{
			name:         "vulnerability check type",
			checkType:    CheckRunTypeVulnerability,
			expectedName: "Vulnerability Scan Check",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedName, string(tt.checkType))
		})
	}
}

func TestCheckService_CheckRunStatuses(t *testing.T) {
	tests := []struct {
		name           string
		status         CheckRunStatus
		expectedString string
	}{
		{
			name:           "queued status",
			status:         StatusQueued,
			expectedString: "queued",
		},
		{
			name:           "in progress status",
			status:         StatusInProgress,
			expectedString: "in_progress",
		},
		{
			name:           "completed status",
			status:         StatusCompleted,
			expectedString: "completed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedString, string(tt.status))
		})
	}
}

func TestCheckService_CheckRunConclusions(t *testing.T) {
	tests := []struct {
		name           string
		conclusion     CheckRunConclusion
		expectedString string
	}{
		{
			name:           "success conclusion",
			conclusion:     ConclusionSuccess,
			expectedString: "success",
		},
		{
			name:           "failure conclusion",
			conclusion:     ConclusionFailure,
			expectedString: "failure",
		},
		{
			name:           "neutral conclusion",
			conclusion:     ConclusionNeutral,
			expectedString: "neutral",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedString, string(tt.conclusion))
		})
	}
}

func TestCheckService_ConvenienceMethods(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewCheckService(mockClient, logger)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "abc123"

	// Test CreatePolicyCheck
	checkRun, err := service.CreatePolicyCheck(ctx, owner, repo, sha)
	assert.NoError(t, err)
	assert.NotNil(t, checkRun)
	assert.Equal(t, 1, mockClient.GetCreateCheckRunCallCount())
	assert.Equal(t, string(CheckRunTypePolicy), mockClient.CreateCheckRunCalls[0].Name)

	// Reset and test CreateVulnerabilityCheck
	mockClient.Reset()
	checkRun, err = service.CreateVulnerabilityCheck(ctx, owner, repo, sha)
	assert.NoError(t, err)
	assert.NotNil(t, checkRun)
	assert.Equal(t, 1, mockClient.GetCreateCheckRunCallCount())
	assert.Equal(t, string(CheckRunTypeVulnerability), mockClient.CreateCheckRunCalls[0].Name)
}