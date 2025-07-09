package services

import (
	"context"
	"log/slog"
	"os"
	"testing"

	gogithub "github.com/google/go-github/v72/github"
	"github.com/stretchr/testify/assert"
	"github.com/terrpan/polly/internal/clients"
)

func TestNewCheckService(t *testing.T) {
	logger := slog.Default()

	// Create a real GitHub client for testing the constructor
	realClient := clients.NewGitHubClient(context.Background())

	service := NewCheckService(realClient, logger)

	assert.NotNil(t, service)
	assert.Equal(t, realClient, service.githubClient)
	assert.Equal(t, logger, service.logger)
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
		{
			name:           "cancelled conclusion",
			conclusion:     ConclusionCancelled,
			expectedString: "cancelled",
		},
		{
			name:           "skipped conclusion",
			conclusion:     ConclusionSkipped,
			expectedString: "skipped",
		},
		{
			name:           "timed out conclusion",
			conclusion:     ConclusionTimedOut,
			expectedString: "timed_out",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expectedString, string(tt.conclusion))
		})
	}
}

func TestCheckService_CheckRunResult(t *testing.T) {
	t.Run("check run result structure", func(t *testing.T) {
		result := CheckRunResult{
			Success: true,
			Title:   "Test Title",
			Summary: "Test Summary",
			Text:    "Test Text",
		}

		assert.True(t, result.Success)
		assert.Equal(t, "Test Title", result.Title)
		assert.Equal(t, "Test Summary", result.Summary)
		assert.Equal(t, "Test Text", result.Text)
		assert.Nil(t, result.Annotations) // Should be nil by default
	})

	t.Run("check run result with annotations", func(t *testing.T) {
		result := CheckRunResult{
			Success:     true,
			Title:       "Test Title",
			Summary:     "Test Summary",
			Text:        "Test Text",
			Annotations: make([]gogithub.CheckRunAnnotation, 0), // Initialize as empty slice
		}

		assert.True(t, result.Success)
		assert.NotNil(t, result.Annotations)
		assert.Len(t, result.Annotations, 0)
	})
}

// Integration test helpers - these would require a real GitHub API or mock server
func TestCheckService_IntegrationExamples(t *testing.T) {
	t.Skip("Integration tests require GitHub API setup")

	// Example of how integration tests would look:
	// logger := slog.Default()
	// githubClient := clients.NewGitHubClient(context.Background())
	// err := githubClient.Authenticate(context.Background(), "test-token")
	// require.NoError(t, err)
	//
	// service := NewCheckService(githubClient, logger)
	//
	// ctx := context.Background()
	// checkRun, err := service.CreatePolicyCheck(ctx, "owner", "repo", "sha")
	// assert.NoError(t, err)
	// assert.NotNil(t, checkRun)
}

func TestCheckService_CreateCheckRun_Parameters(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	githubClient := clients.NewGitHubClient(context.Background())
	service := NewCheckService(githubClient, logger)

	ctx := context.Background()
	
	// Test with empty parameters (will likely fail but tests method signature)
	assert.NotPanics(t, func() {
		_, err := service.CreateCheckRun(ctx, "", "", "", CheckRunTypePolicy)
		assert.Error(t, err, "Should return error for empty parameters")
	})
}

func TestCheckService_CompleteCheckRun_Parameters(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	githubClient := clients.NewGitHubClient(context.Background())
	service := NewCheckService(githubClient, logger)

	ctx := context.Background()
	
	// Test with invalid parameters
	assert.NotPanics(t, func() {
		err := service.CompleteCheckRun(ctx, "", "", 0, CheckRunTypePolicy, ConclusionSuccess, CheckRunResult{})
		assert.Error(t, err, "Should return error for invalid parameters")
	})
}

func TestCheckService_ContextHandling(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	githubClient := clients.NewGitHubClient(context.Background())
	service := NewCheckService(githubClient, logger)

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	
	_, err := service.CreateCheckRun(ctx, "owner", "repo", "sha", CheckRunTypePolicy)
	assert.Error(t, err, "Should handle cancelled context")
}
