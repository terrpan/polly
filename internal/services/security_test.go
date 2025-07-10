package services

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/google/go-github/v72/github"
	"github.com/stretchr/testify/assert"
	"github.com/terrpan/polly/internal/clients"
)

func TestNewSecurityService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()

	service := NewSecurityService(mockClient, logger)

	assert.NotNil(t, service)
	assert.Equal(t, mockClient, service.githubClient)
	assert.Equal(t, logger, service.logger)
}

func TestSecurityService_ProcessWorkflowSecurityArtifacts_NoArtifacts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewSecurityService(mockClient, logger)

	// Configure mock to return empty artifact list
	mockClient.ListWorkflowArtifactsFunc = func(ctx context.Context, owner, repo string, workflowID int64) ([]*github.Artifact, error) {
		return []*github.Artifact{}, nil
	}

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "abc123"
	workflowID := int64(456)

	// Execute the service method
	payloads, err := service.ProcessWorkflowSecurityArtifacts(ctx, owner, repo, sha, workflowID)

	// Verify results
	assert.NoError(t, err)
	assert.Nil(t, payloads) // Should return nil when no artifacts found
	
	// Verify the GitHub client was called correctly
	assert.Equal(t, 1, mockClient.GetListWorkflowArtifactsCallCount())
	call := mockClient.ListWorkflowArtifactsCalls[0]
	assert.Equal(t, owner, call.Owner)
	assert.Equal(t, repo, call.Repo)
	assert.Equal(t, workflowID, call.WorkflowID)
}

func TestSecurityService_ProcessWorkflowSecurityArtifacts_Error(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewSecurityService(mockClient, logger)

	// Configure mock to return an error
	expectedError := errors.New("GitHub API error")
	mockClient.SetListWorkflowArtifactsError(expectedError)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "abc123"
	workflowID := int64(456)

	// Execute the service method
	payloads, err := service.ProcessWorkflowSecurityArtifacts(ctx, owner, repo, sha, workflowID)

	// Verify error handling
	assert.Error(t, err)
	assert.Nil(t, payloads)
	assert.Contains(t, err.Error(), "failed to discover security artifacts")
	
	// Verify the GitHub client was called
	assert.Equal(t, 1, mockClient.GetListWorkflowArtifactsCallCount())
}

func TestSecurityService_ProcessWorkflowSecurityArtifacts_WithArtifacts(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewSecurityService(mockClient, logger)

	// Create mock artifacts
	artifacts := []*github.Artifact{
		{
			ID:   github.Ptr(int64(123)),
			Name: github.Ptr("security-scan"),
			SizeInBytes: github.Ptr(int64(1024)),
		},
	}

	// Configure mock to return artifacts and download data
	mockClient.ListWorkflowArtifactsFunc = func(ctx context.Context, owner, repo string, workflowID int64) ([]*github.Artifact, error) {
		return artifacts, nil
	}

	// Mock zip content that doesn't contain security files
	mockClient.DownloadArtifactFunc = func(ctx context.Context, owner, repo string, artifactID int64) ([]byte, error) {
		// Return minimal zip content that won't be recognized as security content
		return []byte("PK\x03\x04\x14\x00\x00\x00\x08\x00"), nil
	}

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	sha := "abc123"
	workflowID := int64(456)

	// Execute the service method
	payloads, err := service.ProcessWorkflowSecurityArtifacts(ctx, owner, repo, sha, workflowID)

	// Verify results - should succeed but return empty list since no security content found
	assert.NoError(t, err)
	assert.Empty(t, payloads)
	
	// Verify the GitHub client was called correctly
	assert.Equal(t, 1, mockClient.GetListWorkflowArtifactsCallCount())
	assert.Equal(t, 1, mockClient.GetDownloadArtifactCallCount())
}

func TestSecurityService_DiscoverSecurityArtifacts_Error(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewSecurityService(mockClient, logger)

	// Configure mock to return an error
	expectedError := errors.New("GitHub API error")
	mockClient.SetListWorkflowArtifactsError(expectedError)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	workflowID := int64(456)

	// Execute the service method
	artifacts, err := service.DiscoverSecurityArtifacts(ctx, owner, repo, workflowID)

	// Verify error handling
	assert.Error(t, err)
	assert.Nil(t, artifacts)
	assert.Contains(t, err.Error(), "failed to list artifacts")
	
	// Verify the GitHub client was called
	assert.Equal(t, 1, mockClient.GetListWorkflowArtifactsCallCount())
}

func TestSecurityService_BuildPayloadsFromArtifacts_EmptyList(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewSecurityService(mockClient, logger)

	ctx := context.Background()
	artifacts := []*SecurityArtifact{}
	owner := "test-owner"
	repo := "test-repo"
	sha := "abc123"
	workflowID := int64(456)

	// Execute the service method
	payloads, err := service.BuildPayloadsFromArtifacts(ctx, artifacts, owner, repo, sha, workflowID)

	// Verify results
	assert.NoError(t, err)
	assert.Empty(t, payloads)
	
	// No GitHub client calls should be made for this method
	assert.Equal(t, 0, mockClient.GetListWorkflowArtifactsCallCount())
}

func TestSecurityService_BuildPayloadsFromArtifacts_UnsupportedType(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewSecurityService(mockClient, logger)

	ctx := context.Background()
	artifacts := []*SecurityArtifact{
		{
			ArtifactName: "test-artifact",
			FileName:     "unknown.txt",
			Content:      []byte("some content"),
			Type:         ArtifactTypeUnknown,
		},
	}
	owner := "test-owner"
	repo := "test-repo"
	sha := "abc123"
	workflowID := int64(456)

	// Execute the service method
	payloads, err := service.BuildPayloadsFromArtifacts(ctx, artifacts, owner, repo, sha, workflowID)

	// Verify results - should succeed but return empty list for unsupported type
	assert.NoError(t, err)
	assert.Empty(t, payloads)
}

func TestSecurityService_VulnerabilityPayload_Structure(t *testing.T) {
	// Test vulnerability payload structure
	payload := VulnerabilityPayload{
		Type: "vulnerability_scan",
		Metadata: PayloadMetadata{
			SourceFormat: "trivy_json",
			ToolName:     "trivy",
			Repository:   "test/repo",
			CommitSHA:    "abc123",
		},
		Vulnerabilities: []Vulnerability{
			{
				ID:       "CVE-2021-1234",
				Severity: "HIGH",
				Package: Package{
					Name:    "test-package",
					Version: "1.0.0",
				},
			},
		},
		Summary: VulnerabilitySummary{
			TotalVulnerabilities: 1,
			High:                 1,
		},
	}

	assert.Equal(t, "vulnerability_scan", payload.Type)
	assert.Equal(t, "trivy", payload.Metadata.ToolName)
	assert.Len(t, payload.Vulnerabilities, 1)
	assert.Equal(t, "CVE-2021-1234", payload.Vulnerabilities[0].ID)
	assert.Equal(t, 1, payload.Summary.TotalVulnerabilities)
}

func TestSecurityService_ContextCancellation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewSecurityService(mockClient, logger)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Configure mock to check for context cancellation
	mockClient.ListWorkflowArtifactsFunc = func(ctx context.Context, owner, repo string, workflowID int64) ([]*github.Artifact, error) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return []*github.Artifact{}, nil
	}

	owner := "test-owner"
	repo := "test-repo"
	sha := "abc123"
	workflowID := int64(456)

	// Execute the service method
	payloads, err := service.ProcessWorkflowSecurityArtifacts(ctx, owner, repo, sha, workflowID)

	// Verify that context cancellation is handled
	assert.Error(t, err)
	assert.Nil(t, payloads)
	assert.Contains(t, err.Error(), "failed to discover security artifacts")
	assert.Equal(t, 1, mockClient.GetListWorkflowArtifactsCallCount())
}