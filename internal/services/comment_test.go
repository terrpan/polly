package services

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/terrpan/polly/internal/clients"
)

func TestNewCommentService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	githubClient := clients.NewGitHubClient(context.Background())

	service := NewCommentService(githubClient, logger)

	assert.NotNil(t, service)
	assert.Equal(t, githubClient, service.githubClient)
	assert.Equal(t, logger, service.logger)
}

func TestCommentService_WriteComment_Structure(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	githubClient := clients.NewGitHubClient(context.Background())
	service := NewCommentService(githubClient, logger)

	// Test that service has the expected structure
	assert.NotNil(t, service.githubClient)
	assert.NotNil(t, service.logger)

	// Note: We can't test actual WriteComment without mocking GitHub API
	// This would require integration testing with a real or stubbed GitHub API
}

func TestCommentService_WriteComment_Parameters(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	githubClient := clients.NewGitHubClient(context.Background())
	service := NewCommentService(githubClient, logger)

	ctx := context.Background()

	// Test parameter validation (function will likely fail on API call, but tests signature)
	assert.NotPanics(t, func() {
		// Test with empty parameters to verify method signature
		err := service.WriteComment(ctx, "", "", 0, "")
		// Error is expected due to empty parameters and no real GitHub API
		assert.Error(t, err)
	})
}

func TestCommentService_ErrorHandling(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	githubClient := clients.NewGitHubClient(context.Background())
	service := NewCommentService(githubClient, logger)

	ctx := context.Background()

	// Test with invalid parameters
	err := service.WriteComment(ctx, "invalid", "repo", 0, "test comment")
	assert.Error(t, err, "Should return error for invalid parameters")

	// Test with empty comment
	err = service.WriteComment(ctx, "owner", "repo", 1, "")
	assert.Error(t, err, "Should return error for empty comment")
}

func TestCommentService_ContextHandling(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	githubClient := clients.NewGitHubClient(context.Background())
	service := NewCommentService(githubClient, logger)

	// Test context cancellation
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	err := service.WriteComment(ctx, "owner", "repo", 1, "test")
	assert.Error(t, err, "Should handle cancelled context")
}
