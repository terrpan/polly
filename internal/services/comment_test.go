package services

import (
"context"
"testing"
"log/slog"
"os"

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
