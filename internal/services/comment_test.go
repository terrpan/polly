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

func TestNewCommentService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()

	service := NewCommentService(mockClient, logger)

	assert.NotNil(t, service)
	assert.Equal(t, mockClient, service.githubClient)
	assert.Equal(t, logger, service.logger)
}

func TestCommentService_WriteComment_Success(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewCommentService(mockClient, logger)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	number := 123
	comment := "Test comment"

	// Execute the service method
	err := service.WriteComment(ctx, owner, repo, number, comment)

	// Verify results
	assert.NoError(t, err)
	
	// Verify the GitHub client was called correctly
	assert.Equal(t, 1, mockClient.GetWriteCommentCallCount())
	call := mockClient.WriteCommentCalls[0]
	assert.Equal(t, owner, call.Owner)
	assert.Equal(t, repo, call.Repo)
	assert.Equal(t, number, call.Number)
	assert.Equal(t, comment, call.Comment)
}

func TestCommentService_WriteComment_Error(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewCommentService(mockClient, logger)

	// Configure mock to return an error
	expectedError := errors.New("GitHub API error")
	mockClient.SetWriteCommentError(expectedError)

	ctx := context.Background()
	owner := "test-owner"
	repo := "test-repo"
	number := 123
	comment := "Test comment"

	// Execute the service method
	err := service.WriteComment(ctx, owner, repo, number, comment)

	// Verify error handling
	assert.Error(t, err)
	assert.Equal(t, expectedError, err)
	
	// Verify the GitHub client was still called
	assert.Equal(t, 1, mockClient.GetWriteCommentCallCount())
}

func TestCommentService_WriteComment_ParameterValidation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewCommentService(mockClient, logger)

	ctx := context.Background()

	tests := []struct {
		name    string
		owner   string
		repo    string
		number  int
		comment string
	}{
		{
			name:    "empty owner",
			owner:   "",
			repo:    "test-repo",
			number:  123,
			comment: "test comment",
		},
		{
			name:    "empty repo", 
			owner:   "test-owner",
			repo:    "",
			number:  123,
			comment: "test comment",
		},
		{
			name:    "zero number",
			owner:   "test-owner",
			repo:    "test-repo",
			number:  0,
			comment: "test comment",
		},
		{
			name:    "empty comment",
			owner:   "test-owner",
			repo:    "test-repo",
			number:  123,
			comment: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset mock between tests
			mockClient.Reset()

			// Execute the service method
			err := service.WriteComment(ctx, tt.owner, tt.repo, tt.number, tt.comment)

			// The service doesn't do parameter validation, so it should still call the client
			// In a real implementation, you might want to add validation
			assert.NoError(t, err) // Mock returns success by default
			assert.Equal(t, 1, mockClient.GetWriteCommentCallCount())
		})
	}
}

func TestCommentService_WriteComment_ContextCancellation(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	mockClient := clients.NewMockGitHubClient()
	service := NewCommentService(mockClient, logger)

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Configure mock to check for context cancellation
	mockClient.WriteCommentFunc = func(ctx context.Context, owner, repo string, number int, comment string) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return nil
	}

	owner := "test-owner"
	repo := "test-repo"
	number := 123
	comment := "test comment"

	// Execute the service method
	err := service.WriteComment(ctx, owner, repo, number, comment)

	// Verify that context cancellation is handled
	assert.Error(t, err)
	assert.Equal(t, context.Canceled, err)
	assert.Equal(t, 1, mockClient.GetWriteCommentCallCount())
}