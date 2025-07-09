package services

import (
	"context"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Mock GitHub Client for comment service testing
type MockCommentGitHubClient struct {
	mock.Mock
}

func (m *MockCommentGitHubClient) WriteComment(ctx context.Context, owner, repo string, number int, comment string) error {
	args := m.Called(ctx, owner, repo, number, comment)
	return args.Error(0)
}

func TestNewCommentService(t *testing.T) {
	logger := slog.Default()
	mockClient := &MockCommentGitHubClient{}

	service := NewCommentService(mockClient, logger)

	assert.NotNil(t, service)
	assert.Equal(t, mockClient, service.githubClient)
	assert.Equal(t, logger, service.logger)
}

func TestCommentService_WriteComment(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name          string
		owner         string
		repo          string
		prNumber      int
		comment       string
		mockError     error
		expectedError bool
	}{
		{
			name:          "successful comment write",
			owner:         "owner",
			repo:          "repo",
			prNumber:      123,
			comment:       "This is a test comment",
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "successful comment write with long text",
			owner:         "testowner",
			repo:          "testrepo",
			prNumber:      456,
			comment:       "This is a very long comment with lots of text that should still be handled properly by the comment service. It includes multiple sentences and should test the service's ability to handle larger comment bodies without any issues.",
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "successful comment write with special characters",
			owner:         "owner",
			repo:          "repo",
			prNumber:      789,
			comment:       "Comment with special chars: @mention, #issue, `code`, **bold**, *italic*\n\nWith newlines and [links](https://example.com)",
			mockError:     nil,
			expectedError: false,
		},
		{
			name:          "failed comment write - API error",
			owner:         "owner",
			repo:          "repo",
			prNumber:      999,
			comment:       "This comment will fail",
			mockError:     fmt.Errorf("GitHub API error: rate limit exceeded"),
			expectedError: true,
		},
		{
			name:          "failed comment write - permission error",
			owner:         "owner",
			repo:          "private-repo",
			prNumber:      111,
			comment:       "Permission denied comment",
			mockError:     fmt.Errorf("GitHub API error: insufficient permissions"),
			expectedError: true,
		},
		{
			name:          "empty comment",
			owner:         "owner",
			repo:          "repo",
			prNumber:      222,
			comment:       "",
			mockError:     nil,
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockCommentGitHubClient{}
			service := NewCommentService(mockClient, logger)

			mockClient.On("WriteComment", mock.Anything, tt.owner, tt.repo, tt.prNumber, tt.comment).Return(tt.mockError)

			ctx := context.Background()
			err := service.WriteComment(ctx, tt.owner, tt.repo, tt.prNumber, tt.comment)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Equal(t, tt.mockError, err)
			} else {
				assert.NoError(t, err)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestCommentService_WriteComment_ContextHandling(t *testing.T) {
	logger := slog.Default()
	mockClient := &MockCommentGitHubClient{}
	service := NewCommentService(mockClient, logger)

	t.Run("context with values", func(t *testing.T) {
		// Create a context with some values
		ctx := context.WithValue(context.Background(), "test-key", "test-value")
		
		mockClient.On("WriteComment", mock.MatchedBy(func(ctx context.Context) bool {
			// Verify the context is passed through
			return ctx.Value("test-key") == "test-value"
		}), "owner", "repo", 123, "test comment").Return(nil)

		err := service.WriteComment(ctx, "owner", "repo", 123, "test comment")

		assert.NoError(t, err)
		mockClient.AssertExpectations(t)
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel the context before making the call

		// The mock should still receive the cancelled context
		mockClient.On("WriteComment", mock.MatchedBy(func(ctx context.Context) bool {
			return ctx.Err() != nil // Context should be cancelled
		}), "owner", "repo", 123, "test comment").Return(context.Canceled)

		err := service.WriteComment(ctx, "owner", "repo", 123, "test comment")

		assert.Error(t, err)
		assert.Equal(t, context.Canceled, err)
		mockClient.AssertExpectations(t)
	})
}

func TestCommentService_WriteComment_ParameterValidation(t *testing.T) {
	logger := slog.Default()
	mockClient := &MockCommentGitHubClient{}
	service := NewCommentService(mockClient, logger)

	ctx := context.Background()

	tests := []struct {
		name     string
		owner    string
		repo     string
		prNumber int
		comment  string
	}{
		{
			name:     "typical parameters",
			owner:    "octocat",
			repo:     "Hello-World",
			prNumber: 1,
			comment:  "Hello, World!",
		},
		{
			name:     "hyphenated owner and repo",
			owner:    "test-org",
			repo:     "test-repo-name",
			prNumber: 42,
			comment:  "Testing hyphenated names",
		},
		{
			name:     "large PR number",
			owner:    "owner",
			repo:     "repo",
			prNumber: 999999,
			comment:  "Large PR number test",
		},
		{
			name:     "unicode in comment",
			owner:    "owner",
			repo:     "repo", 
			prNumber: 1,
			comment:  "Unicode test: 🎉 ✅ 🚀 こんにちは 世界",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient.On("WriteComment", mock.Anything, tt.owner, tt.repo, tt.prNumber, tt.comment).Return(nil)

			err := service.WriteComment(ctx, tt.owner, tt.repo, tt.prNumber, tt.comment)

			assert.NoError(t, err)
			mockClient.AssertExpectations(t)
		})
	}
}

func TestCommentService_ErrorPropagation(t *testing.T) {
	logger := slog.Default()
	mockClient := &MockCommentGitHubClient{}
	service := NewCommentService(mockClient, logger)

	ctx := context.Background()

	tests := []struct {
		name          string
		mockError     error
		expectedError error
	}{
		{
			name:          "network error",
			mockError:     fmt.Errorf("network connection failed"),
			expectedError: fmt.Errorf("network connection failed"),
		},
		{
			name:          "API rate limit error",
			mockError:     fmt.Errorf("API rate limit exceeded"),
			expectedError: fmt.Errorf("API rate limit exceeded"),
		},
		{
			name:          "authentication error",
			mockError:     fmt.Errorf("authentication failed"),
			expectedError: fmt.Errorf("authentication failed"),
		},
		{
			name:          "repository not found",
			mockError:     fmt.Errorf("repository not found"),
			expectedError: fmt.Errorf("repository not found"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient.On("WriteComment", mock.Anything, "owner", "repo", 123, "test comment").Return(tt.mockError)

			err := service.WriteComment(ctx, "owner", "repo", 123, "test comment")

			assert.Error(t, err)
			assert.Equal(t, tt.expectedError.Error(), err.Error())
			mockClient.AssertExpectations(t)
		})
	}
}

func TestCommentService_Logging(t *testing.T) {
	// This test verifies that the service integrates properly with the logger
	// In a real scenario, you might want to use a test logger to verify log messages

	logger := slog.Default()
	mockClient := &MockCommentGitHubClient{}
	service := NewCommentService(mockClient, logger)

	ctx := context.Background()

	t.Run("successful comment logs properly", func(t *testing.T) {
		mockClient.On("WriteComment", mock.Anything, "owner", "repo", 123, "test comment").Return(nil)

		err := service.WriteComment(ctx, "owner", "repo", 123, "test comment")

		assert.NoError(t, err)
		mockClient.AssertExpectations(t)
		// In a real test, you would verify the log messages were written
	})

	t.Run("failed comment logs error", func(t *testing.T) {
		expectedError := fmt.Errorf("test error")
		mockClient.On("WriteComment", mock.Anything, "owner", "repo", 123, "test comment").Return(expectedError)

		err := service.WriteComment(ctx, "owner", "repo", 123, "test comment")

		assert.Error(t, err)
		assert.Equal(t, expectedError, err)
		mockClient.AssertExpectations(t)
		// In a real test, you would verify the error was logged
	})
}
