# GitHub Client Interface and Mocking

This directory provides both a concrete GitHub client implementation and a mock for testing.

## Interface

The `GitHubClientInterface` defines the GitHub API operations needed by services:

```go
type GitHubClientInterface interface {
    WriteComment(ctx context.Context, owner, repo string, number int, comment string) error
    CreateCheckRun(ctx context.Context, owner, repo, sha, name string) (*github.CheckRun, error)
    UpdateCheckRun(ctx context.Context, owner, repo string, checkRunID int64, name, status string, conclusion *string, output *github.CheckRunOutput) error
    ListWorkflowArtifacts(ctx context.Context, owner, repo string, workflowID int64) ([]*github.Artifact, error)
    DownloadArtifact(ctx context.Context, owner, repo string, artifactID int64) ([]byte, error)
}
```

## Concrete Implementation

The `GitHubClient` struct implements this interface and provides real GitHub API functionality:

```go
// Production usage
githubClient := clients.NewGitHubClient(ctx)
commentService := services.NewCommentService(githubClient, logger)
```

## Mock Implementation

The `MockGitHubClient` struct implements the same interface for testing:

```go
// Test usage
mockClient := clients.NewMockGitHubClient()
commentService := services.NewCommentService(mockClient, logger)

// Configure mock behavior
mockClient.SetWriteCommentError(errors.New("API error"))

// Execute service method
err := commentService.WriteComment(ctx, "owner", "repo", 123, "comment")

// Verify interactions
assert.Equal(t, 1, mockClient.GetWriteCommentCallCount())
```

## Benefits

1. **Unit Testing**: Tests can verify service logic without making real GitHub API calls
2. **Reliability**: No network dependencies or rate limiting issues in tests
3. **Speed**: Tests run faster without network latency
4. **Isolation**: Each test can configure mock behavior independently
5. **Verification**: Tests can verify exact parameters passed to GitHub API

## Usage Examples

See the test files in `internal/services/` for complete examples of how to use the mock in unit tests.