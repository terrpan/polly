package clients

import (
	"context"

	"github.com/google/go-github/v72/github"
)

// MockGitHubClient is a mock implementation of GitHubClientInterface for testing.
// It allows tests to verify service logic without making real GitHub API calls.
type MockGitHubClient struct {
	// WriteCommentFunc allows customizing the WriteComment behavior
	WriteCommentFunc func(ctx context.Context, owner, repo string, number int, comment string) error
	
	// CreateCheckRunFunc allows customizing the CreateCheckRun behavior
	CreateCheckRunFunc func(ctx context.Context, owner, repo, sha, name string) (*github.CheckRun, error)
	
	// UpdateCheckRunFunc allows customizing the UpdateCheckRun behavior
	UpdateCheckRunFunc func(ctx context.Context, owner, repo string, checkRunID int64, name, status string, conclusion *string, output *github.CheckRunOutput) error
	
	// ListWorkflowArtifactsFunc allows customizing the ListWorkflowArtifacts behavior
	ListWorkflowArtifactsFunc func(ctx context.Context, owner, repo string, workflowID int64) ([]*github.Artifact, error)
	
	// DownloadArtifactFunc allows customizing the DownloadArtifact behavior
	DownloadArtifactFunc func(ctx context.Context, owner, repo string, artifactID int64) ([]byte, error)
	
	// Call tracking for verification
	WriteCommentCalls       []WriteCommentCall
	CreateCheckRunCalls     []CreateCheckRunCall
	UpdateCheckRunCalls     []UpdateCheckRunCall
	ListWorkflowArtifactsCalls []ListWorkflowArtifactsCall
	DownloadArtifactCalls   []DownloadArtifactCall
}

// Call tracking structs
type WriteCommentCall struct {
	Owner   string
	Repo    string
	Number  int
	Comment string
}

type CreateCheckRunCall struct {
	Owner string
	Repo  string
	SHA   string
	Name  string
}

type UpdateCheckRunCall struct {
	Owner      string
	Repo       string
	CheckRunID int64
	Name       string
	Status     string
	Conclusion *string
	Output     *github.CheckRunOutput
}

type ListWorkflowArtifactsCall struct {
	Owner      string
	Repo       string
	WorkflowID int64
}

type DownloadArtifactCall struct {
	Owner      string
	Repo       string
	ArtifactID int64
}

// NewMockGitHubClient creates a new mock GitHub client with default implementations.
func NewMockGitHubClient() *MockGitHubClient {
	return &MockGitHubClient{
		WriteCommentCalls:          make([]WriteCommentCall, 0),
		CreateCheckRunCalls:        make([]CreateCheckRunCall, 0),
		UpdateCheckRunCalls:        make([]UpdateCheckRunCall, 0),
		ListWorkflowArtifactsCalls: make([]ListWorkflowArtifactsCall, 0),
		DownloadArtifactCalls:      make([]DownloadArtifactCall, 0),
	}
}

// WriteComment implements GitHubClientInterface.
func (m *MockGitHubClient) WriteComment(ctx context.Context, owner, repo string, number int, comment string) error {
	// Track the call
	m.WriteCommentCalls = append(m.WriteCommentCalls, WriteCommentCall{
		Owner:   owner,
		Repo:    repo,
		Number:  number,
		Comment: comment,
	})
	
	// Use custom function if provided, otherwise return success
	if m.WriteCommentFunc != nil {
		return m.WriteCommentFunc(ctx, owner, repo, number, comment)
	}
	return nil
}

// CreateCheckRun implements GitHubClientInterface.
func (m *MockGitHubClient) CreateCheckRun(ctx context.Context, owner, repo, sha, name string) (*github.CheckRun, error) {
	// Track the call
	m.CreateCheckRunCalls = append(m.CreateCheckRunCalls, CreateCheckRunCall{
		Owner: owner,
		Repo:  repo,
		SHA:   sha,
		Name:  name,
	})
	
	// Use custom function if provided, otherwise return default check run
	if m.CreateCheckRunFunc != nil {
		return m.CreateCheckRunFunc(ctx, owner, repo, sha, name)
	}
	
	// Return a default check run for successful tests
	return &github.CheckRun{
		ID:      github.Ptr(int64(12345)),
		Name:    github.Ptr(name),
		HeadSHA: github.Ptr(sha),
		Status:  github.Ptr("queued"),
	}, nil
}

// UpdateCheckRun implements GitHubClientInterface.
func (m *MockGitHubClient) UpdateCheckRun(ctx context.Context, owner, repo string, checkRunID int64, name, status string, conclusion *string, output *github.CheckRunOutput) error {
	// Track the call
	m.UpdateCheckRunCalls = append(m.UpdateCheckRunCalls, UpdateCheckRunCall{
		Owner:      owner,
		Repo:       repo,
		CheckRunID: checkRunID,
		Name:       name,
		Status:     status,
		Conclusion: conclusion,
		Output:     output,
	})
	
	// Use custom function if provided, otherwise return success
	if m.UpdateCheckRunFunc != nil {
		return m.UpdateCheckRunFunc(ctx, owner, repo, checkRunID, name, status, conclusion, output)
	}
	return nil
}

// ListWorkflowArtifacts implements GitHubClientInterface.
func (m *MockGitHubClient) ListWorkflowArtifacts(ctx context.Context, owner, repo string, workflowID int64) ([]*github.Artifact, error) {
	// Track the call
	m.ListWorkflowArtifactsCalls = append(m.ListWorkflowArtifactsCalls, ListWorkflowArtifactsCall{
		Owner:      owner,
		Repo:       repo,
		WorkflowID: workflowID,
	})
	
	// Use custom function if provided, otherwise return empty list
	if m.ListWorkflowArtifactsFunc != nil {
		return m.ListWorkflowArtifactsFunc(ctx, owner, repo, workflowID)
	}
	return []*github.Artifact{}, nil
}

// DownloadArtifact implements GitHubClientInterface.
func (m *MockGitHubClient) DownloadArtifact(ctx context.Context, owner, repo string, artifactID int64) ([]byte, error) {
	// Track the call
	m.DownloadArtifactCalls = append(m.DownloadArtifactCalls, DownloadArtifactCall{
		Owner:      owner,
		Repo:       repo,
		ArtifactID: artifactID,
	})
	
	// Use custom function if provided, otherwise return empty data
	if m.DownloadArtifactFunc != nil {
		return m.DownloadArtifactFunc(ctx, owner, repo, artifactID)
	}
	return []byte{}, nil
}

// Helper methods for test assertions

// SetWriteCommentError configures the mock to return an error for WriteComment calls.
func (m *MockGitHubClient) SetWriteCommentError(err error) {
	m.WriteCommentFunc = func(ctx context.Context, owner, repo string, number int, comment string) error {
		return err
	}
}

// SetCreateCheckRunError configures the mock to return an error for CreateCheckRun calls.
func (m *MockGitHubClient) SetCreateCheckRunError(err error) {
	m.CreateCheckRunFunc = func(ctx context.Context, owner, repo, sha, name string) (*github.CheckRun, error) {
		return nil, err
	}
}

// SetUpdateCheckRunError configures the mock to return an error for UpdateCheckRun calls.
func (m *MockGitHubClient) SetUpdateCheckRunError(err error) {
	m.UpdateCheckRunFunc = func(ctx context.Context, owner, repo string, checkRunID int64, name, status string, conclusion *string, output *github.CheckRunOutput) error {
		return err
	}
}

// SetListWorkflowArtifactsError configures the mock to return an error for ListWorkflowArtifacts calls.
func (m *MockGitHubClient) SetListWorkflowArtifactsError(err error) {
	m.ListWorkflowArtifactsFunc = func(ctx context.Context, owner, repo string, workflowID int64) ([]*github.Artifact, error) {
		return nil, err
	}
}

// SetDownloadArtifactError configures the mock to return an error for DownloadArtifact calls.
func (m *MockGitHubClient) SetDownloadArtifactError(err error) {
	m.DownloadArtifactFunc = func(ctx context.Context, owner, repo string, artifactID int64) ([]byte, error) {
		return nil, err
	}
}

// Reset clears all call tracking data.
func (m *MockGitHubClient) Reset() {
	m.WriteCommentCalls = make([]WriteCommentCall, 0)
	m.CreateCheckRunCalls = make([]CreateCheckRunCall, 0)
	m.UpdateCheckRunCalls = make([]UpdateCheckRunCall, 0)
	m.ListWorkflowArtifactsCalls = make([]ListWorkflowArtifactsCall, 0)
	m.DownloadArtifactCalls = make([]DownloadArtifactCall, 0)
}

// GetWriteCommentCallCount returns the number of WriteComment calls made.
func (m *MockGitHubClient) GetWriteCommentCallCount() int {
	return len(m.WriteCommentCalls)
}

// GetCreateCheckRunCallCount returns the number of CreateCheckRun calls made.
func (m *MockGitHubClient) GetCreateCheckRunCallCount() int {
	return len(m.CreateCheckRunCalls)
}

// GetUpdateCheckRunCallCount returns the number of UpdateCheckRun calls made.
func (m *MockGitHubClient) GetUpdateCheckRunCallCount() int {
	return len(m.UpdateCheckRunCalls)
}

// GetListWorkflowArtifactsCallCount returns the number of ListWorkflowArtifacts calls made.
func (m *MockGitHubClient) GetListWorkflowArtifactsCallCount() int {
	return len(m.ListWorkflowArtifactsCalls)
}

// GetDownloadArtifactCallCount returns the number of DownloadArtifact calls made.
func (m *MockGitHubClient) GetDownloadArtifactCallCount() int {
	return len(m.DownloadArtifactCalls)
}

// Compile-time check to ensure MockGitHubClient implements GitHubClientInterface
var _ GitHubClientInterface = (*MockGitHubClient)(nil)