package clients

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v72/github"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

type GitHubClient struct {
	client *github.Client
	// httpClient *http.Client
}

// GitHubAppConfig holds the configuration for GitHub App authentication
type GitHubAppConfig struct {
	AppID          int64
	InstallationID int64
	PrivateKey     []byte
}

// NewGitHubClient initializes a new GitHub client.
func NewGitHubClient(ctx context.Context) *GitHubClient {
	client := github.NewClient(nil) // Use nil for unauthenticated requests; replace with an authenticated client if needed.
	return &GitHubClient{
		client: client,
	}
}

// NewGitHubAppClient initializes a new GitHub client for GitHub App authentication.
func NewGitHubAppClient(ctx context.Context, config GitHubAppConfig) (*GitHubClient, error) {
	// Create a GitHub app transport
	transport, err := ghinstallation.New(
		otelhttp.NewTransport(http.DefaultTransport), // Wrap the default transport with OpenTelemetry instrumentation
		// http.DefaultTransport,
		config.AppID,
		config.InstallationID,
		config.PrivateKey,
	)

	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub app transport: %w", err)
	}
	// Create a new GitHub client with the app transport
	httpClient := &http.Client{Transport: transport}
	client := github.NewClient(httpClient)
	return &GitHubClient{
		client: client,
		// httpClient: httpClient,
	}, nil
}

// Authenticate authenticates the GitHub client using a personal access token.
func (c *GitHubClient) Authenticate(ctx context.Context, token string) error {
	if token == "" {
		return fmt.Errorf("authentication token is required")
	}

	c.client = github.NewTokenClient(ctx, token)
	return nil
}

// GetPullRequest retrieves a pull request by its number from the specified repository.
func (c *GitHubClient) GetPullRequest(ctx context.Context, owner, repo string, number int) (*github.PullRequest, error) {
	pr, _, err := c.client.PullRequests.Get(ctx, owner, repo, number)
	if err != nil {
		return nil, err
	}

	return pr, nil
}

// WriteComment writes a comment on a pull request.
func (c *GitHubClient) WriteComment(ctx context.Context, owner, repo string, number int, comment string) error {
	_, _, err := c.client.Issues.CreateComment(ctx, owner, repo, number, &github.IssueComment{Body: &comment})
	if err != nil {
		return fmt.Errorf("failed to write comment: %w", err)
	}

	return nil
}

// CreateCheckRun creates a check run for a given commit SHA in a repository.
func (c *GitHubClient) CreateCheckRun(ctx context.Context, owner, repo, sha, name string) (*github.CheckRun, error) {
	opts := github.CreateCheckRunOptions{
		Name:    name,
		HeadSHA: sha,
		Status:  github.Ptr("queued"),
		StartedAt: &github.Timestamp{
			Time: time.Now(),
		},
	}

	checkRun, _, err := c.client.Checks.CreateCheckRun(ctx, owner, repo, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create check run: %w", err)
	}

	return checkRun, nil
}

// UpdateCheckRun updates an existing check run with the given ID.
func (c *GitHubClient) UpdateCheckRun(ctx context.Context, owner, repo string, checkRunID int64, name, status string, conclusion *string, output *github.CheckRunOutput) error {
	opts := github.UpdateCheckRunOptions{
		Name:   name,
		Status: github.Ptr(status),
	}

	// Only set conclusion and completed_at for completed checks
	if conclusion != nil {
		opts.Conclusion = conclusion
		opts.CompletedAt = &github.Timestamp{
			Time: time.Now(),
		}
	}

	// Add detailed output if provided
	if output != nil {
		opts.Output = output
	}

	_, _, err := c.client.Checks.UpdateCheckRun(ctx, owner, repo, checkRunID, opts)
	if err != nil {
		return fmt.Errorf("failed to update check run: %w", err)
	}

	return nil
}

// GetCheckRun retrieves a check run by its ID from the specified repository.
func (c *GitHubClient) GetCheckRun(ctx context.Context, owner, repo string, checkRunID int64) (*github.CheckRun, error) {
	checkRun, _, err := c.client.Checks.GetCheckRun(ctx, owner, repo, checkRunID)
	if err != nil {
		return nil, fmt.Errorf("failed to get check run: %w", err)
	}

	return checkRun, nil
}

// ListCheckRuns lists all check runs for a given commit SHA in a repository.
func (c *GitHubClient) ListCheckRuns(ctx context.Context, owner, repo, sha string) ([]*github.CheckRun, error) {
	checkRuns, _, err := c.client.Checks.ListCheckRunsForRef(ctx, owner, repo, sha, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to list check runs: %w", err)
	}

	return checkRuns.CheckRuns, nil
}

// ListWorkflowArtifacts lists all artifacts for a given workflow run in a repository.
func (c *GitHubClient) ListWorkflowArtifacts(ctx context.Context, owner, repo string, workflowID int64) ([]*github.Artifact, error) {
	var allArtifacts []*github.Artifact

	opts := &github.ListOptions{
		Page:    1,
		PerPage: 100, // Adjust as needed
	}

	for {
		artifacts, resp, err := c.client.Actions.ListWorkflowRunArtifacts(ctx, owner, repo, workflowID, opts)
		if err != nil {
			return nil, fmt.Errorf("failed to list workflow artifacts: %w", err)
		}

		allArtifacts = append(allArtifacts, artifacts.Artifacts...)

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allArtifacts, nil
}

// DownloadArtifact downloads a specific artifact by its ID from a workflow run.
func (c *GitHubClient) DownloadArtifact(ctx context.Context, owner, repo string, artifactID int64) ([]byte, error) {
	const maxArtifactSize = 100 * 1024 * 1024 // 100 MB limit

	// Get artifact metadata to check size
	artifact, _, err := c.client.Actions.GetArtifact(ctx, owner, repo, artifactID)
	if err != nil {
		return nil, fmt.Errorf("failed to get artifact metadata: %w", err)
	}

	if artifact.GetSizeInBytes() > maxArtifactSize {
		return nil, fmt.Errorf("artifact size exceeds maximum limit of %d bytes", maxArtifactSize)
	}

	// Download the artifact
	url, _, err := c.client.Actions.DownloadArtifact(ctx, owner, repo, artifactID, 2)
	if err != nil {
		return nil, fmt.Errorf("failed to download artifact: %w", err)
	}

	// Use a clean HTTP client for downloading (Azure blob storage doesn't need GitHub auth)
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create download request: %w", err)
	}

	resp, err := httpClient.Do(req) // Use a clean HTTP client for downloading
	if err != nil {
		return nil, fmt.Errorf("failed to perform download request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download artifact: received status code %d", resp.StatusCode)
	}

	// Limit reader to prevent excessive memory usage
	limitedReader := io.LimitReader(resp.Body, maxArtifactSize)
	content, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read artifact content: %w", err)
	}

	return content, nil
}

// GetArtifact gets metadata about a specific artifact
func (c *GitHubClient) GetArtifact(ctx context.Context, owner, repo string, artifactID int64) (*github.Artifact, error) {
	artifact, _, err := c.client.Actions.GetArtifact(ctx, owner, repo, artifactID)
	if err != nil {
		return nil, fmt.Errorf("failed to get artifact: %w", err)
	}

	return artifact, nil
}
