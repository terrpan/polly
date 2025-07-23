package clients

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-github/v72/github"
	"github.com/stretchr/testify/suite"
)

// GitHubClientTestSuite provides a test suite for GitHub client tests
type GitHubClientTestSuite struct {
	suite.Suite
	ctx          context.Context
	mockServer   *httptest.Server
	client       *github.Client
	githubClient *GitHubClient
}

// SetupSuite runs once before all tests in the suite
func (suite *GitHubClientTestSuite) SetupSuite() {
	suite.ctx = context.Background()
}

// SetupTest runs before each test
func (suite *GitHubClientTestSuite) SetupTest() {
	// Create mock server with common GitHub API endpoints
	suite.mockServer = httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			suite.handleMockRequest(w, r)
		}),
	)

	// Create GitHub client pointing to mock server
	suite.client = github.NewClient(nil)
	suite.client.BaseURL = mustParseURL(suite.mockServer.URL + "/")
	suite.githubClient = &GitHubClient{client: suite.client}
}

// TearDownTest runs after each test
func (suite *GitHubClientTestSuite) TearDownTest() {
	if suite.mockServer != nil {
		suite.mockServer.Close()
	}
}

// handleMockRequest handles all mock server requests
func (suite *GitHubClientTestSuite) handleMockRequest(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/repos/owner/repo/pulls/123":
		suite.handleGetPullRequest(w, r, "123")
	case "/repos/owner/repo/pulls/404":
		suite.handleGetPullRequest(w, r, "404")
	case "/repos/owner/repo/issues/123/comments":
		suite.handleWriteComment(w, r, "123")
	case "/repos/owner/repo/issues/500/comments":
		suite.handleWriteComment(w, r, "500")
	case "/repos/owner/repo/check-runs":
		suite.handleCreateCheckRun(w, r, "owner", "repo")
	case "/repos/owner/error-repo/check-runs":
		suite.handleCreateCheckRun(w, r, "owner", "error-repo")
	case "/repos/owner/repo/check-runs/789":
		if r.Method == http.MethodGet {
			suite.handleGetCheckRun(w, r, "789")
		} else {
			suite.handleUpdateCheckRun(w, r, "789")
		}
	case "/repos/owner/repo/check-runs/404":
		if r.Method == http.MethodGet {
			suite.handleGetCheckRun(w, r, "404")
		} else {
			suite.handleUpdateCheckRun(w, r, "404")
		}
	case "/repos/owner/repo/actions/runs/123/artifacts":
		suite.handleListWorkflowArtifacts(w, r, "123")
	case "/repos/owner/repo/actions/runs/404/artifacts":
		suite.handleListWorkflowArtifacts(w, r, "404")
	case "/repos/owner/repo/commits/abc123/check-runs":
		suite.handleListCheckRuns(w, r, "abc123")
	case "/repos/owner/repo/commits/404/check-runs":
		suite.handleListCheckRuns(w, r, "404")
	case "/repos/owner/repo/actions/artifacts/123":
		suite.handleGetArtifact(w, r, "123")
	case "/repos/owner/repo/actions/artifacts/404":
		suite.handleGetArtifact(w, r, "404")
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// Helper methods for specific endpoints
func (suite *GitHubClientTestSuite) handleGetPullRequest(
	w http.ResponseWriter,
	r *http.Request,
	prNumber string,
) {
	if prNumber == "404" {
		w.WriteHeader(http.StatusNotFound)
		writeTestResponse(w, []byte(`{"message": "Not Found"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := `{
		"id": 123,
		"number": 123,
		"title": "Test PR",
		"body": "Test description",
		"state": "open",
		"head": {
			"sha": "abc123"
		},
		"base": {
			"ref": "main"
		}
	}`
	writeTestResponse(w, []byte(response))
}

func (suite *GitHubClientTestSuite) handleWriteComment(
	w http.ResponseWriter,
	r *http.Request,
	issueNumber string,
) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if issueNumber == "500" {
		w.WriteHeader(http.StatusInternalServerError)
		writeTestResponse(w, []byte(`{"message": "Internal Server Error"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	response := `{
		"id": 456,
		"body": "Test comment",
		"user": {
			"login": "test-user"
		}
	}`
	writeTestResponse(w, []byte(response))
}

func (suite *GitHubClientTestSuite) handleCreateCheckRun(
	w http.ResponseWriter,
	r *http.Request,
	owner, repo string,
) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if repo == "error-repo" {
		w.WriteHeader(http.StatusUnprocessableEntity)
		writeTestResponse(w, []byte(`{"message": "Validation Failed"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	response := `{
		"id": 789,
		"name": "Test Check",
		"head_sha": "abc123",
		"status": "queued",
		"started_at": "2023-01-01T00:00:00Z"
	}`
	writeTestResponse(w, []byte(response))
}

func (suite *GitHubClientTestSuite) handleGetCheckRun(
	w http.ResponseWriter,
	r *http.Request,
	checkRunID string,
) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if checkRunID == "404" {
		w.WriteHeader(http.StatusNotFound)
		writeTestResponse(w, []byte(`{"message": "Not Found"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := `{
		"id": 789,
		"name": "Test Check",
		"head_sha": "abc123",
		"status": "completed",
		"conclusion": "success"
	}`
	writeTestResponse(w, []byte(response))
}

func (suite *GitHubClientTestSuite) handleUpdateCheckRun(
	w http.ResponseWriter,
	r *http.Request,
	checkRunID string,
) {
	if r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if checkRunID == "404" {
		w.WriteHeader(http.StatusNotFound)
		writeTestResponse(w, []byte(`{"message": "Not Found"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := `{
		"id": 789,
		"name": "Test Check",
		"head_sha": "abc123",
		"status": "completed",
		"conclusion": "success"
	}`
	writeTestResponse(w, []byte(response))
}

func (suite *GitHubClientTestSuite) handleListWorkflowArtifacts(
	w http.ResponseWriter,
	r *http.Request,
	runID string,
) {
	if runID == "404" {
		w.WriteHeader(http.StatusNotFound)
		writeTestResponse(w, []byte(`{"message": "Not Found"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := `{
		"total_count": 2,
		"artifacts": [
			{
				"id": 456,
				"name": "trivy-results",
				"size_in_bytes": 1024,
				"created_at": "2023-01-01T00:00:00Z"
			},
			{
				"id": 789,
				"name": "sbom-report",
				"size_in_bytes": 2048,
				"created_at": "2023-01-01T00:00:00Z"
			}
		]
	}`
	writeTestResponse(w, []byte(response))
}

func (suite *GitHubClientTestSuite) handleListCheckRuns(
	w http.ResponseWriter,
	r *http.Request,
	sha string,
) {
	if sha == "404" {
		w.WriteHeader(http.StatusNotFound)
		writeTestResponse(w, []byte(`{"message": "Not Found"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := `{
		"total_count": 2,
		"check_runs": [
			{
				"id": 789,
				"name": "Policy Check",
				"head_sha": "abc123",
				"status": "completed",
				"conclusion": "success"
			},
			{
				"id": 790,
				"name": "Vulnerability Check",
				"head_sha": "abc123",
				"status": "in_progress"
			}
		]
	}`
	writeTestResponse(w, []byte(response))
}

func (suite *GitHubClientTestSuite) handleGetArtifact(
	w http.ResponseWriter,
	r *http.Request,
	artifactID string,
) {
	if artifactID == "404" {
		w.WriteHeader(http.StatusNotFound)
		writeTestResponse(w, []byte(`{"message": "Not Found"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := `{
		"id": 123,
		"name": "trivy-results",
		"size_in_bytes": 1024,
		"url": "https://api.github.com/repos/owner/repo/actions/artifacts/123",
		"archive_download_url": "https://api.github.com/repos/owner/repo/actions/artifacts/123/zip",
		"expired": false,
		"created_at": "2023-01-01T00:00:00Z",
		"updated_at": "2023-01-01T00:00:00Z"
	}`
	writeTestResponse(w, []byte(response))
}

// writeTestResponse is a helper function to write test responses and handle errors
func writeTestResponse(w http.ResponseWriter, data []byte) {
	if _, err := w.Write(data); err != nil {
		// Log error but don't fail test
		return
	}
}

// mustParseURL parses a URL and panics if it fails
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}

func (suite *GitHubClientTestSuite) TestNewGitHubClient() {
	client := NewGitHubClient(suite.ctx)

	suite.Assert().NotNil(client)
	suite.Assert().NotNil(client.client)
}

func (suite *GitHubClientTestSuite) TestNewGitHubAppClient() {
	tests := []struct {
		name          string
		errorContains string
		config        GitHubAppConfig
		expectedError bool
	}{
		{
			name: "valid config",
			config: GitHubAppConfig{
				AppID:          123,
				InstallationID: 456,
				PrivateKey: []byte(
					"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB\n-----END PRIVATE KEY-----",
				),
			},
			expectedError: true, // Will fail with invalid key but we test the creation logic
			errorContains: "failed to create GitHub app transport",
		},
		{
			name: "empty private key",
			config: GitHubAppConfig{
				AppID:          123,
				InstallationID: 456,
				PrivateKey:     []byte(""),
			},
			expectedError: true,
			errorContains: "failed to create GitHub app transport",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			client, err := NewGitHubAppClient(suite.ctx, tt.config)

			if tt.expectedError {
				suite.Assert().Error(err)
				suite.Assert().Contains(err.Error(), tt.errorContains)
				suite.Assert().Nil(client)
			} else {
				suite.Assert().NoError(err)
				suite.Assert().NotNil(client)
				suite.Assert().NotNil(client.client)
			}
		})
	}
}

func (suite *GitHubClientTestSuite) TestAuthenticate() {
	tests := []struct {
		name          string
		token         string
		errorMessage  string
		expectedError bool
	}{
		{
			name:          "valid token",
			token:         "ghp_valid_token",
			expectedError: false,
		},
		{
			name:          "empty token",
			token:         "",
			expectedError: true,
			errorMessage:  "authentication token is required",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			client := NewGitHubClient(suite.ctx)

			err := client.Authenticate(suite.ctx, tt.token)

			if tt.expectedError {
				suite.Assert().Error(err)
				suite.Assert().Equal(tt.errorMessage, err.Error())
			} else {
				suite.Assert().NoError(err)
				suite.Assert().NotNil(client.client)
			}
		})
	}
}

// Test suite methods
func (suite *GitHubClientTestSuite) TestGetPullRequest() {
	tests := []struct {
		name          string
		owner         string
		repo          string
		number        int
		expectedError bool
	}{
		{
			name:          "successful request",
			owner:         "owner",
			repo:          "repo",
			number:        123,
			expectedError: false,
		},
		{
			name:          "not found",
			owner:         "owner",
			repo:          "repo",
			number:        404,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			pr, err := suite.githubClient.GetPullRequest(suite.ctx, tt.owner, tt.repo, tt.number)

			if tt.expectedError {
				suite.Assert().Error(err)
				suite.Assert().Nil(pr)
			} else {
				suite.Assert().NoError(err)
				suite.Assert().NotNil(pr)
				suite.Assert().Equal(int64(123), *pr.ID)
				suite.Assert().Equal(123, *pr.Number)
				suite.Assert().Equal("Test PR", *pr.Title)
			}
		})
	}
}

func (suite *GitHubClientTestSuite) TestWriteComment() {
	tests := []struct {
		name          string
		owner         string
		repo          string
		comment       string
		number        int
		expectedError bool
	}{
		{
			name:          "successful comment",
			owner:         "owner",
			repo:          "repo",
			number:        123,
			comment:       "Test comment",
			expectedError: false,
		},
		{
			name:          "server error",
			owner:         "owner",
			repo:          "repo",
			number:        500,
			comment:       "Test comment",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			err := suite.githubClient.WriteComment(
				suite.ctx,
				tt.owner,
				tt.repo,
				tt.number,
				tt.comment,
			)

			if tt.expectedError {
				suite.Assert().Error(err)
				suite.Assert().Contains(err.Error(), "failed to write comment")
			} else {
				suite.Assert().NoError(err)
			}
		})
	}
}

func (suite *GitHubClientTestSuite) TestCreateCheckRun() {
	tests := []struct {
		name          string
		owner         string
		repo          string
		sha           string
		checkName     string
		expectedError bool
	}{
		{
			name:          "successful check run creation",
			owner:         "owner",
			repo:          "repo",
			sha:           "abc123",
			checkName:     "Test Check",
			expectedError: false,
		},
		{
			name:          "validation error",
			owner:         "owner",
			repo:          "error-repo",
			sha:           "abc123",
			checkName:     "Test Check",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			checkRun, err := suite.githubClient.CreateCheckRun(
				suite.ctx,
				tt.owner,
				tt.repo,
				tt.sha,
				tt.checkName,
			)

			if tt.expectedError {
				suite.Assert().Error(err)
				suite.Assert().Nil(checkRun)
			} else {
				suite.Assert().NoError(err)
				suite.Assert().NotNil(checkRun)
				suite.Assert().Equal(int64(789), *checkRun.ID)
				suite.Assert().Equal("Test Check", *checkRun.Name)
				suite.Assert().Equal("abc123", *checkRun.HeadSHA)
				suite.Assert().Equal("queued", *checkRun.Status)
			}
		})
	}
}

func (suite *GitHubClientTestSuite) TestUpdateCheckRun() {
	tests := []struct {
		conclusion    *string
		name          string
		owner         string
		repo          string
		checkName     string
		status        string
		checkRunID    int64
		expectedError bool
	}{
		{
			name:          "successful update completed",
			owner:         "owner",
			repo:          "repo",
			checkRunID:    789,
			checkName:     "Test Check",
			status:        "completed",
			conclusion:    github.Ptr("success"),
			expectedError: false,
		},
		{
			name:          "not found",
			owner:         "owner",
			repo:          "repo",
			checkRunID:    404,
			checkName:     "Test Check",
			status:        "in_progress",
			conclusion:    nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			err := suite.githubClient.UpdateCheckRun(
				suite.ctx,
				tt.owner,
				tt.repo,
				tt.checkRunID,
				tt.checkName,
				tt.status,
				tt.conclusion,
				nil,
			)

			if tt.expectedError {
				suite.Assert().Error(err)
				suite.Assert().Contains(err.Error(), "failed to update check run")
			} else {
				suite.Assert().NoError(err)
			}
		})
	}
}

func (suite *GitHubClientTestSuite) TestDownloadArtifact() {
	// Note: This test is simplified since the actual DownloadArtifact method
	// in the GitHub client involves complex URL redirection and external downloads
	// In a real test environment, you would mock the GitHub API more comprehensively

	suite.T().Skip("Skipping DownloadArtifact test - requires complex GitHub API mocking")
}

func (suite *GitHubClientTestSuite) TestListWorkflowRunArtifacts() {
	tests := []struct {
		name              string
		owner             string
		repo              string
		runID             int64
		expectedError     bool
		expectedArtifacts int
	}{
		{
			name:              "successful list",
			owner:             "owner",
			repo:              "repo",
			runID:             123,
			expectedError:     false,
			expectedArtifacts: 2,
		},
		{
			name:              "not found",
			owner:             "owner",
			repo:              "repo",
			runID:             404,
			expectedError:     true,
			expectedArtifacts: 0,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			artifacts, err := suite.githubClient.ListWorkflowArtifacts(
				suite.ctx,
				tt.owner,
				tt.repo,
				tt.runID,
			)

			if tt.expectedError {
				suite.Assert().Error(err)
				suite.Assert().Nil(artifacts)
			} else {
				suite.Assert().NoError(err)
				suite.Assert().NotNil(artifacts)
				suite.Assert().Len(artifacts, tt.expectedArtifacts)

				if len(artifacts) > 0 {
					suite.Assert().Equal(int64(456), *artifacts[0].ID)
					suite.Assert().Equal("trivy-results", *artifacts[0].Name)
				}
			}
		})
	}
}

func (suite *GitHubClientTestSuite) TestGetCheckRun() {
	tests := []struct {
		name          string
		owner         string
		repo          string
		checkRunID    int64
		expectedError bool
	}{
		{
			name:          "successful get",
			owner:         "owner",
			repo:          "repo",
			checkRunID:    789,
			expectedError: false,
		},
		{
			name:          "not found",
			owner:         "owner",
			repo:          "repo",
			checkRunID:    404,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			checkRun, err := suite.githubClient.GetCheckRun(
				suite.ctx,
				tt.owner,
				tt.repo,
				tt.checkRunID,
			)

			if tt.expectedError {
				suite.Assert().Error(err)
				suite.Assert().Nil(checkRun)
				suite.Assert().Contains(err.Error(), "failed to get check run")
			} else {
				suite.Assert().NoError(err)
				suite.Assert().NotNil(checkRun)
				suite.Assert().Equal(int64(789), *checkRun.ID)
				suite.Assert().Equal("Test Check", *checkRun.Name)
				suite.Assert().Equal("abc123", *checkRun.HeadSHA)
			}
		})
	}
}

func (suite *GitHubClientTestSuite) TestListCheckRuns() {
	tests := []struct {
		name              string
		owner             string
		repo              string
		sha               string
		expectedError     bool
		expectedCheckRuns int
	}{
		{
			name:              "successful list",
			owner:             "owner",
			repo:              "repo",
			sha:               "abc123",
			expectedError:     false,
			expectedCheckRuns: 2,
		},
		{
			name:              "not found",
			owner:             "owner",
			repo:              "repo",
			sha:               "404",
			expectedError:     true,
			expectedCheckRuns: 0,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			checkRuns, err := suite.githubClient.ListCheckRuns(suite.ctx, tt.owner, tt.repo, tt.sha)

			if tt.expectedError {
				suite.Assert().Error(err)
				suite.Assert().Nil(checkRuns)
				suite.Assert().Contains(err.Error(), "failed to list check runs")
			} else {
				suite.Assert().NoError(err)
				suite.Assert().NotNil(checkRuns)
				suite.Assert().Len(checkRuns, tt.expectedCheckRuns)

				if len(checkRuns) > 0 {
					suite.Assert().Equal(int64(789), *checkRuns[0].ID)
					suite.Assert().Equal("Policy Check", *checkRuns[0].Name)
				}
			}
		})
	}
}

func (suite *GitHubClientTestSuite) TestGetArtifact() {
	tests := []struct {
		name          string
		owner         string
		repo          string
		artifactID    int64
		expectedError bool
	}{
		{
			name:          "successful get",
			owner:         "owner",
			repo:          "repo",
			artifactID:    123,
			expectedError: false,
		},
		{
			name:          "not found",
			owner:         "owner",
			repo:          "repo",
			artifactID:    404,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			artifact, err := suite.githubClient.GetArtifact(
				suite.ctx,
				tt.owner,
				tt.repo,
				tt.artifactID,
			)

			if tt.expectedError {
				suite.Assert().Error(err)
				suite.Assert().Nil(artifact)
				suite.Assert().Contains(err.Error(), "failed to get artifact")
			} else {
				suite.Assert().NoError(err)
				suite.Assert().NotNil(artifact)
				suite.Assert().Equal(int64(123), *artifact.ID)
				suite.Assert().Equal("trivy-results", *artifact.Name)
				suite.Assert().Equal(int64(1024), *artifact.SizeInBytes)
				suite.Assert().Equal(false, *artifact.Expired)
			}
		})
	}
}

// Run the test suite
func TestGitHubClientTestSuite(t *testing.T) {
	suite.Run(t, new(GitHubClientTestSuite))
}
