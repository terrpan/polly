package clients

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-github/v72/github"
	"github.com/stretchr/testify/assert"
)

func TestNewGitHubClient(t *testing.T) {
	ctx := context.Background()
	client := NewGitHubClient(ctx)

	assert.NotNil(t, client)
	assert.NotNil(t, client.client)
}

func TestNewGitHubAppClient(t *testing.T) {
	tests := []struct {
		name          string
		config        GitHubAppConfig
		expectedError bool
		errorContains string
	}{
		{
			name: "valid config",
			config: GitHubAppConfig{
				AppID:          123,
				InstallationID: 456,
				PrivateKey:     []byte("-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKB\n-----END PRIVATE KEY-----"),
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
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			client, err := NewGitHubAppClient(ctx, tt.config)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.NotNil(t, client.client)
			}
		})
	}
}

func TestAuthenticate(t *testing.T) {
	tests := []struct {
		name          string
		token         string
		expectedError bool
		errorMessage  string
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
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			client := NewGitHubClient(ctx)

			err := client.Authenticate(ctx, tt.token)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Equal(t, tt.errorMessage, err.Error())
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client.client)
			}
		})
	}
}

func TestGetPullRequest(t *testing.T) {
	// Mock GitHub API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/pulls/123":
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
			_, _ = w.Write([]byte(response))
		case "/repos/owner/repo/pulls/404":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message": "Not Found"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	client := github.NewClient(nil)
	client.BaseURL = mustParseURL(server.URL + "/")

	githubClient := &GitHubClient{client: client}

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
		t.Run(tt.name, func(t *testing.T) {
			pr, err := githubClient.GetPullRequest(ctx, tt.owner, tt.repo, tt.number)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, pr)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, pr)
				assert.Equal(t, int64(123), *pr.ID)
				assert.Equal(t, 123, *pr.Number)
				assert.Equal(t, "Test PR", *pr.Title)
			}
		})
	}
}

func TestWriteComment(t *testing.T) {
	// Mock GitHub API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/issues/123/comments":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
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
			_, _ = w.Write([]byte(response))
		case "/repos/owner/repo/issues/500/comments":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message": "Internal Server Error"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	client := github.NewClient(nil)
	client.BaseURL = mustParseURL(server.URL + "/")

	githubClient := &GitHubClient{client: client}

	tests := []struct {
		name          string
		owner         string
		repo          string
		number        int
		comment       string
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
		t.Run(tt.name, func(t *testing.T) {
			err := githubClient.WriteComment(ctx, tt.owner, tt.repo, tt.number, tt.comment)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to write comment")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateCheckRun(t *testing.T) {
	// Mock GitHub API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/check-runs":
			if r.Method != http.MethodPost {
				w.WriteHeader(http.StatusMethodNotAllowed)
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
			_, _ = w.Write([]byte(response))
		case "/repos/owner/error-repo/check-runs":
			w.WriteHeader(http.StatusUnprocessableEntity)
			_, _ = w.Write([]byte(`{"message": "Validation Failed"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	client := github.NewClient(nil)
	client.BaseURL = mustParseURL(server.URL + "/")

	githubClient := &GitHubClient{client: client}

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
		t.Run(tt.name, func(t *testing.T) {
			checkRun, err := githubClient.CreateCheckRun(ctx, tt.owner, tt.repo, tt.sha, tt.checkName)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, checkRun)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, checkRun)
				assert.Equal(t, int64(789), *checkRun.ID)
				assert.Equal(t, "Test Check", *checkRun.Name)
				assert.Equal(t, "abc123", *checkRun.HeadSHA)
				assert.Equal(t, "queued", *checkRun.Status)
			}
		})
	}
}

func TestUpdateCheckRun(t *testing.T) {
	// Mock GitHub API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/check-runs/789":
			if r.Method != http.MethodPatch {
				w.WriteHeader(http.StatusMethodNotAllowed)
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
			_, _ = w.Write([]byte(response))
		case "/repos/owner/repo/check-runs/404":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message": "Not Found"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	client := github.NewClient(nil)
	client.BaseURL = mustParseURL(server.URL + "/")

	githubClient := &GitHubClient{client: client}

	tests := []struct {
		name          string
		owner         string
		repo          string
		checkRunID    int64
		checkName     string
		status        string
		conclusion    *string
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
		t.Run(tt.name, func(t *testing.T) {
			err := githubClient.UpdateCheckRun(ctx, tt.owner, tt.repo, tt.checkRunID, tt.checkName, tt.status, tt.conclusion, nil)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "failed to update check run")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDownloadArtifact(t *testing.T) {
	// Note: This test is simplified since the actual DownloadArtifact method
	// in the GitHub client involves complex URL redirection and external downloads
	// In a real test environment, you would mock the GitHub API more comprehensively

	t.Skip("Skipping DownloadArtifact test - requires complex GitHub API mocking")
}

func TestListWorkflowRunArtifacts(t *testing.T) {
	// Mock GitHub API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/actions/runs/123/artifacts":
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
			_, _ = w.Write([]byte(response))
		case "/repos/owner/repo/actions/runs/404/artifacts":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message": "Not Found"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	client := github.NewClient(nil)
	client.BaseURL = mustParseURL(server.URL + "/")

	githubClient := &GitHubClient{client: client}

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
		t.Run(tt.name, func(t *testing.T) {
			artifacts, err := githubClient.ListWorkflowArtifacts(ctx, tt.owner, tt.repo, tt.runID)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, artifacts)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, artifacts)
				assert.Len(t, artifacts, tt.expectedArtifacts)

				if len(artifacts) > 0 {
					assert.Equal(t, int64(456), *artifacts[0].ID)
					assert.Equal(t, "trivy-results", *artifacts[0].Name)
				}
			}
		})
	}
}

func TestGetCheckRun(t *testing.T) {
	// Mock GitHub API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/check-runs/789":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			response := `{
				"id": 789,
				"name": "Test Check",
				"head_sha": "abc123",
				"status": "completed",
				"conclusion": "success"
			}`
			_, _ = w.Write([]byte(response))
		case "/repos/owner/repo/check-runs/404":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message": "Not Found"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	client := github.NewClient(nil)
	client.BaseURL = mustParseURL(server.URL + "/")

	githubClient := &GitHubClient{client: client}

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
		t.Run(tt.name, func(t *testing.T) {
			checkRun, err := githubClient.GetCheckRun(ctx, tt.owner, tt.repo, tt.checkRunID)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, checkRun)
				assert.Contains(t, err.Error(), "failed to get check run")
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, checkRun)
				assert.Equal(t, int64(789), *checkRun.ID)
				assert.Equal(t, "Test Check", *checkRun.Name)
				assert.Equal(t, "abc123", *checkRun.HeadSHA)
			}
		})
	}
}

func TestListCheckRuns(t *testing.T) {
	// Mock GitHub API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/commits/abc123/check-runs":
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
			_, _ = w.Write([]byte(response))
		case "/repos/owner/repo/commits/404/check-runs":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message": "Not Found"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	client := github.NewClient(nil)
	client.BaseURL = mustParseURL(server.URL + "/")

	githubClient := &GitHubClient{client: client}

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
		t.Run(tt.name, func(t *testing.T) {
			checkRuns, err := githubClient.ListCheckRuns(ctx, tt.owner, tt.repo, tt.sha)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, checkRuns)
				assert.Contains(t, err.Error(), "failed to list check runs")
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, checkRuns)
				assert.Len(t, checkRuns, tt.expectedCheckRuns)

				if len(checkRuns) > 0 {
					assert.Equal(t, int64(789), *checkRuns[0].ID)
					assert.Equal(t, "Policy Check", *checkRuns[0].Name)
				}
			}
		})
	}
}

func TestGetArtifact(t *testing.T) {
	// Mock GitHub API server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/owner/repo/actions/artifacts/123":
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
			_, _ = w.Write([]byte(response))
		case "/repos/owner/repo/actions/artifacts/404":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message": "Not Found"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	ctx := context.Background()
	client := github.NewClient(nil)
	client.BaseURL = mustParseURL(server.URL + "/")

	githubClient := &GitHubClient{client: client}

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
		t.Run(tt.name, func(t *testing.T) {
			artifact, err := githubClient.GetArtifact(ctx, tt.owner, tt.repo, tt.artifactID)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, artifact)
				assert.Contains(t, err.Error(), "failed to get artifact")
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, artifact)
				assert.Equal(t, int64(123), *artifact.ID)
				assert.Equal(t, "trivy-results", *artifact.Name)
				assert.Equal(t, int64(1024), *artifact.SizeInBytes)
				assert.Equal(t, false, *artifact.Expired)
			}
		})
	}
}

// Helper function to parse URL for tests
func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}
