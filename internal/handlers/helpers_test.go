package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/go-playground/webhooks/v6/github"
	"github.com/stretchr/testify/assert"

	"github.com/terrpan/polly/internal/services"
)

func TestBuildLicenseComment(t *testing.T) {
	tests := []struct {
		name         string
		violations   []services.SBOMPolicyComponent
		conditionals []services.SBOMPolicyComponent
		expected     []string
	}{
		{
			name: "both violations and conditionals",
			violations: []services.SBOMPolicyComponent{
				{
					Name:            "violation-package",
					VersionInfo:     "1.0.0",
					LicenseDeclared: "GPL-3.0",
				},
			},
			conditionals: []services.SBOMPolicyComponent{
				{
					Name:             "conditional-package",
					VersionInfo:      "2.0.0",
					LicenseConcluded: "Apache-2.0",
				},
			},
			expected: []string{
				"❌ **License Violations Found - 1 packages**",
				"**Package:** `violation-package`@1.0.0",
				"**License Declared:** GPL-3.0",
				"ℹ️ **Conditionally Allowed Licenses Found - 1 packages require consideration**",
				"**Package:** `conditional-package`@2.0.0",
				"**License Concluded:** Apache-2.0",
			},
		},
		{
			name: "only violations",
			violations: []services.SBOMPolicyComponent{
				{
					Name:            "violation-only",
					LicenseDeclared: "GPL-2.0",
				},
			},
			conditionals: nil,
			expected: []string{
				"❌ **License Violations Found - 1 packages**",
				"**Package:** `violation-only`",
				"**License Declared:** GPL-2.0",
			},
		},
		{
			name:       "only conditionals",
			violations: nil,
			conditionals: []services.SBOMPolicyComponent{
				{
					Name:             "conditional-only",
					LicenseConcluded: "MIT",
				},
			},
			expected: []string{
				"ℹ️ **Conditionally Allowed Licenses Found - 1 packages require consideration**",
				"**Package:** `conditional-only`",
				"**License Concluded:** MIT",
			},
		},
		{
			name:         "empty lists",
			violations:   nil,
			conditionals: nil,
			expected:     []string{""}, // Should return empty string
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildLicenseComment(tt.violations, tt.conditionals)

			if tt.name == "empty lists" {
				assert.Equal(t, "", result)
			} else {
				for _, expected := range tt.expected {
					assert.Contains(t, result, expected)
				}
			}
		})
	}
}

func TestBuildLicenseViolationSection(t *testing.T) {
	violations := []services.SBOMPolicyComponent{
		{
			Name:            "test-package",
			VersionInfo:     "1.0.0",
			LicenseDeclared: "GPL-3.0",
			Supplier:        "Test Corp",
			SPDXID:          "SPDXRef-Package-test",
		},
		{
			Name:             "another-package",
			LicenseConcluded: "AGPL-3.0",
		},
	}

	result := buildLicenseViolationSection(violations)

	assert.Contains(t, result, "❌ **License Violations Found - 2 packages**")
	assert.Contains(t, result, "**Package:** `test-package`@1.0.0")
	assert.Contains(t, result, "**License Declared:** GPL-3.0")
	assert.Contains(t, result, "**Supplier:** Test Corp")
	assert.Contains(t, result, "**SPDX ID:** `SPDXRef-Package-test`")
	assert.Contains(t, result, "**Package:** `another-package`")
	assert.Contains(t, result, "**License Concluded:** AGPL-3.0")
	assert.Contains(t, result, "<details>")
	assert.Contains(t, result, "Click to view license violations")
}

func TestBuildLicenseConditionalSection(t *testing.T) {
	conditionals := []services.SBOMPolicyComponent{
		{
			Name:             "conditional-package",
			VersionInfo:      "2.0.0",
			LicenseConcluded: "Apache-2.0",
		},
	}

	result := buildLicenseConditionalSection(conditionals)

	assert.Contains(
		t,
		result,
		"ℹ️ **Conditionally Allowed Licenses Found - 1 packages require consideration**",
	)
	assert.Contains(t, result, "**Package:** `conditional-package`@2.0.0")
	assert.Contains(t, result, "**License Concluded:** Apache-2.0")
	assert.Contains(t, result, "<details>")
	assert.Contains(t, result, "Click to view conditionally allowed licenses")
}

func TestBuildComponentComment(t *testing.T) {
	tests := []struct {
		name        string
		component   services.SBOMPolicyComponent
		expected    []string
		notExpected []string
	}{
		{
			name: "full component info",
			component: services.SBOMPolicyComponent{
				Name:            "full-package",
				VersionInfo:     "1.0.0",
				LicenseDeclared: "MIT",
				Supplier:        "Example Corp",
				SPDXID:          "SPDXRef-Package-full",
			},
			expected: []string{
				"**Package:** `full-package`@1.0.0",
				"**License Declared:** MIT",
				"**Supplier:** Example Corp",
				"**SPDX ID:** `SPDXRef-Package-full`",
			},
		},
		{
			name: "minimal component info",
			component: services.SBOMPolicyComponent{
				Name: "minimal-package",
			},
			expected: []string{
				"**Package:** `minimal-package`",
			},
			notExpected: []string{
				"@",
				"**License",
				"**Supplier:",
				"**SPDX ID:",
			},
		},
		{
			name: "component with concluded license (no declared)",
			component: services.SBOMPolicyComponent{
				Name:             "concluded-package",
				VersionInfo:      "2.0.0",
				LicenseConcluded: "Apache-2.0",
			},
			expected: []string{
				"**Package:** `concluded-package`@2.0.0",
				"**License Concluded:** Apache-2.0",
			},
			notExpected: []string{
				"**License Declared:",
			},
		},
		{
			name: "component with both declared and concluded (declared takes precedence)",
			component: services.SBOMPolicyComponent{
				Name:             "both-licenses",
				LicenseDeclared:  "MIT",
				LicenseConcluded: "Apache-2.0",
			},
			expected: []string{
				"**Package:** `both-licenses`",
				"**License Declared:** MIT",
			},
			notExpected: []string{
				"**License Concluded:",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildComponentComment(tt.component)

			for _, expected := range tt.expected {
				assert.Contains(t, result, expected)
			}

			for _, notExpected := range tt.notExpected {
				assert.NotContains(t, result, notExpected)
			}
		})
	}
}

func TestBuildVulnerabilityCheckResult(t *testing.T) {
	tests := []struct {
		name               string
		result             PolicyProcessingResult
		payloadCount       int
		expectedConclusion services.CheckRunConclusion
		expectedTitle      string
	}{
		{
			name:               "successful result",
			result:             PolicyProcessingResult{AllPassed: true},
			payloadCount:       2,
			expectedConclusion: services.ConclusionSuccess,
			expectedTitle:      "Vulnerability Check - Passed",
		},
		{
			name: "failed result",
			result: PolicyProcessingResult{
				AllPassed:      false,
				FailureDetails: []string{"violation 1", "violation 2"},
			},
			payloadCount:       2,
			expectedConclusion: services.ConclusionFailure,
			expectedTitle:      "Vulnerability Check - Failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conclusion, checkResult := buildVulnerabilityCheckResult(tt.result, tt.payloadCount)

			assert.Equal(t, tt.expectedConclusion, conclusion)
			assert.Equal(t, tt.expectedTitle, checkResult.Title)
			assert.Contains(t, checkResult.Summary, fmt.Sprintf("%d", tt.payloadCount))
		})
	}
}

// TracingHelperTestSuite provides tests for the TracingHelper

func TestBaseWebhookHandler_storeCheckRunID(t *testing.T) {
	tests := []struct {
		name       string
		storeError error
		checkType  string
		checkRunID int64
	}{
		{
			name:       "successful storage",
			storeError: nil,
			checkType:  "vulnerability",
			checkRunID: 12345,
		},
		{
			name:       "storage failure",
			storeError: errors.New("storage failed"),
			checkType:  "license",
			checkRunID: 67890,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simple logger
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))

			// Create handler with minimal dependencies
			handler := &BaseWebhookHandler{
				logger: logger,
			}

			ctx := context.Background()
			owner, repo, sha := "testowner", "testrepo", "abc123"

			// Create a simple store function that returns the test error
			storeFunc := func(ctx context.Context, owner, repo, sha string, checkRunID int64) error {
				return tt.storeError
			}

			// Execute the function - it should not panic regardless of the store function result
			handler.storeCheckRunID(ctx, owner, repo, sha, tt.checkRunID, tt.checkType, storeFunc)

			// The function doesn't return anything, so we just verify it doesn't panic
			// In a real scenario, the error would be logged, but we're testing the function behavior
		})
	}
}

func TestBaseWebhookHandler_storeCheckRunIDWithError(t *testing.T) {
	tests := []struct {
		name        string
		storeError  error
		expectError bool
		checkType   string
		checkRunID  int64
	}{
		{
			name:        "successful storage",
			storeError:  nil,
			expectError: false,
			checkType:   "vulnerability",
			checkRunID:  12345,
		},
		{
			name:        "storage failure",
			storeError:  errors.New("storage failed"),
			expectError: true,
			checkType:   "license",
			checkRunID:  67890,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a simple logger
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				Level: slog.LevelDebug,
			}))

			// Create handler with minimal dependencies
			handler := &BaseWebhookHandler{
				logger: logger,
			}

			ctx := context.Background()
			owner, repo, sha := "testowner", "testrepo", "abc123"

			// Create a simple store function that returns the test error
			storeFunc := func(ctx context.Context, owner, repo, sha string, checkRunID int64) error {
				return tt.storeError
			}

			// Execute the function
			err := handler.storeCheckRunIDWithError(ctx, owner, repo, sha, tt.checkRunID, tt.checkType, storeFunc)

			// Verify the error handling behavior
			if tt.expectError {
				assert.Error(t, err)
				assert.Equal(t, tt.storeError, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestGetEventInfo(t *testing.T) {
	t.Run("PullRequestPayload", func(t *testing.T) {
		payload := github.PullRequestPayload{}
		payload.Repository.Name = "testrepo"
		payload.Repository.Owner.Login = "testowner"
		payload.PullRequest.Head.Sha = "abc123def"
		payload.PullRequest.ID = 12345

		owner, repo, sha, eventID := getEventInfo(payload)

		assert.Equal(t, "testowner", owner)
		assert.Equal(t, "testrepo", repo)
		assert.Equal(t, "abc123def", sha)
		assert.Equal(t, int64(12345), eventID)
	})

	t.Run("CheckRunPayload", func(t *testing.T) {
		payload := github.CheckRunPayload{}
		payload.Repository.Name = "checkrepo"
		payload.Repository.Owner.Login = "checkowner"
		payload.CheckRun.HeadSHA = "def456ghi"
		payload.CheckRun.ID = 67890

		owner, repo, sha, eventID := getEventInfo(payload)

		assert.Equal(t, "checkowner", owner)
		assert.Equal(t, "checkrepo", repo)
		assert.Equal(t, "def456ghi", sha)
		assert.Equal(t, int64(67890), eventID)
	})

	t.Run("WorkflowRunPayload", func(t *testing.T) {
		payload := github.WorkflowRunPayload{}
		payload.Repository.Name = "workflowrepo"
		payload.Repository.Owner.Login = "workflowowner"
		payload.WorkflowRun.HeadSha = "ghi789jkl"
		payload.WorkflowRun.ID = 99999

		owner, repo, sha, eventID := getEventInfo(payload)

		assert.Equal(t, "workflowowner", owner)
		assert.Equal(t, "workflowrepo", repo)
		assert.Equal(t, "ghi789jkl", sha)
		assert.Equal(t, int64(99999), eventID)
	})
}
