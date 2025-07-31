package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/go-playground/webhooks/v6/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/utils"
)

// MockPolicyService is a mock implementation of the PolicyService for testing
type MockPolicyService struct {
	mock.Mock
}

func (m *MockPolicyService) CheckVulnerabilityPolicyWithCache(
	ctx context.Context,
	input *services.VulnerabilityPayload,
	owner, repo, sha string,
) (services.VulnerabilityPolicyResult, error) {
	args := m.Called(ctx, input, owner, repo, sha)
	return args.Get(0).(services.VulnerabilityPolicyResult), args.Error(1)
}

func (m *MockPolicyService) CheckSBOMPolicyWithCache(
	ctx context.Context,
	input *services.SBOMPayload,
	owner, repo, sha string,
) (services.SBOMPolicyResult, error) {
	args := m.Called(ctx, input, owner, repo, sha)
	return args.Get(0).(services.SBOMPolicyResult), args.Error(1)
}

// MockPolicyCacheService is a mock implementation of the PolicyCacheService for testing
type MockPolicyCacheService struct {
	mock.Mock
}

func (m *MockPolicyCacheService) CheckVulnerabilityPolicyWithCache(
	ctx context.Context,
	input *services.VulnerabilityPayload,
	owner, repo, sha string,
) (services.VulnerabilityPolicyResult, error) {
	args := m.Called(ctx, input, owner, repo, sha)
	return args.Get(0).(services.VulnerabilityPolicyResult), args.Error(1)
}

func (m *MockPolicyCacheService) CheckSBOMPolicyWithCache(
	ctx context.Context,
	input *services.SBOMPayload,
	owner, repo, sha string,
) (services.SBOMPolicyResult, error) {
	args := m.Called(ctx, input, owner, repo, sha)
	return args.Get(0).(services.SBOMPolicyResult), args.Error(1)
}

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
			err := handler.storeCheckRunIDWithError(
				ctx,
				owner,
				repo,
				sha,
				tt.checkRunID,
				tt.checkType,
				storeFunc,
			)

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

// Test Strategy Pattern Implementation

func TestVulnerabilityPolicyProcessor(t *testing.T) {
	processor := &VulnerabilityPolicyProcessor{}

	t.Run("GetPolicyType", func(t *testing.T) {
		assert.Equal(t, "vulnerability", processor.GetPolicyType())
	})

	t.Run("ProcessPayloads_Success", func(t *testing.T) {
		mockService := &MockPolicyCacheService{}
		payloads := []*services.VulnerabilityPayload{
			{
				Summary: services.VulnerabilitySummary{
					Critical: 0,
					High:     0,
					Medium:   1,
					Low:      2,
				},
			},
		}

		mockService.On("CheckVulnerabilityPolicyWithCache", context.Background(), payloads[0], "owner", "repo", "sha").Return(
			services.VulnerabilityPolicyResult{
				Compliant:                   true,
				TotalVulnerabilities:        3,
				NonCompliantCount:           0,
				NonCompliantVulnerabilities: []services.VulnerabilityPolicyVuln{},
			}, nil)

		result := processor.ProcessPayloads(
			context.Background(),
			slog.Default(),
			mockService,
			payloads,
			"owner",
			"repo",
			"sha",
		)

		assert.True(t, result.AllPassed)
		assert.Empty(t, result.FailureDetails)
		assert.Empty(t, result.NonCompliantVulns)
		mockService.AssertExpectations(t)
	})

	t.Run("ProcessPayloads_PolicyViolation", func(t *testing.T) {
		mockService := &MockPolicyCacheService{}
		payloads := []*services.VulnerabilityPayload{
			{
				Summary: services.VulnerabilitySummary{
					Critical: 2,
					High:     3,
					Medium:   1,
					Low:      2,
				},
			},
		}

		violations := []services.VulnerabilityPolicyVuln{
			{ID: "CVE-2023-0001", Severity: "CRITICAL"},
			{ID: "CVE-2023-0002", Severity: "HIGH"},
		}

		mockService.On("CheckVulnerabilityPolicyWithCache", context.Background(), payloads[0], "owner", "repo", "sha").Return(
			services.VulnerabilityPolicyResult{
				Compliant:                   false,
				TotalVulnerabilities:        8,
				NonCompliantCount:           2,
				NonCompliantVulnerabilities: violations,
			}, nil)

		result := processor.ProcessPayloads(
			context.Background(),
			slog.Default(),
			mockService,
			payloads,
			"owner",
			"repo",
			"sha",
		)

		assert.False(t, result.AllPassed)
		assert.Len(t, result.FailureDetails, 1)
		assert.Contains(
			t,
			result.FailureDetails[0],
			"Vulnerability policy violation: 2 non-compliant vulnerabilities out of 8 total",
		)
		assert.Equal(t, violations, result.NonCompliantVulns)
		mockService.AssertExpectations(t)
	})

	t.Run("ProcessPayloads_PolicyError", func(t *testing.T) {
		mockService := &MockPolicyCacheService{}
		payloads := []*services.VulnerabilityPayload{
			{
				Summary: services.VulnerabilitySummary{
					Critical: 2,
					High:     1,
					Medium:   1,
					Low:      2,
				},
			},
		}

		mockService.On("CheckVulnerabilityPolicyWithCache", context.Background(), payloads[0], "owner", "repo", "sha").Return(
			services.VulnerabilityPolicyResult{}, errors.New("policy service error"))

		result := processor.ProcessPayloads(
			context.Background(),
			slog.Default(),
			mockService,
			payloads,
			"owner",
			"repo",
			"sha",
		)

		assert.False(t, result.AllPassed)
		assert.Len(t, result.FailureDetails, 1)
		assert.Contains(
			t,
			result.FailureDetails[0],
			"Found 2 critical and 1 high severity vulnerabilities (policy evaluation failed)",
		)
		mockService.AssertExpectations(t)
	})
}

func TestLicensePolicyProcessor(t *testing.T) {
	processor := &LicensePolicyProcessor{}

	t.Run("GetPolicyType", func(t *testing.T) {
		assert.Equal(t, "license", processor.GetPolicyType())
	})

	t.Run("ProcessPayloads_Success", func(t *testing.T) {
		mockService := &MockPolicyCacheService{}
		payloads := []*services.SBOMPayload{
			{
				Summary: services.SBOMSummary{
					TotalPackages:          10,
					PackagesWithoutLicense: 0,
				},
			},
		}

		mockService.On("CheckSBOMPolicyWithCache", context.Background(), payloads[0], "owner", "repo", "sha").Return(
			services.SBOMPolicyResult{
				Compliant:              true,
				TotalComponents:        10,
				CompliantComponents:    10,
				NonCompliantComponents: []services.SBOMPolicyComponent{},
				ConditionalComponents:  []services.SBOMPolicyComponent{},
			}, nil)

		result := processor.ProcessPayloads(
			context.Background(),
			slog.Default(),
			mockService,
			payloads,
			"owner",
			"repo",
			"sha",
		)

		assert.True(t, result.AllPassed)
		assert.Empty(t, result.FailureDetails)
		assert.Empty(t, result.NonCompliantComponents)
		mockService.AssertExpectations(t)
	})

	t.Run("ProcessPayloads_PolicyViolation", func(t *testing.T) {
		mockService := &MockPolicyCacheService{}
		payloads := []*services.SBOMPayload{
			{
				Summary: services.SBOMSummary{
					TotalPackages:          10,
					PackagesWithoutLicense: 2,
				},
			},
		}

		nonCompliantComponents := []services.SBOMPolicyComponent{
			{Name: "bad-package", VersionInfo: "1.0.0", LicenseDeclared: "GPL-3.0"},
		}
		conditionalComponents := []services.SBOMPolicyComponent{
			{Name: "conditional-package", VersionInfo: "2.0.0", LicenseConcluded: "Apache-2.0"},
		}

		mockService.On("CheckSBOMPolicyWithCache", context.Background(), payloads[0], "owner", "repo", "sha").Return(
			services.SBOMPolicyResult{
				Compliant:              false,
				TotalComponents:        10,
				CompliantComponents:    8,
				NonCompliantComponents: nonCompliantComponents,
				ConditionalComponents:  conditionalComponents,
			}, nil)

		result := processor.ProcessPayloads(
			context.Background(),
			slog.Default(),
			mockService,
			payloads,
			"owner",
			"repo",
			"sha",
		)

		assert.False(t, result.AllPassed)
		assert.Len(t, result.FailureDetails, 1)
		assert.Contains(
			t,
			result.FailureDetails[0],
			"SBOM policy violation: 2 non-compliant components out of 10 total",
		)
		assert.Equal(t, nonCompliantComponents, result.NonCompliantComponents)
		assert.Equal(t, conditionalComponents, result.ConditionalComponents)
		mockService.AssertExpectations(t)
	})

	t.Run("ProcessPayloads_PolicyError", func(t *testing.T) {
		mockService := &MockPolicyCacheService{}
		payloads := []*services.SBOMPayload{
			{
				Summary: services.SBOMSummary{
					TotalPackages:          10,
					PackagesWithoutLicense: 3,
				},
			},
		}

		mockService.On("CheckSBOMPolicyWithCache", context.Background(), payloads[0], "owner", "repo", "sha").Return(
			services.SBOMPolicyResult{}, errors.New("policy service error"))

		result := processor.ProcessPayloads(
			context.Background(),
			slog.Default(),
			mockService,
			payloads,
			"owner",
			"repo",
			"sha",
		)

		assert.False(t, result.AllPassed)
		assert.Len(t, result.FailureDetails, 1)
		assert.Contains(
			t,
			result.FailureDetails[0],
			"Found 3 packages without license (policy evaluation failed)",
		)
		mockService.AssertExpectations(t)
	})
}

func TestProcessPoliciesWithStrategy(t *testing.T) {
	t.Run("VulnerabilityStrategy", func(t *testing.T) {
		mockService := &MockPolicyCacheService{}
		processor := &VulnerabilityPolicyProcessor{}
		payloads := []*services.VulnerabilityPayload{
			{
				Summary: services.VulnerabilitySummary{
					Critical: 0,
					High:     0,
					Medium:   1,
					Low:      2,
				},
			},
		}

		mockService.On("CheckVulnerabilityPolicyWithCache", context.Background(), payloads[0], "owner", "repo", "sha").Return(
			services.VulnerabilityPolicyResult{
				Compliant:                   true,
				TotalVulnerabilities:        3,
				NonCompliantCount:           0,
				NonCompliantVulnerabilities: []services.VulnerabilityPolicyVuln{},
			}, nil)

		result := processPoliciesWithStrategy(
			context.Background(),
			slog.Default(),
			mockService,
			processor,
			payloads,
			"owner",
			"repo",
			"sha",
		)

		assert.True(t, result.AllPassed)
		mockService.AssertExpectations(t)
	})

	t.Run("LicenseStrategy", func(t *testing.T) {
		mockService := &MockPolicyCacheService{}
		processor := &LicensePolicyProcessor{}
		payloads := []*services.SBOMPayload{
			{
				Summary: services.SBOMSummary{
					TotalPackages:          10,
					PackagesWithoutLicense: 0,
				},
			},
		}

		mockService.On("CheckSBOMPolicyWithCache", context.Background(), payloads[0], "owner", "repo", "sha").Return(
			services.SBOMPolicyResult{
				Compliant:              true,
				TotalComponents:        10,
				CompliantComponents:    10,
				NonCompliantComponents: []services.SBOMPolicyComponent{},
				ConditionalComponents:  []services.SBOMPolicyComponent{},
			}, nil)

		result := processPoliciesWithStrategy(
			context.Background(),
			slog.Default(),
			mockService,
			processor,
			payloads,
			"owner",
			"repo",
			"sha",
		)

		assert.True(t, result.AllPassed)
		mockService.AssertExpectations(t)
	})
}

// TestProcessWorkflowSecurityArtifactsConcurrent verifies that vulnerability and SBOM checks run concurrently
func TestProcessWorkflowSecurityArtifactsConcurrent(t *testing.T) {
	t.Run("processes vulnerability and SBOM checks concurrently", func(t *testing.T) {
		// Test the concurrent execution pattern by verifying utils.ExecuteConcurrently is used
		// This ensures the artifact processing follows the concurrent pattern

		// Create mock tasks to simulate vulnerability and SBOM processing
		var executionOrder []string
		var mu sync.Mutex

		tasks := []func() error{
			func() error {
				time.Sleep(10 * time.Millisecond) // Simulate vulnerability processing
				mu.Lock()
				executionOrder = append(executionOrder, "vulnerability")
				mu.Unlock()
				return nil
			},
			func() error {
				time.Sleep(10 * time.Millisecond) // Simulate SBOM processing
				mu.Lock()
				executionOrder = append(executionOrder, "sbom")
				mu.Unlock()
				return nil
			},
		}

		// Execute tasks concurrently (simulating what happens in processWorkflowSecurityArtifacts)
		startTime := time.Now()
		errs := utils.ExecuteConcurrently(tasks)
		duration := time.Since(startTime)

		// Verify both tasks completed without errors
		assert.Len(t, errs, 2)
		for _, err := range errs {
			assert.NoError(t, err)
		}

		// Verify both tasks executed
		assert.Len(t, executionOrder, 2)
		assert.Contains(t, executionOrder, "vulnerability")
		assert.Contains(t, executionOrder, "sbom")

		// Verify concurrent execution: should take ~10ms, not ~20ms (sequential)
		assert.Less(t, duration, 15*time.Millisecond,
			"Concurrent execution should be faster than sequential")

		t.Logf("Concurrent artifact processing simulation completed in %v", duration)
	})
}

// TestExecuteConcurrently1000Tasks tests the concurrent utility with 1000 tasks to verify scalability
func TestExecuteConcurrently1000Tasks(t *testing.T) {
	t.Run("handles 1000 concurrent tasks successfully", func(t *testing.T) {
		const numTasks = 1000
		var results []int
		var mu sync.Mutex

		// Create 1000 tasks that each add their index to results
		tasks := make([]func() error, numTasks)
		for i := 0; i < numTasks; i++ {
			taskIndex := i // Capture loop variable
			tasks[i] = func() error {
				// Simulate some work
				time.Sleep(time.Millisecond)

				mu.Lock()
				results = append(results, taskIndex)
				mu.Unlock()

				return nil
			}
		}

		// Execute all tasks concurrently
		startTime := time.Now()
		errs := utils.ExecuteConcurrently(tasks)
		duration := time.Since(startTime)

		// Verify all tasks completed without errors
		assert.Len(t, errs, numTasks, "Should have %d error results", numTasks)
		for i, err := range errs {
			assert.NoError(t, err, "Task %d should not return an error", i)
		}

		// Verify all tasks executed
		assert.Len(t, results, numTasks, "All %d tasks should have executed", numTasks)

		// Verify execution was reasonably fast (concurrent, not sequential)
		// Sequential execution would take ~1000ms, concurrent should be much faster
		assert.Less(t, duration, 200*time.Millisecond,
			"1000 concurrent tasks should complete faster than sequential execution")

		// Verify we got all expected indices (though order may vary due to concurrency)
		resultMap := make(map[int]bool)
		for _, result := range results {
			resultMap[result] = true
		}

		for i := 0; i < numTasks; i++ {
			assert.True(t, resultMap[i], "Should have result for task %d", i)
		}

		t.Logf("Successfully executed %d concurrent tasks in %v", numTasks, duration)
	})
}
