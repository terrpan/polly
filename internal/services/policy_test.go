package services

import (
	"context"
	"testing"
	"time"

	"log/slog"
	"os"

	"github.com/stretchr/testify/assert"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/telemetry"
)

func createTestPolicyService() (*PolicyService, *slog.Logger) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	telHelper := telemetry.NewTelemetryHelper("test/policy")

	// Create with nil evaluators first, then add standard evaluators
	service := NewPolicyService(opaClient, logger, telHelper, nil)
	evaluators := NewStandardEvaluators(service)
	return NewPolicyService(opaClient, logger, telHelper, evaluators), logger
}

func TestNewPolicyService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	telHelper := telemetry.NewTelemetryHelper("test/policy")

	// Test creating with no evaluators
	policyService := NewPolicyService(opaClient, logger, telHelper, nil)

	assert.NotNil(t, policyService)
	assert.Equal(t, opaClient, policyService.opaClient)
	assert.Equal(t, logger, policyService.logger)
	assert.Equal(t, telHelper, policyService.telemetry)
	assert.Empty(t, policyService.evaluators)

	// Test creating with standard evaluators
	service := NewPolicyService(opaClient, logger, telHelper, nil)
	evaluators := NewStandardEvaluators(service)
	serviceWithEvaluators := NewPolicyService(opaClient, logger, telHelper, evaluators)

	assert.NotNil(t, serviceWithEvaluators)
	assert.Len(t, serviceWithEvaluators.evaluators, 2)
	assert.Contains(t, serviceWithEvaluators.evaluators, "vulnerability")
	assert.Contains(t, serviceWithEvaluators.evaluators, "sbom")
}

func TestPolicyService_VulnerabilityPolicyResult_Structure(t *testing.T) {
	result := VulnerabilityPolicyResult{
		Compliant:            true,
		TotalVulnerabilities: 5,
		NonCompliantCount:    2,
		NonCompliantVulnerabilities: []VulnerabilityPolicyVuln{
			{
				ID:       "CVE-2021-1234",
				Package:  "test-package",
				Version:  "1.0.0",
				Severity: "HIGH",
				Score:    7.5,
			},
		},
	}

	assert.True(t, result.Compliant)
	assert.Equal(t, 5, result.TotalVulnerabilities)
	assert.Equal(t, 2, result.NonCompliantCount)
	assert.Len(t, result.NonCompliantVulnerabilities, 1)
	assert.Equal(t, "CVE-2021-1234", result.NonCompliantVulnerabilities[0].ID)
}

func TestPolicyService_SBOMPolicyResult_Structure(t *testing.T) {
	result := SBOMPolicyResult{
		Compliant:            true,
		TotalComponents:      10,
		CompliantComponents:  8,
		NonCompliantLicenses: []string{"GPL-2.0-only"},
		NonCompliantComponents: []SBOMPolicyComponent{
			{
				Name:             "test-component",
				SPDXID:           "SPDXRef-test-component",
				VersionInfo:      "1.0.0",
				LicenseConcluded: "GPL-2.0-only",
			},
		},
		ConditionalComponents: []SBOMPolicyComponent{
			{
				Name:             "conditional-component",
				SPDXID:           "SPDXRef-conditional-component",
				VersionInfo:      "1.0.0",
				LicenseConcluded: "MIT",
			},
		},
		AllowedLicenses: []string{"MIT", "Apache-2.0"},
	}

	assert.True(t, result.Compliant)
	assert.Equal(t, 10, result.TotalComponents)
	assert.Equal(t, 8, result.CompliantComponents)
	assert.Len(t, result.NonCompliantLicenses, 1)
	assert.Equal(t, "GPL-2.0-only", result.NonCompliantLicenses[0])
	assert.Len(t, result.AllowedLicenses, 2)
	assert.Contains(t, result.AllowedLicenses, "MIT")
	assert.Contains(t, result.AllowedLicenses, "Apache-2.0")
	assert.Len(t, result.NonCompliantComponents, 1)
	assert.Equal(t, "test-component", result.NonCompliantComponents[0].Name)
	assert.Len(t, result.ConditionalComponents, 1)
	assert.Equal(t, "conditional-component", result.ConditionalComponents[0].Name)
}

// TestPolicyService_CheckVulnerabilityPolicy_EdgeCases tests edge cases for vulnerability policy
func TestPolicyService_CheckVulnerabilityPolicy_EdgeCases(t *testing.T) {
	service, _ := createTestPolicyService()

	ctx := context.Background()

	tests := []struct {
		payload *VulnerabilityPayload
		name    string
		wantErr bool
	}{
		{
			name: "empty payload",
			payload: &VulnerabilityPayload{
				Summary: VulnerabilitySummary{},
			},
			wantErr: true, // Will fail due to no OPA connection
		},
		{
			name: "payload with vulnerabilities",
			payload: &VulnerabilityPayload{
				Summary: VulnerabilitySummary{
					Critical: 1,
					High:     2,
					Medium:   3,
					Low:      4,
				},
				Vulnerabilities: []Vulnerability{
					{
						ID:       "CVE-2024-1234",
						Package:  Package{Name: "test-package", Version: "1.0.0"},
						Severity: "CRITICAL",
					},
				},
			},
			wantErr: true, // Will fail due to no OPA connection
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := service.CheckVulnerabilityPolicy(ctx, tt.payload)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
			}
		})
	}
}

// TestPolicyService_CheckSBOMPolicy_EdgeCases tests edge cases for SBOM policy
func TestPolicyService_CheckSBOMPolicy_EdgeCases(t *testing.T) {
	tests := []struct {
		payload *SBOMPayload
		name    string
		wantErr bool
	}{
		{
			name: "empty SBOM payload",
			payload: &SBOMPayload{
				Metadata: PayloadMetadata{},
				Summary:  SBOMSummary{},
				Packages: []SBOMPackage{},
			},
			wantErr: true, // Expected to fail due to no OPA server
		},
		{
			name: "SBOM with packages",
			payload: &SBOMPayload{
				Metadata: PayloadMetadata{},
				Summary: SBOMSummary{
					TotalPackages: 2,
					AllLicenses:   []string{"MIT", "Apache-2.0"},
					LicenseDistribution: map[string]int{
						"MIT":        1,
						"Apache-2.0": 1,
					},
				},
				Packages: []SBOMPackage{
					{
						Name:             "test-package-1",
						LicenseConcluded: "MIT",
						LicenseDeclared:  "MIT",
					},
					{
						Name:             "test-package-2",
						LicenseConcluded: "Apache-2.0",
						LicenseDeclared:  "Apache-2.0",
					},
				},
			},
			wantErr: true, // Expected to fail due to no OPA server
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, _ := createTestPolicyService()

			ctx := context.Background()
			result, err := service.CheckSBOMPolicy(ctx, tt.payload)

			if tt.wantErr {
				assert.Error(t, err)
				// Check result structure is still valid even with errors
				assert.NotNil(t, result)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestPolicyService_EvaluatePolicy_ErrorHandling tests error scenarios in policy evaluation
func TestPolicyService_EvaluatePolicy_ErrorHandling(t *testing.T) {
	service, _ := createTestPolicyService()

	ctx := context.Background()

	// Test vulnerability policy with invalid context
	ctx, cancel := context.WithCancel(ctx)
	cancel() // Cancel immediately

	input := &VulnerabilityPayload{
		Summary: VulnerabilitySummary{Critical: 1},
		Vulnerabilities: []Vulnerability{
			{
				ID:       "CVE-2024-1234",
				Package:  Package{Name: "test-package", Version: "1.0.0"},
				Severity: "CRITICAL",
			},
		},
	}
	result, err := service.CheckVulnerabilityPolicy(ctx, input)
	assert.Error(t, err)
	assert.False(t, result.Compliant)
}

// TestPolicyService_ContextTimeout tests context timeout handling
func TestPolicyService_ContextTimeout(t *testing.T) {
	service, _ := createTestPolicyService()

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	// Give the timeout a chance to expire
	time.Sleep(10 * time.Millisecond)

	// Test with SBOM policy instead of hello policy
	input := &SBOMPayload{
		Metadata: PayloadMetadata{ScanTarget: "test", ToolName: "test"},
		Summary:  SBOMSummary{TotalPackages: 1},
		Packages: []SBOMPackage{
			{
				Name:             "test-package",
				LicenseConcluded: "MIT",
				LicenseDeclared:  "MIT",
			},
		},
	}
	result, err := service.CheckSBOMPolicy(ctx, input)
	assert.Error(t, err)
	assert.False(t, result.Compliant)
	assert.Contains(t, err.Error(), "context")
}

// TestPolicyService_PolicyPaths tests that policy paths are correctly defined
func TestPolicyService_PolicyPaths(t *testing.T) {
	// These constants should be accessible and correctly defined
	assert.Equal(t, "/v1/data/compliance/license_report", licensePolicyPath)
	assert.Equal(t, "/v1/data/compliance/vulnerability_report", vulnerabilityPolicyPath)
}

// TestPolicyService_EvaluatePolicy_EmptyInput tests policy evaluation with empty inputs
func TestPolicyService_EvaluatePolicy_EmptyInput(t *testing.T) {
	service, _ := createTestPolicyService()

	ctx := context.Background()

	// Test vulnerability policy with empty input
	emptyVulnPayload := &VulnerabilityPayload{
		Metadata:        PayloadMetadata{},
		Summary:         VulnerabilitySummary{},
		Vulnerabilities: []Vulnerability{},
	}
	result, err := service.CheckVulnerabilityPolicy(ctx, emptyVulnPayload)
	assert.Error(t, err) // Will fail due to no OPA connection
	assert.False(t, result.Compliant)
	assert.Zero(t, result.TotalVulnerabilities)

	// Test SBOM policy with empty input
	emptySBOMPayload := &SBOMPayload{
		Metadata: PayloadMetadata{},
		Summary:  SBOMSummary{},
		Packages: []SBOMPackage{},
	}
	sbomResult, err := service.CheckSBOMPolicy(ctx, emptySBOMPayload)
	assert.Error(t, err) // Will fail due to no OPA connection
	assert.False(t, sbomResult.Compliant)
	assert.Zero(t, sbomResult.TotalComponents)
}

// TestPolicyService_FactoryPattern tests the new factory pattern functionality
func TestPolicyService_FactoryPattern(t *testing.T) {
	service, _ := createTestPolicyService()
	ctx := context.Background()

	t.Run("Evaluate_UnknownPolicyType", func(t *testing.T) {
		result, err := service.Evaluate(ctx, "unknown", nil)
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrUnknownPolicyType)
		assert.Nil(t, result)
	})

	t.Run("Evaluate_VulnerabilityPolicy", func(t *testing.T) {
		// This will fail due to no OPA connection, but tests the registry
		input := &VulnerabilityPayload{
			Summary:         VulnerabilitySummary{},
			Vulnerabilities: []Vulnerability{},
		}
		result, err := service.Evaluate(ctx, "vulnerability", input)
		assert.Error(t, err) // Will fail due to no OPA connection
		assert.Equal(t, VulnerabilityPolicyResult{}, result)
	})

	t.Run("Evaluate_SBOMPolicy", func(t *testing.T) {
		// This will fail due to no OPA connection, but tests the registry
		input := &SBOMPayload{
			Summary:  SBOMSummary{},
			Packages: []SBOMPackage{},
		}
		result, err := service.Evaluate(ctx, "sbom", input)
		assert.Error(t, err) // Will fail due to no OPA connection
		assert.Equal(t, SBOMPolicyResult{}, result)
	})
}

// TestPolicyEvaluators tests the individual evaluator implementations through the public interface
func TestPolicyEvaluators(t *testing.T) {
	service, _ := createTestPolicyService()
	evaluators := NewStandardEvaluators(service)

	var vulnEvaluator, sbomEvaluator PolicyEvaluator
	for _, evaluator := range evaluators {
		switch evaluator.PolicyType() {
		case "vulnerability":
			vulnEvaluator = evaluator
		case "sbom":
			sbomEvaluator = evaluator
		}
	}

	t.Run("VulnerabilityEvaluator", func(t *testing.T) {
		assert.NotNil(t, vulnEvaluator)
		assert.Equal(t, "vulnerability", vulnEvaluator.PolicyType())
		assert.Equal(t, vulnerabilityPolicyPath, vulnEvaluator.PolicyPath())

		// Test wrong payload type
		result, err := vulnEvaluator.Evaluate(context.Background(), "wrong type")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrPolicyEvaluation)
		assert.Nil(t, result)
	})

	t.Run("SBOMEvaluator", func(t *testing.T) {
		assert.NotNil(t, sbomEvaluator)
		assert.Equal(t, "sbom", sbomEvaluator.PolicyType())
		assert.Equal(t, licensePolicyPath, sbomEvaluator.PolicyPath())

		// Test wrong payload type
		result, err := sbomEvaluator.Evaluate(context.Background(), "wrong type")
		assert.Error(t, err)
		assert.ErrorIs(t, err, ErrPolicyEvaluation)
		assert.Nil(t, result)
	})
}

// TestNewStandardEvaluators tests the factory function
func TestNewStandardEvaluators(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")
	telHelper := telemetry.NewTelemetryHelper("test/policy")
	service := NewPolicyService(opaClient, logger, telHelper, nil)

	evaluators := NewStandardEvaluators(service)
	assert.Len(t, evaluators, 2)

	// Check evaluator types by their behavior
	var vulnEvaluator, sbomEvaluator PolicyEvaluator
	for _, evaluator := range evaluators {
		switch evaluator.PolicyType() {
		case "vulnerability":
			vulnEvaluator = evaluator
		case "sbom":
			sbomEvaluator = evaluator
		}
	}

	assert.NotNil(t, vulnEvaluator)
	assert.NotNil(t, sbomEvaluator)

	// Test their behavior instead of their concrete types
	assert.Equal(t, "vulnerability", vulnEvaluator.PolicyType())
	assert.Equal(t, "sbom", sbomEvaluator.PolicyType())
}

// TestPolicyService_PolicyResult_DefaultValues tests default values for policy results
func TestPolicyService_PolicyResult_DefaultValues(t *testing.T) {
	// Test VulnerabilityPolicyResult default values
	var vulnResult VulnerabilityPolicyResult
	assert.False(t, vulnResult.Compliant)
	assert.Zero(t, vulnResult.TotalVulnerabilities)
	assert.Zero(t, vulnResult.CompliantCount)
	assert.Zero(t, vulnResult.NonCompliantCount)
	assert.Nil(t, vulnResult.NonCompliantVulnerabilities)

	// Test SBOMPolicyResult default values
	var sbomResult SBOMPolicyResult
	assert.False(t, sbomResult.Compliant)
	assert.Zero(t, sbomResult.TotalComponents)
	assert.Zero(t, sbomResult.CompliantComponents)
	assert.Nil(t, sbomResult.NonCompliantLicenses)
	assert.Nil(t, sbomResult.NonCompliantComponents)
	assert.Nil(t, sbomResult.ConditionalComponents)
	assert.Nil(t, sbomResult.AllowedLicenses)
}

// TestPolicyService_VulnerabilityPolicyVuln_Structure tests vulnerability policy vulnerability structure
func TestPolicyService_VulnerabilityPolicyVuln_Structure(t *testing.T) {
	vuln := VulnerabilityPolicyVuln{
		ID:           "CVE-2024-1234",
		Package:      "test-package",
		Version:      "1.0.0",
		Severity:     "HIGH",
		Score:        7.5,
		FixedVersion: "1.0.1",
	}

	assert.Equal(t, "CVE-2024-1234", vuln.ID)
	assert.Equal(t, "test-package", vuln.Package)
	assert.Equal(t, "1.0.0", vuln.Version)
	assert.Equal(t, "HIGH", vuln.Severity)
	assert.Equal(t, 7.5, vuln.Score)
	assert.Equal(t, "1.0.1", vuln.FixedVersion)
}
