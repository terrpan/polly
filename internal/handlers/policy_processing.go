package handlers

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/terrpan/polly/internal/services"
)

// PolicyProcessingResult holds the result of processing security payloads
type PolicyProcessingResult struct {
	FailureDetails         []string
	NonCompliantVulns      []services.VulnerabilityPolicyVuln
	NonCompliantComponents []services.SBOMPolicyComponent
	ConditionalComponents  []services.SBOMPolicyComponent
	AllPassed              bool
}

// PolicyServiceInterface defines the interface for policy evaluation services
type PolicyServiceInterface interface {
	CheckVulnerabilityPolicy(
		ctx context.Context,
		input *services.VulnerabilityPayload,
	) (services.VulnerabilityPolicyResult, error)
	CheckSBOMPolicy(
		ctx context.Context,
		input *services.SBOMPayload,
	) (services.SBOMPolicyResult, error)
}

// PolicyProcessor defines the strategy interface for processing different types of security policies
type PolicyProcessor interface {
	ProcessPayloads(
		ctx context.Context,
		logger *slog.Logger,
		policyService PolicyServiceInterface,
		payloads interface{},
		owner, repo, sha string,
	) PolicyProcessingResult
	GetPolicyType() string
}

// VulnerabilityPolicyProcessor handles vulnerability policy processing
type VulnerabilityPolicyProcessor struct{}

// ProcessPayloads processes vulnerability payloads and evaluates policies
func (p *VulnerabilityPolicyProcessor) ProcessPayloads(
	ctx context.Context,
	logger *slog.Logger,
	policyService PolicyServiceInterface,
	payloads interface{},
	owner, repo, sha string,
) PolicyProcessingResult {
	vulnPayloads := payloads.([]*services.VulnerabilityPayload)
	result := PolicyProcessingResult{AllPassed: true}

	for _, payload := range vulnPayloads {
		logger.DebugContext(ctx, "Processing vulnerability payload",
			"owner", owner, "repo", repo, "sha", sha,
			"payload_vulnerability_summary", payload.Summary,
		)

		policyResult, err := policyService.CheckVulnerabilityPolicy(ctx, payload)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to evaluate vulnerability policy", "error", err)

			if payload.Summary.Critical > 0 || payload.Summary.High > 0 {
				result.AllPassed = false
				result.FailureDetails = append(
					result.FailureDetails,
					fmt.Sprintf(
						"Found %d critical and %d high severity vulnerabilities (policy evaluation failed)",
						payload.Summary.Critical,
						payload.Summary.High,
					),
				)
			}

			continue
		}

		if !policyResult.Compliant {
			result.AllPassed = false
			result.FailureDetails = append(
				result.FailureDetails,
				fmt.Sprintf(
					"Vulnerability policy violation: %d non-compliant vulnerabilities out of %d total",
					policyResult.NonCompliantCount,
					policyResult.TotalVulnerabilities,
				),
			)
			result.NonCompliantVulns = append(
				result.NonCompliantVulns,
				policyResult.NonCompliantVulnerabilities...)
		}
	}

	return result
}

// GetPolicyType returns the policy type identifier
func (p *VulnerabilityPolicyProcessor) GetPolicyType() string {
	return "vulnerability"
}

// LicensePolicyProcessor handles license policy processing
type LicensePolicyProcessor struct{}

// ProcessPayloads processes SBOM payloads and evaluates license policies
func (p *LicensePolicyProcessor) ProcessPayloads(
	ctx context.Context,
	logger *slog.Logger,
	policyService PolicyServiceInterface,
	payloads interface{},
	owner, repo, sha string,
) PolicyProcessingResult {
	sbomPayloads := payloads.([]*services.SBOMPayload)
	result := PolicyProcessingResult{AllPassed: true}

	for _, payload := range sbomPayloads {
		logger.DebugContext(ctx, "Processing SBOM payload",
			"owner", owner, "repo", repo, "sha", sha,
			"package_count", payload.Summary.TotalPackages,
		)

		policyResult, err := policyService.CheckSBOMPolicy(ctx, payload)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to evaluate SBOM policy", "error", err)

			if payload.Summary.PackagesWithoutLicense > 0 {
				result.AllPassed = false
				result.FailureDetails = append(result.FailureDetails,
					fmt.Sprintf("Found %d packages without license (policy evaluation failed)",
						payload.Summary.PackagesWithoutLicense))
			}

			continue
		}

		if !policyResult.Compliant {
			result.AllPassed = false
			result.FailureDetails = append(result.FailureDetails,
				fmt.Sprintf(
					"SBOM policy violation: %d non-compliant components out of %d total",
					policyResult.TotalComponents-policyResult.CompliantComponents,
					policyResult.TotalComponents,
				))
			result.NonCompliantComponents = append(
				result.NonCompliantComponents,
				policyResult.NonCompliantComponents...)
		}

		result.ConditionalComponents = append(
			result.ConditionalComponents,
			policyResult.ConditionalComponents...)
	}

	return result
}

// GetPolicyType returns the policy type identifier
func (p *LicensePolicyProcessor) GetPolicyType() string {
	return "license"
}

// processPoliciesWithStrategy processes policies using the strategy pattern
func processPoliciesWithStrategy(
	ctx context.Context,
	logger *slog.Logger,
	policyService PolicyServiceInterface,
	processor PolicyProcessor,
	payloads interface{},
	owner, repo, sha string,
) PolicyProcessingResult {
	return processor.ProcessPayloads(ctx, logger, policyService, payloads, owner, repo, sha)
}

// processVulnerabilityPolicies evaluates vulnerability policies for all payloads using strategy pattern
func processVulnerabilityPolicies(
	ctx context.Context,
	logger *slog.Logger,
	policyService *services.PolicyService,
	payloads []*services.VulnerabilityPayload,
	owner, repo, sha string,
) PolicyProcessingResult {
	processor := &VulnerabilityPolicyProcessor{}

	return processPoliciesWithStrategy(
		ctx,
		logger,
		policyService,
		processor,
		payloads,
		owner,
		repo,
		sha,
	)
}

// processLicensePolicies evaluates license policies for all payloads using strategy pattern
func processLicensePolicies(
	ctx context.Context,
	logger *slog.Logger,
	policyService *services.PolicyService,
	payloads []*services.SBOMPayload,
	owner, repo, sha string,
) PolicyProcessingResult {
	processor := &LicensePolicyProcessor{}

	return processPoliciesWithStrategy(
		ctx,
		logger,
		policyService,
		processor,
		payloads,
		owner,
		repo,
		sha,
	)
}
