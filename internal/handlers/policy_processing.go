package handlers

import (
	"context"
	"errors"
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
	SystemUnavailable      bool // Indicates if the policy evaluation system is unavailable
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

// PolicyCacheServiceInterface defines the interface for cached policy evaluation services
type PolicyCacheServiceInterface interface {
	CheckVulnerabilityPolicyWithCache(
		ctx context.Context,
		input *services.VulnerabilityPayload,
		owner, repo, sha string,
	) (services.VulnerabilityPolicyResult, error)
	CheckSBOMPolicyWithCache(
		ctx context.Context,
		input *services.SBOMPayload,
		owner, repo, sha string,
	) (services.SBOMPolicyResult, error)
}

// PolicyProcessor defines the strategy interface for processing different types of security policies
type PolicyProcessor interface {
	ProcessPayloads(
		ctx context.Context,
		logger *slog.Logger,
		policyCacheService PolicyCacheServiceInterface,
		payloads interface{},
		owner, repo, sha string,
	) PolicyProcessingResult
	GetPolicyType() string
}

// VulnerabilityPolicyProcessor handles vulnerability policy processing
type VulnerabilityPolicyProcessor struct{}

// LicensePolicyProcessor handles license policy processing
type LicensePolicyProcessor struct{}

// ProcessPayloads processes vulnerability payloads and evaluates policies
func (p *VulnerabilityPolicyProcessor) ProcessPayloads(
	ctx context.Context,
	logger *slog.Logger,
	policyCacheService PolicyCacheServiceInterface,
	payloads interface{},
	owner, repo, sha string,
) PolicyProcessingResult {
	vulnPayloads, ok := payloads.([]*services.VulnerabilityPayload)
	if !ok {
		logger.ErrorContext(ctx, "Invalid payload type for vulnerability processing")
		return PolicyProcessingResult{AllPassed: false, FailureDetails: []string{"Invalid payload type for vulnerability processing"}}
	}

	result := PolicyProcessingResult{AllPassed: true}

	for _, payload := range vulnPayloads {
		logger.DebugContext(ctx, "Processing vulnerability payload",
			"owner", owner, "repo", repo, "sha", sha,
			"payload_vulnerability_summary", payload.Summary,
		)

		// Use cache-aware policy evaluation
		policyResult, err := policyCacheService.CheckVulnerabilityPolicyWithCache(ctx, payload, owner, repo, sha)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to evaluate vulnerability policy", "error", err)

			// Check if this is a system error (OPA down, network issues)
			if errors.Is(err, services.ErrSystemUnavailable) {
				logger.WarnContext(ctx, "Policy evaluation system unavailable, skipping check",
					"owner", owner, "repo", repo, "sha", sha)
				// Return early - don't process check run when system is down
				return PolicyProcessingResult{
					AllPassed:         false,
					SystemUnavailable: true,
					FailureDetails:    []string{"Policy evaluation system temporarily unavailable"},
				}
			}

			// For other errors, use fallback logic
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

// ProcessPayloads processes SBOM payloads and evaluates license policies
func (p *LicensePolicyProcessor) ProcessPayloads(
	ctx context.Context,
	logger *slog.Logger,
	policyCacheService PolicyCacheServiceInterface,
	payloads interface{},
	owner, repo, sha string,
) PolicyProcessingResult {
	sbomPayloads, ok := payloads.([]*services.SBOMPayload)
	if !ok {
		logger.ErrorContext(ctx, "Invalid payload type for SBOM processing")
		return PolicyProcessingResult{AllPassed: false, FailureDetails: []string{"Invalid payload type for SBOM processing"}}
	}
	result := PolicyProcessingResult{AllPassed: true}

	for _, payload := range sbomPayloads {
		logger.DebugContext(ctx, "Processing SBOM payload",
			"owner", owner, "repo", repo, "sha", sha,
			"package_count", payload.Summary.TotalPackages,
		)

		// Use cache-aware policy evaluation
		policyResult, err := policyCacheService.CheckSBOMPolicyWithCache(ctx, payload, owner, repo, sha)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to evaluate SBOM policy", "error", err)

			// Check if this is a system error (OPA down, network issues)
			if errors.Is(err, services.ErrSystemUnavailable) {
				logger.WarnContext(ctx, "Policy evaluation system unavailable, skipping check",
					"owner", owner, "repo", repo, "sha", sha)
				// Return early - don't process check run when system is down
				return PolicyProcessingResult{
					AllPassed:         false,
					SystemUnavailable: true,
					FailureDetails:    []string{"Policy evaluation system temporarily unavailable"},
				}
			}

			// For other errors, use fallback logic
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
	policyCacheService PolicyCacheServiceInterface,
	processor PolicyProcessor,
	payloads interface{},
	owner, repo, sha string,
) PolicyProcessingResult {
	return processor.ProcessPayloads(ctx, logger, policyCacheService, payloads, owner, repo, sha)
}

// processVulnerabilityPolicies evaluates vulnerability policies for all payloads using strategy pattern
func processVulnerabilityPolicies(
	ctx context.Context,
	logger *slog.Logger,
	policyCacheService *services.PolicyCacheService,
	payloads []*services.VulnerabilityPayload,
	owner, repo, sha string,
) PolicyProcessingResult {
	processor := &VulnerabilityPolicyProcessor{}

	return processPoliciesWithStrategy(
		ctx,
		logger,
		policyCacheService,
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
	policyCacheService *services.PolicyCacheService,
	payloads []*services.SBOMPayload,
	owner, repo, sha string,
) PolicyProcessingResult {
	processor := &LicensePolicyProcessor{}

	return processPoliciesWithStrategy(
		ctx,
		logger,
		policyCacheService,
		processor,
		payloads,
		owner,
		repo,
		sha,
	)
}
