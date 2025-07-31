package services

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/terrpan/polly/internal/config"
)

// PolicyCacheService provides cached policy evaluation
type PolicyCacheService struct {
	policyService *PolicyService
	stateService  *StateService
	logger        *slog.Logger
}

// NewPolicyCacheService creates a new PolicyCacheService
func NewPolicyCacheService(
	policyService *PolicyService,
	stateService *StateService,
	logger *slog.Logger,
) *PolicyCacheService {
	return &PolicyCacheService{
		policyService: policyService,
		stateService:  stateService,
		logger:        logger,
	}
}

// CheckVulnerabilityPolicyWithCache evaluates vulnerability policy with caching
func (s *PolicyCacheService) CheckVulnerabilityPolicyWithCache(
	ctx context.Context,
	input *VulnerabilityPayload,
	owner, repo, sha string,
) (VulnerabilityPolicyResult, error) {
	tracer := otel.Tracer("polly/services")

	ctx, span := tracer.Start(ctx, "policy_cache.check_vulnerability")
	defer span.End()

	span.SetAttributes(
		attribute.String("policy.type", "vulnerability"),
		attribute.String("repo.owner", owner),
		attribute.String("repo.name", repo),
		attribute.String("repo.sha", sha),
	)

	// Check cache only if enabled
	cacheConfig := config.GetPolicyCacheConfig()
	if cacheConfig.Enabled {
		if cachedResult, found, err := s.stateService.GetCachedPolicyResults(ctx, owner, repo, sha, "vulnerability"); err == nil &&
			found {
			// Handle both direct struct and map[string]interface{} from cache
			if result, ok := cachedResult.(VulnerabilityPolicyResult); ok {
				span.SetAttributes(attribute.Bool("cache.hit", true))
				s.logger.DebugContext(ctx, "Using cached vulnerability policy result")

				return result, nil
			} else if resultMap, ok := cachedResult.(map[string]interface{}); ok {
				// Convert map back to struct
				if result, err := convertMapToVulnerabilityPolicyResult(resultMap); err == nil {
					span.SetAttributes(attribute.Bool("cache.hit", true))
					s.logger.DebugContext(ctx, "Using cached vulnerability policy result (converted from map)")

					return result, nil
				} else {
					s.logger.WarnContext(ctx, "Failed to convert cached map to VulnerabilityPolicyResult", "error", err)
				}
			}
		}
	}

	span.SetAttributes(attribute.Bool("cache.hit", false))

	// Cache miss - evaluate policy
	result, err := s.policyService.CheckVulnerabilityPolicy(ctx, input)
	if err != nil {
		return VulnerabilityPolicyResult{}, err
	}

	// Store in cache only if enabled
	if cacheConfig.Enabled {
		if err := s.stateService.StoreCachedPolicyResults(ctx, owner, repo, sha, "vulnerability", result); err != nil {
			s.logger.WarnContext(ctx, "Failed to cache vulnerability policy result", "error", err)
		} else {
			s.logger.DebugContext(ctx, "Cached vulnerability policy result")
		}
	}

	return result, nil
}

// CheckSBOMPolicyWithCache evaluates SBOM policy with caching
func (s *PolicyCacheService) CheckSBOMPolicyWithCache(
	ctx context.Context,
	input *SBOMPayload,
	owner, repo, sha string,
) (SBOMPolicyResult, error) {
	tracer := otel.Tracer("polly/services")

	ctx, span := tracer.Start(ctx, "policy_cache.check_sbom")
	defer span.End()

	span.SetAttributes(
		attribute.String("policy.type", "sbom"),
		attribute.String("repo.owner", owner),
		attribute.String("repo.name", repo),
		attribute.String("repo.sha", sha),
	)

	// Check cache only if enabled
	cacheConfig := config.GetPolicyCacheConfig()
	if cacheConfig.Enabled {
		if cachedResult, found, err := s.stateService.GetCachedPolicyResults(ctx, owner, repo, sha, "sbom"); err == nil &&
			found {
			// Handle both direct struct and map[string]interface{} from cache
			if result, ok := cachedResult.(SBOMPolicyResult); ok {
				span.SetAttributes(attribute.Bool("cache.hit", true))
				s.logger.DebugContext(ctx, "Using cached SBOM policy result")

				return result, nil
			} else if resultMap, ok := cachedResult.(map[string]interface{}); ok {
				// Convert map back to struct
				if result, err := convertMapToSBOMPolicyResult(resultMap); err == nil {
					span.SetAttributes(attribute.Bool("cache.hit", true))
					s.logger.DebugContext(ctx, "Using cached SBOM policy result (converted from map)")

					return result, nil
				} else {
					s.logger.WarnContext(ctx, "Failed to convert cached map to SBOMPolicyResult", "error", err)
				}
			}
		}
	}

	span.SetAttributes(attribute.Bool("cache.hit", false))

	// Cache miss - evaluate policy
	result, err := s.policyService.CheckSBOMPolicy(ctx, input)
	if err != nil {
		return SBOMPolicyResult{}, err
	}

	// Store in cache only if enabled
	if cacheConfig.Enabled {
		if err := s.stateService.StoreCachedPolicyResults(ctx, owner, repo, sha, "sbom", result); err != nil {
			s.logger.WarnContext(ctx, "Failed to cache SBOM policy result", "error", err)
		} else {
			s.logger.DebugContext(ctx, "Cached SBOM policy result")
		}
	}

	return result, nil
}
