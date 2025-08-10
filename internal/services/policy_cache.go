package services

import (
	"context"
	"errors"
	"log/slog"

	"github.com/terrpan/polly/internal/config"
	"github.com/terrpan/polly/internal/telemetry"
)

// PolicyCacheService provides cached policy evaluation
type PolicyCacheService struct {
	policyService *PolicyService
	stateService  *StateService
	logger        *slog.Logger
	telemetry     *telemetry.Helper
}

// NewPolicyCacheService creates a new PolicyCacheService
func NewPolicyCacheService(
	policyService *PolicyService,
	stateService *StateService,
	logger *slog.Logger,
	telemetry *telemetry.Helper,
) *PolicyCacheService {
	return &PolicyCacheService{
		policyService: policyService,
		stateService:  stateService,
		logger:        logger,
		telemetry:     telemetry,
	}
}

// CheckVulnerabilityPolicyWithCache evaluates vulnerability policy with caching
func (s *PolicyCacheService) CheckVulnerabilityPolicyWithCache(
	ctx context.Context,
	input *VulnerabilityPayload,
	owner, repo, sha string,
) (VulnerabilityPolicyResult, error) {
	return checkPolicyWithCache(
		ctx,
		s,
		"vulnerability",
		"policy_cache.check_vulnerability",
		owner, repo, sha,
		func(ctx context.Context) (VulnerabilityPolicyResult, error) {
			return s.policyService.CheckVulnerabilityPolicy(ctx, input)
		},
		convertMapToVulnerabilityPolicyResult,
	)
}

// CheckSBOMPolicyWithCache evaluates SBOM policy with caching
func (s *PolicyCacheService) CheckSBOMPolicyWithCache(
	ctx context.Context,
	input *SBOMPayload,
	owner, repo, sha string,
) (SBOMPolicyResult, error) {
	return checkPolicyWithCache(
		ctx,
		s,
		"sbom",
		"policy_cache.check_sbom",
		owner, repo, sha,
		func(ctx context.Context) (SBOMPolicyResult, error) {
			return s.policyService.CheckSBOMPolicy(ctx, input)
		},
		convertMapToSBOMPolicyResult,
	)
}

// checkPolicyWithCache provides generic caching logic for policy evaluation
func checkPolicyWithCache[T any](
	ctx context.Context,
	s *PolicyCacheService,
	policyType, spanName string,
	owner, repo, sha string,
	evaluatePolicy func(context.Context) (T, error),
	convertFromMap func(map[string]interface{}) (T, error),
) (T, error) {
	var zero T

	ctx, span := s.telemetry.StartSpan(ctx, spanName)
	defer span.End()

	s.telemetry.SetPolicyAttributes(span, policyType)

	// Check cache only if enabled
	cacheConfig := config.GetPolicyCacheConfig()
	if cacheConfig.Enabled {
		if cachedResult, found, err := s.stateService.GetCachedPolicyResults(ctx, owner, repo, sha, policyType); err == nil &&
			found {
			// Handle both direct struct and map[string]interface{} from cache
			if result, ok := cachedResult.(T); ok {
				s.telemetry.SetCacheAttributes(span, true)
				s.logger.DebugContext(ctx, "Using cached "+policyType+" policy result")

				return result, nil
			} else if resultMap, ok := cachedResult.(map[string]interface{}); ok {
				// Convert map back to struct
				if result, err := convertFromMap(resultMap); err == nil {
					s.telemetry.SetCacheAttributes(span, true)
					s.logger.DebugContext(ctx, "Using cached "+policyType+" policy result (converted from map)")

					return result, nil
				} else {
					s.logger.WarnContext(ctx, "Failed to convert cached map to "+policyType+"PolicyResult", "error", err)
				}
			}
		}
	}

	s.telemetry.SetCacheAttributes(span, false)

	// Cache miss - evaluate policy
	result, err := evaluatePolicy(ctx)
	if err != nil {
		// Don't cache system unavailable errors - allow retry when system is back up
		if errors.Is(err, ErrSystemUnavailable) {
			s.logger.DebugContext(
				ctx,
				"System unavailable - not caching error result to allow retry",
				"error",
				err,
			)

			return zero, err
		}

		return zero, err
	}

	// Store in cache only if enabled
	if cacheConfig.Enabled {
		if err := s.stateService.StoreCachedPolicyResults(ctx, owner, repo, sha, policyType, result); err != nil {
			s.logger.WarnContext(ctx, "Failed to cache "+policyType+" policy result", "error", err)
		} else {
			s.logger.DebugContext(ctx, "Cached "+policyType+" policy result")
		}
	}

	return result, nil
}
