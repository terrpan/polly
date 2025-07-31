// Package services provides business logic and state management for the Polly application.
// This file defines the StateService which handles state-related operations.
package services

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/terrpan/polly/internal/config"
	"github.com/terrpan/polly/internal/storage"
)

// StateKeyType represents the type of state keys.
type StateKeyType string

// RepoContext represents the repository context for state operations.
type RepoContext struct {
	Owner string
	Repo  string
	SHA   string
}

// StateService handles state-related operations.
type StateService struct {
	store      storage.Store
	logger     *slog.Logger
	expiration time.Duration // Default expiration duration for keys
}

// StateMap represents a map of state data for a repository context.
type StateMap struct {
	PRNumber              int64
	VulnerabilityCheckID  int64
	LicenseCheckID        int64
	WorkflowRunID         int64
	HasPRNumber           bool
	HasVulnerabilityCheck bool
	HasLicenseCheck       bool
	HasWorkflowRun        bool
}

const (
	// StateKeyPR represents the key for storing PR numbers.
	StateKeyPR StateKeyType = "pr"
	// StateKeyVulnCheck represents the key for storing vulnerability check run IDs.
	StateKeyVulnCheck StateKeyType = "vulnerability_check"
	// StateKeyLicenseCheck represents the key for storing license check run IDs.
	StateKeyLicenseCheck StateKeyType = "license_check"
	// StateKeyWorkflow represents the key for storing workflow run IDs.
	StateKeyWorkflow StateKeyType = "workflow"
)

// NewStateService creates a new StateService.
func NewStateService(store storage.Store, logger *slog.Logger) *StateService {
	return &StateService{
		store:      store,
		logger:     logger,
		expiration: config.GetDefaultExpiration(), // Use the helper function to get the default expiration TODO: rename to parse from config
	}
}

// storeInt64 stores an int64 value with the given key type and repository context.
// in the format "<owner>:<repo>:<keyType>:<sha>". e.g.: "terrpan:polly:pr:abc123def456 -> 42"
func (s *StateService) storeInt64(
	ctx context.Context,
	keyType StateKeyType,
	repoCtx RepoContext,
	value int64,
) error {
	tracer := otel.Tracer("polly/services")

	ctx, span := tracer.Start(ctx, fmt.Sprintf("state.store_%s", keyType))
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", repoCtx.Owner),
		attribute.String("github.repo", repoCtx.Repo),
		attribute.String("github.sha", repoCtx.SHA),
		attribute.String("state.key_type", string(keyType)),
		attribute.Int64("state.value", value),
	)

	key := fmt.Sprintf("%s:%s:%s:%s", repoCtx.Owner, repoCtx.Repo, keyType, repoCtx.SHA)
	span.SetAttributes(attribute.String("storage.key", key))

	return s.store.Set(ctx, key, value, s.expiration)
}

// getInt64 retrieves an int64 value for the given key type and repository context.
// It returns the value, a boolean indicating if the key was found, and an error if any.
func (s *StateService) getInt64(
	ctx context.Context,
	keyType StateKeyType,
	repoCtx RepoContext,
) (int64, bool, error) {
	tracer := otel.Tracer("polly/services")

	ctx, span := tracer.Start(ctx, fmt.Sprintf("state.get_%s", keyType))
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", repoCtx.Owner),
		attribute.String("github.repo", repoCtx.Repo),
		attribute.String("github.sha", repoCtx.SHA),
		attribute.String("state.key_type", string(keyType)),
	)

	key := fmt.Sprintf("%s:%s:%s:%s", repoCtx.Owner, repoCtx.Repo, keyType, repoCtx.SHA)
	span.SetAttributes(attribute.String("storage.key", key))

	value, err := s.store.Get(ctx, key)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			span.SetAttributes(
				attribute.Bool("cache.hit", false),
				attribute.String("cache.miss_reason", "not_found"),
			)

			return 0, false, nil
		}

		span.SetAttributes(attribute.Bool("cache.hit", false))

		return 0, false, err
	}

	span.SetAttributes(attribute.Bool("cache.hit", true))

	// Handle JSON unmarshalling variations
	switch v := value.(type) {
	case int64:
		span.SetAttributes(attribute.Int64("state.value", v))
		return v, true, nil
	case float64:
		result := int64(v)
		span.SetAttributes(attribute.Int64("state.value", result))

		return result, true, nil
	case string:
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			span.SetAttributes(attribute.Int64("state.value", n))
			return n, true, nil
		}
	}

	return 0, false, fmt.Errorf("unexpected value type for key %s: %T", key, value)
}

// deleteState deletes the state for a given key type and repository context.
func (s *StateService) deleteState(
	ctx context.Context,
	keyType StateKeyType,
	repoCtx RepoContext,
) error {
	key := fmt.Sprintf("%s:%s:%s:%s", repoCtx.Owner, repoCtx.Repo, keyType, repoCtx.SHA)
	return s.store.Delete(ctx, key)
}

// StorePRNumber stores the PR number for a given repository context.
func (s *StateService) StorePRNumber(
	ctx context.Context,
	owner, repo, sha string,
	prNumber int64,
) error {
	repoCtx := RepoContext{Owner: owner, Repo: repo, SHA: sha}
	return s.storeInt64(ctx, StateKeyPR, repoCtx, prNumber)
}

// GetPRNumber retrieves the PR number for a given repository context.
func (s *StateService) GetPRNumber(
	ctx context.Context,
	owner, repo, sha string,
) (int64, bool, error) {
	repoCtx := RepoContext{Owner: owner, Repo: repo, SHA: sha}
	return s.getInt64(ctx, StateKeyPR, repoCtx)
}

// StoreVulnerabilityCheckRunID stores the vulnerability check run ID for a given repository context.
func (s *StateService) StoreVulnerabilityCheckRunID(
	ctx context.Context,
	owner, repo, sha string,
	runID int64,
) error {
	repoCtx := RepoContext{Owner: owner, Repo: repo, SHA: sha}
	return s.storeInt64(ctx, StateKeyVulnCheck, repoCtx, runID)
}

// GetVulnerabilityCheckRunID retrieves the vulnerability check run ID for a given repository context.
func (s *StateService) GetVulnerabilityCheckRunID(
	ctx context.Context,
	owner, repo, sha string,
) (int64, bool, error) {
	repoCtx := RepoContext{Owner: owner, Repo: repo, SHA: sha}
	return s.getInt64(ctx, StateKeyVulnCheck, repoCtx)
}

// StoreLicenseCheckRunID stores the license check run ID for a given repository context.
func (s *StateService) StoreLicenseCheckRunID(
	ctx context.Context,
	owner, repo, sha string,
	runID int64,
) error {
	repoCtx := RepoContext{Owner: owner, Repo: repo, SHA: sha}
	return s.storeInt64(ctx, StateKeyLicenseCheck, repoCtx, runID)
}

// GetLicenseCheckRunID retrieves the license check run ID for a given repository context.
func (s *StateService) GetLicenseCheckRunID(
	ctx context.Context,
	owner, repo, sha string,
) (int64, bool, error) {
	repoCtx := RepoContext{Owner: owner, Repo: repo, SHA: sha}
	return s.getInt64(ctx, StateKeyLicenseCheck, repoCtx)
}

// StoreWorkflowRunID stores the workflow run ID for a given repository context.
func (s *StateService) StoreWorkflowRunID(
	ctx context.Context,
	owner, repo, sha string,
	runID int64,
) error {
	repoCtx := RepoContext{Owner: owner, Repo: repo, SHA: sha}
	return s.storeInt64(ctx, StateKeyWorkflow, repoCtx, runID)
}

// GetWorkflowRunID retrieves the workflow run ID for a given repository context.
func (s *StateService) GetWorkflowRunID(
	ctx context.Context,
	owner, repo, sha string,
) (int64, bool, error) {
	repoCtx := RepoContext{Owner: owner, Repo: repo, SHA: sha}
	return s.getInt64(ctx, StateKeyWorkflow, repoCtx)
}

// GetCachedPolicyResults retrieves cached policy results for check run re-runs
func (s *StateService) GetCachedPolicyResults(
	ctx context.Context,
	owner, repo, sha string,
	checkType string,
) (interface{}, bool, error) {
	tracer := otel.Tracer("polly/services")

	ctx, span := tracer.Start(ctx, "state.get_cached_policy_results")
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.String("github.sha", sha),
		attribute.String("check.type", checkType),
	)

	// Check if policy caching is enabled in configuration
	policyCacheConfig := config.GetPolicyCacheConfig()
	if !policyCacheConfig.Enabled {
		span.SetAttributes(attribute.Bool("cache.enabled", false))
		s.logger.DebugContext(ctx, "Policy caching is disabled")

		return nil, false, nil
	}

	key := fmt.Sprintf("policy_results:%s:%s:%s:%s", checkType, owner, repo, sha)
	span.SetAttributes(attribute.String("storage.key", key))

	entry, err := s.store.GetCachedPolicyResults(ctx, key)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			span.SetAttributes(
				attribute.Bool("cache.hit", false),
				attribute.String("cache.miss_reason", "not_found"),
			)
			s.logger.DebugContext(ctx, "Cached policy results not found in storage", "key", key)

			return nil, false, nil
		}

		span.SetAttributes(attribute.Bool("cache.hit", false))
		s.logger.ErrorContext(ctx, "Failed to get cached policy results from storage",
			"error", err,
			"key", key,
		)

		return nil, false, fmt.Errorf("failed to get cached policy results: %w", err)
	}

	span.SetAttributes(
		attribute.Bool("cache.hit", true),
		attribute.Int64("cache.size_bytes", entry.Size),
		attribute.String("cache.cached_at", entry.CachedAt.Format("2006-01-02T15:04:05Z07:00")),
		attribute.String("cache.expires_at", entry.ExpiresAt.Format("2006-01-02T15:04:05Z07:00")),
	)
	s.logger.DebugContext(ctx, "Retrieved cached policy results from storage",
		"check_type", checkType,
		"key", key,
		"size_bytes", entry.Size,
	)

	return entry.Result, true, nil
}

// StoreCachedPolicyResults stores policy results for check run re-runs
func (s *StateService) StoreCachedPolicyResults(
	ctx context.Context,
	owner, repo, sha string,
	checkType string,
	results interface{},
) error {
	tracer := otel.Tracer("polly/services")

	ctx, span := tracer.Start(ctx, "state.store_cached_policy_results")
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.String("github.sha", sha),
		attribute.String("check.type", checkType),
	)

	// Check if policy caching is enabled in configuration
	policyCacheConfig := config.GetPolicyCacheConfig()
	if !policyCacheConfig.Enabled {
		span.SetAttributes(attribute.Bool("cache.enabled", false))
		s.logger.DebugContext(ctx, "Policy caching is disabled, skipping cache storage")

		return nil
	}

	key := fmt.Sprintf("policy_results:%s:%s:%s:%s", checkType, owner, repo, sha)
	span.SetAttributes(attribute.String("storage.key", key))

	// Parse TTL from configuration, with fallback for invalid values
	ttl, err := time.ParseDuration(policyCacheConfig.TTL)
	if err != nil {
		s.logger.WarnContext(ctx, "Invalid TTL in policy cache config, using default",
			"configured_ttl", policyCacheConfig.TTL,
			"error", err,
		)

		ttl = 30 * time.Minute // Default fallback
	}

	maxSize := policyCacheConfig.MaxSize

	span.SetAttributes(
		attribute.String("cache.ttl", ttl.String()),
		attribute.Int64("cache.max_size_bytes", maxSize),
	)

	err = s.store.StoreCachedPolicyResults(ctx, key, results, ttl, maxSize)
	if err != nil {
		if err == storage.ErrEntrySizeExceeded {
			span.SetAttributes(attribute.Bool("cache.size_exceeded", true))
			s.logger.WarnContext(ctx, "Policy result too large for caching, skipping cache storage",
				"key", key,
				"max_size_bytes", maxSize,
			)

			return nil // Don't fail the operation, just skip caching
		}

		s.logger.ErrorContext(ctx, "Failed to store cached policy results",
			"error", err,
			"key", key,
		)

		return fmt.Errorf("failed to store cached policy results: %w", err)
	}

	span.SetAttributes(attribute.Bool("cache.stored", true))
	s.logger.DebugContext(ctx, "Stored cached policy results",
		"check_type", checkType,
		"key", key,
		"ttl", ttl.String(),
	)

	return nil
}

// DeletePStates deletes all states related to a given repository context.
func (s *StateService) DeletePStates(ctx context.Context, owner, repo, sha string) error {
	repoCtx := RepoContext{Owner: owner, Repo: repo, SHA: sha}
	keys := []string{
		fmt.Sprintf("%s:%s:%s:%s", repoCtx.Owner, repoCtx.Repo, StateKeyPR, repoCtx.SHA),
		fmt.Sprintf("%s:%s:%s:%s", repoCtx.Owner, repoCtx.Repo, StateKeyVulnCheck, repoCtx.SHA),
		fmt.Sprintf("%s:%s:%s:%s", repoCtx.Owner, repoCtx.Repo, StateKeyLicenseCheck, repoCtx.SHA),
		fmt.Sprintf("%s:%s:%s:%s", repoCtx.Owner, repoCtx.Repo, StateKeyWorkflow, repoCtx.SHA),
	}

	for _, key := range keys {
		if err := s.store.Delete(ctx, key); err != nil {
			return err
		}
	}

	return nil
}

// GetAllState retrieves all state information for a given repository context as a map.
func (s *StateService) GetAllState(
	ctx context.Context,
	owner, repo, sha string,
) (*StateMap, error) {
	tracer := otel.Tracer("polly/services")

	ctx, span := tracer.Start(ctx, "state.get_all_state")
	defer span.End()

	span.SetAttributes(
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.String("github.sha", sha),
	)

	stateMap := &StateMap{}

	// Get PR Number
	if prNumber, exists, err := s.GetPRNumber(ctx, owner, repo, sha); err != nil {
		return nil, fmt.Errorf("failed to get PR number: %w", err)
	} else if exists {
		stateMap.PRNumber = prNumber
		stateMap.HasPRNumber = true
	}

	// Get Vulnerability Check ID
	if vulnCheckID, exists, err := s.GetVulnerabilityCheckRunID(ctx, owner, repo, sha); err != nil {
		return nil, fmt.Errorf("failed to get vulnerability check ID: %w", err)
	} else if exists {
		stateMap.VulnerabilityCheckID = vulnCheckID
		stateMap.HasVulnerabilityCheck = true
	}

	// Get License Check ID
	if licenseCheckID, exists, err := s.GetLicenseCheckRunID(ctx, owner, repo, sha); err != nil {
		return nil, fmt.Errorf("failed to get license check ID: %w", err)
	} else if exists {
		stateMap.LicenseCheckID = licenseCheckID
		stateMap.HasLicenseCheck = true
	}

	// Get Workflow Run ID
	if workflowRunID, exists, err := s.GetWorkflowRunID(ctx, owner, repo, sha); err != nil {
		return nil, fmt.Errorf("failed to get workflow run ID: %w", err)
	} else if exists {
		stateMap.WorkflowRunID = workflowRunID
		stateMap.HasWorkflowRun = true
	}

	span.SetAttributes(
		attribute.Bool("state.has_pr_number", stateMap.HasPRNumber),
		attribute.Bool("state.has_vulnerability_check", stateMap.HasVulnerabilityCheck),
		attribute.Bool("state.has_license_check", stateMap.HasLicenseCheck),
		attribute.Bool("state.has_workflow_run", stateMap.HasWorkflowRun),
	)

	return stateMap, nil
}

// Close closes the state service, releasing any resources it holds.
func (s *StateService) Close() error {
	return s.store.Close()
}
