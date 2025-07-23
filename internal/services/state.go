package services

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

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
	StateKeyPR           StateKeyType = "pr"
	StateKeyVulnCheck    StateKeyType = "vulnerability_check"
	StateKeyLicenseCheck StateKeyType = "license_check"
	StateKeyWorkflow     StateKeyType = "workflow"
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
	key := fmt.Sprintf("%s:%s:%s:%s", repoCtx.Owner, repoCtx.Repo, keyType, repoCtx.SHA)
	return s.store.Set(ctx, key, value, s.expiration)
}

// getInt64 retrieves an int64 value for the given key type and repository context.
// It returns the value, a boolean indicating if the key was found, and an error if any.
func (s *StateService) getInt64(
	ctx context.Context,
	keyType StateKeyType,
	repoCtx RepoContext,
) (int64, bool, error) {
	key := fmt.Sprintf("%s:%s:%s:%s", repoCtx.Owner, repoCtx.Repo, keyType, repoCtx.SHA)
	value, err := s.store.Get(ctx, key)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			return 0, false, nil
		}
		return 0, false, err
	}

	// Handle JSON unmarshalling variations
	switch v := value.(type) {
	case int64:
		return v, true, nil
	case float64:
		return int64(v), true, nil
	case string:
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
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

	return stateMap, nil
}

// Close closes the state service, releasing any resources it holds.
func (s *StateService) Close() error {
	return s.store.Close()
}
