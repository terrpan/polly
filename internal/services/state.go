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

// StateService handles state-related operations.
type StateService struct {
	store      storage.Store
	logger     *slog.Logger
	expiration time.Duration // Default expiration duration for keys
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

// storeInt64 stores an int64 value with the given key type and SHA.
// in the format "<keyType>:<sha>". Ie: "pr:abc2134f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v1w2x3y4z5 -> 42"
func (s *StateService) storeInt64(ctx context.Context, keyType StateKeyType, sha string, value int64) error {
	key := fmt.Sprintf("%s:%s", keyType, sha)
	return s.store.Set(ctx, key, value, s.expiration)
}

// getInt64 retrieves an int64 value for the given key type and SHA.
// It returns the value, a boolean indicating if the key was found, and an error if any.
func (s *StateService) getInt64(ctx context.Context, keyType StateKeyType, sha string) (int64, bool, error) {
	key := fmt.Sprintf("%s:%s", keyType, sha)
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

// deleteState deletes the state for a given key type and SHA.
func (s *StateService) deleteState(ctx context.Context, keyType StateKeyType, sha string) error {
	key := fmt.Sprintf("%s:%s", keyType, sha)
	return s.store.Delete(ctx, key)
}

// StorePRNumber stores the PR number for a given SHA.
func (s *StateService) StorePRNumber(ctx context.Context, sha string, prNumber int64) error {
	return s.storeInt64(ctx, StateKeyPR, sha, prNumber)
}

// GetPRNumber retrieves the PR number for a given SHA.
func (s *StateService) GetPRNumber(ctx context.Context, sha string) (int64, bool, error) {
	return s.getInt64(ctx, StateKeyPR, sha)
}

// StoreVulnerabilityCheckRunID stores the vulnerability check run ID for a given SHA.
func (s *StateService) StoreVulnerabilityCheckRunID(ctx context.Context, sha string, runID int64) error {
	return s.storeInt64(ctx, StateKeyVulnCheck, sha, runID)
}

// GetVulnerabilityCheckRunID retrieves the vulnerability check run ID for a given SHA.
func (s *StateService) GetVulnerabilityCheckRunID(ctx context.Context, sha string) (int64, bool, error) {
	return s.getInt64(ctx, StateKeyVulnCheck, sha)
}

// StoreLicenseCheckRunID stores the license check run ID for a given SHA.
func (s *StateService) StoreLicenseCheckRunID(ctx context.Context, sha string, runID int64) error {
	return s.storeInt64(ctx, StateKeyLicenseCheck, sha, runID)
}

// GetLicenseCheckRunID retrieves the license check run ID for a given SHA.
func (s *StateService) GetLicenseCheckRunID(ctx context.Context, sha string) (int64, bool, error) {
	return s.getInt64(ctx, StateKeyLicenseCheck, sha)
}

// StoreWorkflowRunID stores the workflow run ID for a given SHA.
func (s *StateService) StoreWorkflowRunID(ctx context.Context, sha string, runID int64) error {
	return s.storeInt64(ctx, StateKeyWorkflow, sha, runID)
}

// GetWorkflowRunID retrieves the workflow run ID for a given SHA.
func (s *StateService) GetWorkflowRunID(ctx context.Context, sha string) (int64, bool, error) {
	return s.getInt64(ctx, StateKeyWorkflow, sha)
}

// DeletePStates deletes all states related to a given SHA.
func (s *StateService) DeletePStates(ctx context.Context, sha string) error {
	keys := []string{
		fmt.Sprintf("%s:%s", StateKeyPR, sha),
		fmt.Sprintf("%s:%s", StateKeyVulnCheck, sha),
		fmt.Sprintf("%s:%s", StateKeyLicenseCheck, sha),
		fmt.Sprintf("%s:%s", StateKeyWorkflow, sha),
	}

	for _, key := range keys {
		if err := s.store.Delete(ctx, key); err != nil {
			return err
		}
	}

	return nil
}

// Close closes the state service, releasing any resources it holds.
func (s *StateService) Close() error {
	return s.store.Close()
}
