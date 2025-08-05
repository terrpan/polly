package handlers

import (
	"context"
	"github.com/terrpan/polly/internal/telemetry"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/storage"
)

// SecurityCheckManagerTestSuite provides test suite for SecurityCheckManager
type SecurityCheckManagerTestSuite struct {
	suite.Suite
	ctx          context.Context
	logger       *slog.Logger
	manager      *SecurityCheckManager
	stateService *services.StateService
}

func (suite *SecurityCheckManagerTestSuite) SetupTest() {
	suite.ctx = context.Background()
	suite.logger = slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
	)

	// Create mock services
	githubClient := clients.NewGitHubClient(suite.ctx)
	store := storage.NewMemoryStore()

	checkService := services.NewCheckService(githubClient, suite.logger, telemetry.NewTelemetryHelper("test"))
	suite.stateService = services.NewStateService(store, suite.logger, telemetry.NewTelemetryHelper("test"))

	// Create security check manager
	suite.manager = NewSecurityCheckManager(suite.logger, checkService, suite.stateService)
}

func TestSecurityCheckManagerTestSuite(t *testing.T) {
	suite.Run(t, new(SecurityCheckManagerTestSuite))
}

func (suite *SecurityCheckManagerTestSuite) TestNewSecurityCheckManager() {
	suite.T().Run("creates manager successfully", func(t *testing.T) {
		manager := NewSecurityCheckManager(suite.logger, nil, suite.stateService)

		assert.NotNil(t, manager)
		assert.NotNil(t, manager.logger)
		assert.NotNil(t, manager.stateService)
		assert.NotNil(t, manager.tracingHelper)
	})
}

func (suite *SecurityCheckManagerTestSuite) TestCreateSecurityCheckRuns() {
	suite.T().Run("creates security check runs", func(t *testing.T) {
		// This will try to make GitHub API calls which will fail in tests
		err := suite.manager.CreateSecurityCheckRuns(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
			123,
		)

		// Expect error due to failed GitHub API calls
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create")
	})

	suite.T().Run("handles invalid parameters gracefully", func(t *testing.T) {
		// Test with empty parameters
		err := suite.manager.CreateSecurityCheckRuns(suite.ctx, "", "", "", 0)

		// Should still try to create checks and fail with API error
		assert.Error(t, err)
	})
}

func (suite *SecurityCheckManagerTestSuite) TestCompleteSecurityChecksAsNeutral() {
	suite.T().Run("completes checks as neutral when no check runs exist", func(t *testing.T) {
		// This should not error even if no check runs exist
		err := suite.manager.CompleteSecurityChecksAsNeutral(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
		)

		// Should not return error - method handles missing check runs gracefully
		assert.NoError(t, err)
	})

	suite.T().Run("completes checks as neutral with existing check runs", func(t *testing.T) {
		// First store some check run IDs
		err := suite.stateService.StoreVulnerabilityCheckRunID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
			12345,
		)
		require.NoError(suite.T(), err)

		err = suite.stateService.StoreLicenseCheckRunID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
			67890,
		)
		require.NoError(suite.T(), err)

		// Now try to complete them as neutral - this will fail GitHub API calls but should handle gracefully
		err = suite.manager.CompleteSecurityChecksAsNeutral(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
		)

		// Should not return error - method handles API failures gracefully
		assert.NoError(t, err)
	})
}

func (suite *SecurityCheckManagerTestSuite) TestFindVulnerabilityCheckRun() {
	suite.T().Run("returns zero when no check run exists", func(t *testing.T) {
		checkRunID, err := suite.manager.findVulnerabilityCheckRun(
			suite.ctx,
			"test-owner",
			"test-repo",
			"nonexistent-sha",
		)

		assert.NoError(t, err)
		assert.Equal(t, int64(0), checkRunID)
	})

	suite.T().Run("returns check run ID when it exists", func(t *testing.T) {
		// Store a vulnerability check run ID
		expectedID := int64(98765)
		err := suite.stateService.StoreVulnerabilityCheckRunID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
			expectedID,
		)
		require.NoError(suite.T(), err)

		// Find the check run
		checkRunID, err := suite.manager.findVulnerabilityCheckRun(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
		)

		assert.NoError(t, err)
		assert.Equal(t, expectedID, checkRunID)
	})
}

func (suite *SecurityCheckManagerTestSuite) TestFindLicenseCheckRun() {
	suite.T().Run("returns zero when no check run exists", func(t *testing.T) {
		checkRunID, err := suite.manager.findLicenseCheckRun(
			suite.ctx,
			"test-owner",
			"test-repo",
			"nonexistent-sha",
		)

		assert.NoError(t, err)
		assert.Equal(t, int64(0), checkRunID)
	})

	suite.T().Run("returns check run ID when it exists", func(t *testing.T) {
		// Store a license check run ID
		expectedID := int64(54321)
		err := suite.stateService.StoreLicenseCheckRunID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
			expectedID,
		)
		require.NoError(suite.T(), err)

		// Find the check run
		checkRunID, err := suite.manager.findLicenseCheckRun(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
		)

		assert.NoError(t, err)
		assert.Equal(t, expectedID, checkRunID)
	})
}

func (suite *SecurityCheckManagerTestSuite) TestGetSecurityCheckTypes() {
	suite.T().Run("returns configured check types", func(t *testing.T) {
		checkTypes := suite.manager.getSecurityCheckTypes(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
		)

		assert.Len(t, checkTypes, 2)

		// Verify we have both vulnerability and license check types
		var hasVuln, hasLicense bool

		for _, ct := range checkTypes {
			if ct.name == "vulnerability" {
				hasVuln = true
			}

			if ct.name == "license" {
				hasLicense = true
			}
		}

		assert.True(t, hasVuln, "Should have vulnerability check type")
		assert.True(t, hasLicense, "Should have license check type")
	})
}

func (suite *SecurityCheckManagerTestSuite) TestCompleteVulnerabilityCheckAsNeutral() {
	suite.T().Run("handles missing vulnerability check gracefully", func(t *testing.T) {
		err := suite.manager.completeVulnerabilityCheckAsNeutral(
			suite.ctx,
			"test-owner",
			"test-repo",
			"nonexistent-sha",
		)

		// Should not error when no check run exists
		assert.NoError(t, err)
	})

	suite.T().Run("attempts to complete existing vulnerability check", func(t *testing.T) {
		// Store a vulnerability check run ID
		checkRunID := int64(11111)
		err := suite.stateService.StoreVulnerabilityCheckRunID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
			checkRunID,
		)
		require.NoError(suite.T(), err)

		// Try to complete it - this will fail GitHub API call but method should handle it
		err = suite.manager.completeVulnerabilityCheckAsNeutral(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
		)

		// Will return API error since we're not mocking the GitHub client
		assert.Error(t, err)
	})
}

func (suite *SecurityCheckManagerTestSuite) TestCompleteLicenseCheckAsNeutral() {
	suite.T().Run("handles missing license check gracefully", func(t *testing.T) {
		err := suite.manager.completeLicenseCheckAsNeutral(
			suite.ctx,
			"test-owner",
			"test-repo",
			"nonexistent-sha",
		)

		// Should not error when no check run exists
		assert.NoError(t, err)
	})

	suite.T().Run("attempts to complete existing license check", func(t *testing.T) {
		// Store a license check run ID
		checkRunID := int64(22222)
		err := suite.stateService.StoreLicenseCheckRunID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
			checkRunID,
		)
		require.NoError(suite.T(), err)

		// Try to complete it - this will fail GitHub API call but method should handle it
		err = suite.manager.completeLicenseCheckAsNeutral(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
		)

		// Will return API error since we're not mocking the GitHub client
		assert.Error(t, err)
	})
}

func (suite *SecurityCheckManagerTestSuite) TestStateServiceIntegration() {
	suite.T().Run("can store and retrieve check run IDs", func(t *testing.T) {
		vulnID := int64(111)
		licenseID := int64(222)

		// Store check run IDs using the manager's storeCheckRunID helper
		suite.manager.storeCheckRunID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
			vulnID,
			"vulnerability",
			suite.stateService.StoreVulnerabilityCheckRunID,
		)
		suite.manager.storeCheckRunID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
			licenseID,
			"license",
			suite.stateService.StoreLicenseCheckRunID,
		)

		// Verify they can be retrieved
		retrievedVulnID, vulnExists, err := suite.stateService.GetVulnerabilityCheckRunID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
		)
		assert.NoError(t, err)
		assert.True(t, vulnExists)
		assert.Equal(t, vulnID, retrievedVulnID)

		retrievedLicenseID, licenseExists, err := suite.stateService.GetLicenseCheckRunID(
			suite.ctx,
			"test-owner",
			"test-repo",
			"test-sha",
		)
		assert.NoError(t, err)
		assert.True(t, licenseExists)
		assert.Equal(t, licenseID, retrievedLicenseID)
	})
}

// Simple unit tests for SecurityCheckManager
func TestNewSecurityCheckManager_Unit(t *testing.T) {
	t.Run("creates manager with valid dependencies", func(t *testing.T) {
		logger := slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
		)
		store := storage.NewMemoryStore()
		stateService := services.NewStateService(store, logger, telemetry.NewTelemetryHelper("test"))

		manager := NewSecurityCheckManager(logger, nil, stateService)

		assert.NotNil(t, manager)
		assert.Equal(t, logger, manager.logger)
		assert.Equal(t, stateService, manager.stateService)
		assert.NotNil(t, manager.tracingHelper)
	})

	t.Run("handles nil logger gracefully", func(t *testing.T) {
		store := storage.NewMemoryStore()
		logger := slog.New(
			slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
		)
		stateService := services.NewStateService(store, logger, telemetry.NewTelemetryHelper("test"))

		manager := NewSecurityCheckManager(nil, nil, stateService)

		assert.NotNil(t, manager)
		assert.Nil(t, manager.logger)
	})
}
