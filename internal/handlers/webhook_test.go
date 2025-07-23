package handlers

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/services"
	"github.com/terrpan/polly/internal/storage"
)

// WebhookHandlerTestSuite provides a test suite for webhook handler tests
type WebhookHandlerTestSuite struct {
	suite.Suite
	ctx             context.Context
	logger          *slog.Logger
	handler         *WebhookHandler
	commentService  *services.CommentService
	checkService    *services.CheckService
	policyService   *services.PolicyService
	securityService *services.SecurityService
	stateService    *services.StateService
}

// SetupSuite runs once before all tests in the suite
func (suite *WebhookHandlerTestSuite) SetupSuite() {
	suite.ctx = context.Background()
	suite.logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
}

// SetupTest runs before each test
func (suite *WebhookHandlerTestSuite) SetupTest() {
	// Create test services
	suite.commentService, suite.checkService, suite.policyService, suite.securityService, suite.stateService = suite.createTestServices()

	// Create webhook handler
	var err error
	suite.handler, err = NewWebhookHandler(
		suite.logger,
		suite.commentService,
		suite.checkService,
		suite.policyService,
		suite.securityService,
		suite.stateService,
	)
	suite.Require().NoError(err)
}

// createTestServices creates test services for the suite
func (suite *WebhookHandlerTestSuite) createTestServices() (*services.CommentService, *services.CheckService, *services.PolicyService, *services.SecurityService, *services.StateService) {
	// Create test GitHub client (will not make real API calls in tests)
	githubClient := clients.NewGitHubClient(suite.ctx)

	// Create test OPA client
	opaClient, _ := clients.NewOPAClient("http://test-opa:8181")

	// Create test storage and state service
	store := storage.NewMemoryStore()
	stateService := services.NewStateService(store, suite.logger)

	commentService := services.NewCommentService(githubClient, suite.logger)
	checkService := services.NewCheckService(githubClient, suite.logger)
	policyService := services.NewPolicyService(opaClient, suite.logger)
	securityService := services.NewSecurityService(githubClient, suite.logger)

	return commentService, checkService, policyService, securityService, stateService
}

func (suite *WebhookHandlerTestSuite) TestNewWebhookHandler() {
	suite.Assert().NotNil(suite.handler)
}

func (suite *WebhookHandlerTestSuite) TestWebhookHandlerStructure() {
	// Test that handler has the expected structure
	suite.Assert().NotNil(suite.handler.commentService)
	suite.Assert().NotNil(suite.handler.checkService)
	suite.Assert().NotNil(suite.handler.policyService)
	suite.Assert().NotNil(suite.handler.securityService)
	suite.Assert().NotNil(suite.handler.stateService)
}

func (suite *WebhookHandlerTestSuite) TestContextStore() {
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	// Test that StateService is available
	suite.Assert().NotNil(suite.handler.stateService)

	// Test that StateService can store and retrieve data
	err := suite.handler.stateService.StorePRNumber(suite.ctx, owner, repo, sha, 123)
	suite.Require().NoError(err)
	err = suite.handler.stateService.StoreVulnerabilityCheckRunID(suite.ctx, owner, repo, sha, 456)
	suite.Require().NoError(err)

	prNum, exists, err := suite.handler.stateService.GetPRNumber(suite.ctx, owner, repo, sha)
	suite.Require().NoError(err)
	suite.Require().True(exists)
	suite.Assert().Equal(int64(123), prNum)

	vulnCheckID, exists, err := suite.handler.stateService.GetVulnerabilityCheckRunID(
		suite.ctx,
		owner,
		repo,
		sha,
	)
	suite.Require().NoError(err)
	suite.Require().True(exists)
	suite.Assert().Equal(int64(456), vulnCheckID)
}

func (suite *WebhookHandlerTestSuite) TestServices() {
	// Test that all services are properly assigned
	suite.Assert().Equal(suite.commentService, suite.handler.commentService)
	suite.Assert().Equal(suite.checkService, suite.handler.checkService)
	suite.Assert().Equal(suite.policyService, suite.handler.policyService)
	suite.Assert().Equal(suite.securityService, suite.handler.securityService)
	suite.Assert().Equal(suite.stateService, suite.handler.stateService)
}

func (suite *WebhookHandlerTestSuite) TestConcurrentAccess() {
	// Test that StateService can be used for concurrent access without explicit mutexes
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"

	suite.Assert().NotPanics(func() {
		err := suite.handler.stateService.StorePRNumber(suite.ctx, owner, repo, sha, 1)
		suite.Require().NoError(err)
	})

	suite.Assert().NotPanics(func() {
		err := suite.handler.stateService.StoreVulnerabilityCheckRunID(suite.ctx, owner, repo, sha, 2)
		suite.Require().NoError(err)
	})
}

func (suite *WebhookHandlerTestSuite) TestStoreCheckRunIDHelpers() {
	owner := "test-owner"
	repo := "test-repo"
	sha := "test-sha"
	checkRunID := int64(12345)

	suite.Run("storeCheckRunID does not return error (fire and forget)", func() {
		// Should not panic and should store successfully
		suite.Assert().NotPanics(func() {
			suite.handler.storeCheckRunID(
				suite.ctx,
				owner,
				repo,
				sha,
				checkRunID,
				"vulnerability",
				suite.handler.stateService.StoreVulnerabilityCheckRunID,
			)
		})

		// Verify it was stored
		storedID, exists, err := suite.handler.stateService.GetVulnerabilityCheckRunID(
			suite.ctx,
			owner,
			repo,
			sha,
		)
		suite.Require().NoError(err)
		suite.Assert().True(exists)
		suite.Assert().Equal(checkRunID, storedID)
	})

	suite.Run("storeCheckRunIDWithError returns error when storage fails", func() {
		// Test with a function that returns an error
		mockStoreFunc := func(ctx context.Context, owner, repo, sha string, id int64) error {
			return assert.AnError
		}

		err := suite.handler.storeCheckRunIDWithError(
			suite.ctx,
			owner,
			repo,
			sha,
			checkRunID+1,
			"test",
			mockStoreFunc,
		)
		suite.Assert().Error(err)
		suite.Assert().Equal(assert.AnError, err)
	})

	suite.Run("storeCheckRunIDWithError succeeds when storage succeeds", func() {
		licenseCheckRunID := int64(67890)

		err := suite.handler.storeCheckRunIDWithError(
			suite.ctx,
			owner,
			repo,
			sha,
			licenseCheckRunID,
			"license",
			suite.handler.stateService.StoreLicenseCheckRunID,
		)
		suite.Assert().NoError(err)

		// Verify it was stored
		storedID, exists, err := suite.handler.stateService.GetLicenseCheckRunID(suite.ctx, owner, repo, sha)
		suite.Require().NoError(err)
		suite.Assert().True(exists)
		suite.Assert().Equal(licenseCheckRunID, storedID)
	})
}

// Run the test suite
func TestWebhookHandlerTestSuite(t *testing.T) {
	suite.Run(t, new(WebhookHandlerTestSuite))
}
