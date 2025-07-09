package handlers

import (
"context"
"testing"
"log/slog"
"os"

"github.com/stretchr/testify/assert"
"github.com/stretchr/testify/require"
"github.com/terrpan/polly/internal/clients"
"github.com/terrpan/polly/internal/services"
)

// Test helper to create test services
func createTestServices() (*services.CommentService, *services.CheckService, *services.PolicyService, *services.SecurityService) {
logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

// Create test GitHub client (will not make real API calls in tests)
githubClient := clients.NewGitHubClient(context.Background())

// Create test OPA client 
opaClient, _ := clients.NewOPAClient("http://test-opa:8181")

commentService := services.NewCommentService(githubClient, logger)
checkService := services.NewCheckService(githubClient, logger)
policyService := services.NewPolicyService(opaClient, logger)
securityService := services.NewSecurityService(githubClient, logger)

return commentService, checkService, policyService, securityService
}

func TestNewWebhookHandler(t *testing.T) {
logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
commentService, checkService, policyService, securityService := createTestServices()

handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)

require.NoError(t, err)
assert.NotNil(t, handler)
assert.Equal(t, logger, handler.logger)
}

func TestWebhookHandler_Structure(t *testing.T) {
logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
commentService, checkService, policyService, securityService := createTestServices()

handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
require.NoError(t, err)

// Test that handler has the expected structure
assert.NotNil(t, handler.commentService)
assert.NotNil(t, handler.checkService)
assert.NotNil(t, handler.policyService)
assert.NotNil(t, handler.securityService)
assert.NotNil(t, handler.prContextStore)
assert.NotNil(t, handler.vulnerabilityCheckStore)
}

func TestWebhookHandler_ServicesInitialization(t *testing.T) {
logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
commentService, checkService, policyService, securityService := createTestServices()

handler, err := NewWebhookHandler(logger, commentService, checkService, policyService, securityService)
require.NoError(t, err)

// Verify all services are properly initialized
assert.Same(t, commentService, handler.commentService)
assert.Same(t, checkService, handler.checkService)
assert.Same(t, policyService, handler.policyService)
assert.Same(t, securityService, handler.securityService)
}
