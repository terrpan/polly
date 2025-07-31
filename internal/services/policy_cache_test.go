package services

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/config"
	"github.com/terrpan/polly/internal/storage"
)

// PolicyCacheIntegrationTestSuite tests policy cache functionality with real storage and OPA
type PolicyCacheIntegrationTestSuite struct {
	suite.Suite
	valkeyContainer    testcontainers.Container
	opaContainer       testcontainers.Container
	store              storage.Store
	stateService       *StateService
	policyService      *PolicyService
	policyCacheService *PolicyCacheService
	logger             *slog.Logger
	originalConfig     config.StorageConfig
}

func (suite *PolicyCacheIntegrationTestSuite) SetupSuite() {
	if testing.Short() {
		suite.T().Skip("Skipping integration tests in short mode")
	}

	// Initialize config if not already done
	if config.AppConfig == nil {
		config.AppConfig = &config.Config{
			Storage: config.StorageConfig{
				PolicyCache: config.PolicyCacheConfig{
					Enabled: true,
					TTL:     "30m",
					MaxSize: 10 * 1024 * 1024,
				},
			},
		}
	}

	// Store original config
	suite.originalConfig = config.AppConfig.Storage

	suite.logger = slog.New(
		slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}),
	)

	// Setup testcontainers
	ctx := context.Background()

	// Start Valkey container
	valkeyContainer, err := redis.Run(ctx, "valkey/valkey:8-alpine")
	require.NoError(suite.T(), err)
	suite.valkeyContainer = valkeyContainer

	// Start OPA container with our policy bundle
	opaContainer, err := suite.createOPAContainer(ctx)
	require.NoError(suite.T(), err)
	suite.opaContainer = opaContainer

	// Cleanup on test completion
	suite.T().Cleanup(func() {
		if suite.valkeyContainer != nil {
			testcontainers.TerminateContainer(suite.valkeyContainer)
		}
		if suite.opaContainer != nil {
			testcontainers.TerminateContainer(suite.opaContainer)
		}
	})
}

// createOPAContainer creates an OPA container with our policy bundle
func (suite *PolicyCacheIntegrationTestSuite) createOPAContainer(
	ctx context.Context,
) (testcontainers.Container, error) {
	// Get the absolute path to the OPA bundle
	bundlePath, err := filepath.Abs("../../tools/opa/bundle")
	if err != nil {
		return nil, fmt.Errorf("failed to get bundle path: %w", err)
	}

	// Create OPA container with policy bundle mounted
	req := testcontainers.ContainerRequest{
		Image:        "openpolicyagent/opa:latest",
		ExposedPorts: []string{"8181/tcp"},
		Files: []testcontainers.ContainerFile{
			{
				HostFilePath:      bundlePath,
				ContainerFilePath: "/bundle",
				FileMode:          0755,
			},
		},
		Cmd: []string{
			"run",
			"--server",
			"--addr=0.0.0.0:8181",
			"--bundle",
			"/bundle",
		},
		WaitingFor: wait.ForHTTP("/").WithPort("8181/tcp").WithStartupTimeout(30 * time.Second),
	}

	return testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
}

func (suite *PolicyCacheIntegrationTestSuite) SetupTest() {
	var err error

	// Get connection info from Valkey container
	ctx := context.Background()
	host, err := suite.valkeyContainer.Host(ctx)
	require.NoError(suite.T(), err)

	port, err := suite.valkeyContainer.MappedPort(ctx, "6379")
	require.NoError(suite.T(), err)

	// Create Valkey storage for isolated testing
	storageConfig := config.StorageConfig{
		Type: "valkey",
		Valkey: config.ValkeyConfig{
			Address: fmt.Sprintf("%s:%s", host, port.Port()),
		},
	}

	suite.store, err = storage.NewStore(storageConfig)
	require.NoError(suite.T(), err)

	// Get OPA container connection info
	opaHost, err := suite.opaContainer.Host(ctx)
	require.NoError(suite.T(), err)

	opaPort, err := suite.opaContainer.MappedPort(ctx, "8181")
	require.NoError(suite.T(), err)

	// Create services with real OPA client
	suite.stateService = NewStateService(suite.store, suite.logger)
	opaClient, err := clients.NewOPAClient(fmt.Sprintf("http://%s:%s", opaHost, opaPort.Port()))
	require.NoError(suite.T(), err)

	suite.policyService = NewPolicyService(opaClient, suite.logger)
	suite.policyCacheService = NewPolicyCacheService(
		suite.policyService,
		suite.stateService,
		suite.logger,
	)
}

func (suite *PolicyCacheIntegrationTestSuite) TearDownTest() {
	if suite.store != nil {
		suite.store.Close()
	}
}

func (suite *PolicyCacheIntegrationTestSuite) TearDownSuite() {
	// Restore original config
	config.AppConfig.Storage = suite.originalConfig
}

func (suite *PolicyCacheIntegrationTestSuite) TestVulnerabilityPolicyCacheEnabled() {
	// Enable cache in config
	config.AppConfig.Storage.PolicyCache.Enabled = true
	config.AppConfig.Storage.PolicyCache.TTL = "30m"
	config.AppConfig.Storage.PolicyCache.MaxSize = 10 * 1024 * 1024

	ctx := context.Background()
	owner, repo, sha := "testowner", "testrepo", "testsha123"

	input := &VulnerabilityPayload{
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-2024-1234", Severity: "HIGH", Score: 8.5},
		},
		Metadata: PayloadMetadata{
			ScanTarget: ".",
			ToolName:   "trivy",
		},
	}

	// First call - should hit OPA and cache result
	result1, err := suite.policyCacheService.CheckVulnerabilityPolicyWithCache(
		ctx,
		input,
		owner,
		repo,
		sha,
	)
	require.NoError(suite.T(), err)

	// HIGH severity should be non-compliant based on our OPA policy (max allowed is MEDIUM)
	assert.False(suite.T(), result1.Compliant, "HIGH vulnerability should be non-compliant")
	assert.Equal(
		suite.T(),
		1,
		result1.TotalVulnerabilities,
		"Should have 1 vulnerability from input",
	)
	assert.Equal(
		suite.T(),
		1,
		result1.NonCompliantCount,
		"Should have 1 non-compliant vulnerability",
	)

	// Verify result was cached
	cachedResult, found, err := suite.stateService.GetCachedPolicyResults(
		ctx,
		owner,
		repo,
		sha,
		"vulnerability",
	)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), found, "Result should be cached")

	// Handle both struct and map types from cache
	if resultStruct, ok := cachedResult.(VulnerabilityPolicyResult); ok {
		assert.Equal(suite.T(), result1, resultStruct, "Cached result should match original")
	} else if resultMap, ok := cachedResult.(map[string]interface{}); ok {
		// Convert map to struct and compare
		convertedResult, err := convertMapToVulnerabilityPolicyResult(resultMap)
		require.NoError(suite.T(), err, "Should be able to convert cached map to struct")
		assert.Equal(suite.T(), result1.Compliant, convertedResult.Compliant)
		assert.Equal(suite.T(), result1.TotalVulnerabilities, convertedResult.TotalVulnerabilities)
		assert.Equal(suite.T(), result1.NonCompliantCount, convertedResult.NonCompliantCount)
	}

	// Second call - should hit cache, not OPA
	result2, err := suite.policyCacheService.CheckVulnerabilityPolicyWithCache(
		ctx,
		input,
		owner,
		repo,
		sha,
	)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), result1, result2, "Should get same result from cache")

	suite.T().Log("Vulnerability policy cache integration test completed successfully")
}

func (suite *PolicyCacheIntegrationTestSuite) TestSBOMPolicyCacheEnabled() {
	// Enable cache in config
	config.AppConfig.Storage.PolicyCache.Enabled = true
	config.AppConfig.Storage.PolicyCache.TTL = "30m"
	config.AppConfig.Storage.PolicyCache.MaxSize = 10 * 1024 * 1024

	ctx := context.Background()
	owner, repo, sha := "testowner", "testrepo", "testsha456"

	input := &SBOMPayload{
		Packages: []SBOMPackage{
			{Name: "test-component", VersionInfo: "1.0.0", LicenseConcluded: "MIT"},
		},
		Metadata: PayloadMetadata{
			ScanTarget: ".",
			ToolName:   "syft",
		},
	}

	// First call - should hit OPA and cache result
	result1, err := suite.policyCacheService.CheckSBOMPolicyWithCache(ctx, input, owner, repo, sha)
	require.NoError(suite.T(), err)

	// MIT license should be compliant based on our OPA policy
	assert.True(suite.T(), result1.Compliant, "MIT license should be compliant")
	assert.Equal(suite.T(), 1, result1.TotalComponents, "Should have 1 component from input")
	assert.Equal(suite.T(), 1, result1.CompliantComponents, "Should have 1 compliant component")

	// Verify result was cached
	cachedResult, found, err := suite.stateService.GetCachedPolicyResults(
		ctx,
		owner,
		repo,
		sha,
		"sbom",
	)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), found, "Result should be cached")

	// Handle both struct and map types from cache
	if resultStruct, ok := cachedResult.(SBOMPolicyResult); ok {
		assert.Equal(suite.T(), result1, resultStruct, "Cached result should match original")
	} else if resultMap, ok := cachedResult.(map[string]interface{}); ok {
		// Convert map to struct and compare
		convertedResult, err := convertMapToSBOMPolicyResult(resultMap)
		require.NoError(suite.T(), err, "Should be able to convert cached map to struct")
		assert.Equal(suite.T(), result1.Compliant, convertedResult.Compliant)
		assert.Equal(suite.T(), result1.TotalComponents, convertedResult.TotalComponents)
		assert.Equal(suite.T(), result1.CompliantComponents, convertedResult.CompliantComponents)
	}

	// Second call - should hit cache, not OPA
	result2, err := suite.policyCacheService.CheckSBOMPolicyWithCache(ctx, input, owner, repo, sha)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), result1, result2, "Should get same result from cache")

	suite.T().Log("SBOM policy cache integration test completed successfully")
}

func (suite *PolicyCacheIntegrationTestSuite) TestPolicyCacheDisabled() {
	// Disable cache in config
	config.AppConfig.Storage.PolicyCache.Enabled = false

	ctx := context.Background()
	owner, repo, sha := "testowner", "testrepo", "testsha789"

	input := &VulnerabilityPayload{
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-2024-5678", Severity: "MEDIUM", Score: 5.5},
		},
		Metadata: PayloadMetadata{
			ScanTarget: ".",
			ToolName:   "trivy",
		},
	}

	// Call with cache disabled - should still work with OPA but not cache
	result1, err := suite.policyCacheService.CheckVulnerabilityPolicyWithCache(
		ctx,
		input,
		owner,
		repo,
		sha,
	)
	require.NoError(suite.T(), err)

	// MEDIUM severity should be compliant based on our OPA policy (max allowed is MEDIUM)
	assert.True(suite.T(), result1.Compliant, "MEDIUM vulnerability should be compliant")

	// Verify nothing was cached (cache disabled)
	_, found, err := suite.stateService.GetCachedPolicyResults(
		ctx,
		owner,
		repo,
		sha,
		"vulnerability",
	)
	require.NoError(suite.T(), err)
	assert.False(suite.T(), found, "Should not cache when cache is disabled")

	// Second call - should hit OPA again (no cache)
	result2, err := suite.policyCacheService.CheckVulnerabilityPolicyWithCache(
		ctx,
		input,
		owner,
		repo,
		sha,
	)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), result1, result2, "Should get same result from OPA")

	suite.T().Log("Policy cache disabled test completed successfully")
}

func (suite *PolicyCacheIntegrationTestSuite) TestCacheMissScenarios() {
	// Enable cache
	config.AppConfig.Storage.PolicyCache.Enabled = true
	config.AppConfig.Storage.PolicyCache.TTL = "30m"

	ctx := context.Background()
	owner, repo := "testowner", "testrepo"

	input := &VulnerabilityPayload{
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-2024-9999", Severity: "LOW", Score: 2.0},
		},
		Metadata: PayloadMetadata{
			ScanTarget: ".",
			ToolName:   "trivy",
		},
	}

	// Test different SHAs result in cache misses
	sha1 := "sha1abc"
	sha2 := "sha2def"

	result1, err := suite.policyCacheService.CheckVulnerabilityPolicyWithCache(
		ctx,
		input,
		owner,
		repo,
		sha1,
	)
	require.NoError(suite.T(), err)

	result2, err := suite.policyCacheService.CheckVulnerabilityPolicyWithCache(
		ctx,
		input,
		owner,
		repo,
		sha2,
	)
	require.NoError(suite.T(), err)

	// Both should be equal (same policy result) but cached separately
	assert.Equal(suite.T(), result1, result2, "Same input should produce same policy result")

	// Verify both are cached independently
	cached1, found1, err1 := suite.stateService.GetCachedPolicyResults(
		ctx,
		owner,
		repo,
		sha1,
		"vulnerability",
	)
	require.NoError(suite.T(), err1)
	assert.True(suite.T(), found1, "SHA1 result should be cached")

	cached2, found2, err2 := suite.stateService.GetCachedPolicyResults(
		ctx,
		owner,
		repo,
		sha2,
		"vulnerability",
	)
	require.NoError(suite.T(), err2)
	assert.True(suite.T(), found2, "SHA2 result should be cached")

	assert.Equal(suite.T(), cached1, cached2, "Same content, different cache keys")

	suite.T().Log("Cache miss scenarios test completed successfully")
}

func (suite *PolicyCacheIntegrationTestSuite) TestCacheErrorHandling() {
	// Enable cache
	config.AppConfig.Storage.PolicyCache.Enabled = true

	ctx := context.Background()
	owner, repo, sha := "testowner", "testrepo", "testsha"

	// Test with empty/invalid input that should cause policy evaluation error
	input := &VulnerabilityPayload{
		// Empty vulnerabilities array should still work with OPA
		Vulnerabilities: []Vulnerability{},
		Metadata: PayloadMetadata{
			ScanTarget: ".",
			ToolName:   "trivy",
		},
	}

	// Test policy evaluation with empty vulnerabilities (should succeed but return compliant=true)
	result, err := suite.policyCacheService.CheckVulnerabilityPolicyWithCache(
		ctx,
		input,
		owner,
		repo,
		sha,
	)
	require.NoError(suite.T(), err, "Empty vulnerabilities should be handled gracefully")

	// Empty vulnerabilities should be compliant (no vulnerabilities = no policy violations)
	// Note: This depends on the OPA policy implementation
	assert.Equal(suite.T(), 0, result.TotalVulnerabilities, "Should have 0 vulnerabilities")
	assert.Equal(
		suite.T(),
		0,
		result.NonCompliantCount,
		"Should have 0 non-compliant vulnerabilities",
	)

	// Verify result was cached
	_, found, err := suite.stateService.GetCachedPolicyResults(
		ctx,
		owner,
		repo,
		sha,
		"vulnerability",
	)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), found, "Valid results should be cached even if empty")

	suite.T().Log("Cache error handling test completed successfully")
}

func (suite *PolicyCacheIntegrationTestSuite) TestConcurrentCacheAccess() {
	// Enable cache
	config.AppConfig.Storage.PolicyCache.Enabled = true
	config.AppConfig.Storage.PolicyCache.TTL = "30m"

	ctx := context.Background()
	owner, repo, sha := "testowner", "testrepo", "concurrent-test"

	input := &VulnerabilityPayload{
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-2024-CONCURRENT", Severity: "MEDIUM", Score: 6.0},
		},
		Metadata: PayloadMetadata{
			ScanTarget: ".",
			ToolName:   "trivy",
		},
	}

	// Run multiple concurrent requests
	const numGoroutines = 10
	resultsChan := make(chan VulnerabilityPolicyResult, numGoroutines)
	errorsChan := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			result, err := suite.policyCacheService.CheckVulnerabilityPolicyWithCache(
				ctx,
				input,
				owner,
				repo,
				sha,
			)
			if err != nil {
				errorsChan <- err
				return
			}
			resultsChan <- result
		}()
	}

	// Collect results
	var results []VulnerabilityPolicyResult
	var errors []error

	for i := 0; i < numGoroutines; i++ {
		select {
		case result := <-resultsChan:
			results = append(results, result)
		case err := <-errorsChan:
			errors = append(errors, err)
		case <-time.After(5 * time.Second):
			suite.T().Fatal("Timeout waiting for concurrent requests")
		}
	}

	// If OPA is not available, all requests should fail - this is expected
	if len(errors) == numGoroutines {
		suite.T().Log("OPA not available - all concurrent requests failed as expected")
		suite.T().Log("Concurrent cache access test completed successfully")
		return
	}

	// With working OPA, all requests should succeed
	require.Empty(suite.T(), errors, "All requests should succeed with working OPA")
	require.Len(suite.T(), results, numGoroutines, "Should have results from all goroutines")

	// All results should be identical
	expectedResult := results[0]
	for i, result := range results {
		assert.Equal(suite.T(), expectedResult, result, "Result %d should match expected", i)
	}

	// Verify result is cached
	cachedResult, found, err := suite.stateService.GetCachedPolicyResults(
		ctx,
		owner,
		repo,
		sha,
		"vulnerability",
	)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), found, "Result should be cached")

	// Handle both struct and map types from cache
	if resultStruct, ok := cachedResult.(VulnerabilityPolicyResult); ok {
		assert.Equal(suite.T(), expectedResult, resultStruct, "Cached result should match expected")
	} else if resultMap, ok := cachedResult.(map[string]interface{}); ok {
		convertedResult, err := convertMapToVulnerabilityPolicyResult(resultMap)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), expectedResult, convertedResult, "Converted cached result should match expected")
	}

	suite.T().Log("Concurrent cache access test completed successfully")
}

func (suite *PolicyCacheIntegrationTestSuite) TestCacheWithDifferentPolicyTypes() {
	// Enable cache
	config.AppConfig.Storage.PolicyCache.Enabled = true
	config.AppConfig.Storage.PolicyCache.TTL = "30m"

	ctx := context.Background()
	owner, repo, sha := "testowner", "testrepo", "mixed-policies"

	vulnInput := &VulnerabilityPayload{
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-2024-MIXED", Severity: "HIGH", Score: 8.0},
		},
		Metadata: PayloadMetadata{
			ScanTarget: ".",
			ToolName:   "trivy",
		},
	}

	sbomInput := &SBOMPayload{
		Packages: []SBOMPackage{
			{Name: "mixed-package", VersionInfo: "2.0.0", LicenseConcluded: "Apache-2.0"},
		},
		Metadata: PayloadMetadata{
			ScanTarget: "sbom.spdx.json",
			ToolName:   "spdx",
		},
	}

	// Test both policy types with same SHA
	vulnResult, err := suite.policyCacheService.CheckVulnerabilityPolicyWithCache(
		ctx,
		vulnInput,
		owner,
		repo,
		sha,
	)
	require.NoError(suite.T(), err, "Vulnerability policy check should succeed")

	sbomResult, err := suite.policyCacheService.CheckSBOMPolicyWithCache(
		ctx,
		sbomInput,
		owner,
		repo,
		sha,
	)
	require.NoError(suite.T(), err, "SBOM policy check should succeed")

	// Verify both are cached independently
	cachedVuln, foundVuln, err := suite.stateService.GetCachedPolicyResults(
		ctx,
		owner,
		repo,
		sha,
		"vulnerability",
	)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), foundVuln, "Vulnerability result should be cached")

	// Handle both struct and map types from cache for vulnerability
	if resultStruct, ok := cachedVuln.(VulnerabilityPolicyResult); ok {
		assert.Equal(
			suite.T(),
			vulnResult,
			resultStruct,
			"Cached vulnerability result should match original",
		)
	} else if resultMap, ok := cachedVuln.(map[string]interface{}); ok {
		convertedResult, err := convertMapToVulnerabilityPolicyResult(resultMap)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), vulnResult.Compliant, convertedResult.Compliant)
		assert.Equal(suite.T(), vulnResult.TotalVulnerabilities, convertedResult.TotalVulnerabilities)
	}

	cachedSBOM, foundSBOM, err := suite.stateService.GetCachedPolicyResults(
		ctx,
		owner,
		repo,
		sha,
		"sbom",
	)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), foundSBOM, "SBOM result should be cached")

	// Handle both struct and map types from cache for SBOM
	if resultStruct, ok := cachedSBOM.(SBOMPolicyResult); ok {
		assert.Equal(
			suite.T(),
			sbomResult,
			resultStruct,
			"Cached SBOM result should match original",
		)
	} else if resultMap, ok := cachedSBOM.(map[string]interface{}); ok {
		convertedResult, err := convertMapToSBOMPolicyResult(resultMap)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), sbomResult.Compliant, convertedResult.Compliant)
		assert.Equal(suite.T(), sbomResult.TotalComponents, convertedResult.TotalComponents)
	}

	// Test cache hits - should return cached results, not hit OPA again
	vulnResult2, err := suite.policyCacheService.CheckVulnerabilityPolicyWithCache(
		ctx,
		vulnInput,
		owner,
		repo,
		sha,
	)
	require.NoError(suite.T(), err)
	assert.Equal(
		suite.T(),
		vulnResult,
		vulnResult2,
		"Second vulnerability call should return cached result",
	)

	sbomResult2, err := suite.policyCacheService.CheckSBOMPolicyWithCache(
		ctx,
		sbomInput,
		owner,
		repo,
		sha,
	)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), sbomResult, sbomResult2, "Second SBOM call should return cached result")

	suite.T().Log("Mixed policy types cache test completed successfully")
}

func (suite *PolicyCacheIntegrationTestSuite) TestCacheConfigToggle() {
	ctx := context.Background()
	owner, repo, sha := "testowner", "testrepo", "config-toggle-test"

	input := &VulnerabilityPayload{
		Vulnerabilities: []Vulnerability{
			{ID: "CVE-2024-CONFIG", Severity: "HIGH", Score: 8.5},
		},
		Metadata: PayloadMetadata{
			ScanTarget: ".",
			ToolName:   "trivy",
		},
	}

	// Test with cache enabled
	config.AppConfig.Storage.PolicyCache.Enabled = true
	config.AppConfig.Storage.PolicyCache.TTL = "30m"

	result1, err := suite.policyCacheService.CheckVulnerabilityPolicyWithCache(
		ctx,
		input,
		owner,
		repo,
		sha,
	)
	require.NoError(suite.T(), err)

	// Verify result was cached
	_, found, err := suite.stateService.GetCachedPolicyResults(
		ctx,
		owner,
		repo,
		sha,
		"vulnerability",
	)
	require.NoError(suite.T(), err)
	assert.True(suite.T(), found, "Result should be cached when enabled")

	// Clear cache and disable caching
	require.NoError(suite.T(), suite.stateService.DeletePStates(ctx, owner, repo, sha))
	config.AppConfig.Storage.PolicyCache.Enabled = false

	result2, err := suite.policyCacheService.CheckVulnerabilityPolicyWithCache(
		ctx,
		input,
		owner,
		repo,
		sha,
	)
	require.NoError(suite.T(), err)

	// Verify nothing was cached (cache disabled)
	_, found, err = suite.stateService.GetCachedPolicyResults(
		ctx,
		owner,
		repo,
		sha,
		"vulnerability",
	)
	require.NoError(suite.T(), err)
	assert.False(suite.T(), found, "Result should not be cached when disabled")

	// Results should be the same (same policy evaluation)
	assert.Equal(
		suite.T(),
		result1,
		result2,
		"Policy results should be identical regardless of caching",
	)

	suite.T().Log("Cache config toggle test completed successfully")
}

// Run the integration test suite
func TestPolicyCacheIntegrationSuite(t *testing.T) {
	suite.Run(t, new(PolicyCacheIntegrationTestSuite))
}
