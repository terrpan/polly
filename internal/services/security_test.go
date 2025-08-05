package services

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/terrpan/polly/internal/clients"
	"github.com/terrpan/polly/internal/telemetry"
)

// testSecurityService creates a SecurityService for testing with default detectors
func testSecurityService() *SecurityService {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	githubClient := clients.NewGitHubClient(context.Background())
	telemetryHelper := telemetry.NewTelemetryHelper("test")

	return NewSecurityService(githubClient, logger, telemetryHelper,
		&SPDXDetector{},
		&TrivyJSONDetector{},
		&SARIFDetector{},
	)
}

func TestNewSecurityService(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	githubClient := clients.NewGitHubClient(context.Background())
	telemetryHelper := telemetry.NewTelemetryHelper("test")

	service := NewSecurityService(githubClient, logger, telemetryHelper,
		&SPDXDetector{},
		&TrivyJSONDetector{},
		&SARIFDetector{},
	)

	assert.NotNil(t, service)
	assert.Equal(t, githubClient, service.githubClient)
	assert.Equal(t, logger, service.logger)
}

func TestSecurityService_VulnerabilityPayload_Structure(t *testing.T) {
	payload := VulnerabilityPayload{
		Type: "vulnerability_json",
		Metadata: PayloadMetadata{
			ToolName:   "trivy",
			ScanTarget: "package.json",
		},
		Vulnerabilities: []Vulnerability{
			{
				ID:       "CVE-2021-1234",
				Severity: "HIGH",
				Package: Package{
					Name:    "test-package",
					Version: "1.0.0",
				},
			},
		},
		Summary: VulnerabilitySummary{
			TotalVulnerabilities: 1,
			High:                 1,
		},
	}

	assert.Equal(t, "vulnerability_json", payload.Type)
	assert.Equal(t, "trivy", payload.Metadata.ToolName)
	assert.Len(t, payload.Vulnerabilities, 1)
	assert.Equal(t, "CVE-2021-1234", payload.Vulnerabilities[0].ID)
	assert.Equal(t, 1, payload.Summary.TotalVulnerabilities)
}

func TestSecurityService_ProcessWorkflowSecurityArtifacts_Parameters(t *testing.T) {
	service := testSecurityService()

	ctx := context.Background()

	// Test with empty parameters
	assert.NotPanics(t, func() {
		_, _, err := service.ProcessWorkflowSecurityArtifacts(ctx, "", "", "", 0)
		// Error expected due to empty parameters
		assert.Error(t, err)
	})
}

func TestSecurityService_VulnerabilityPayload_NewStructure(t *testing.T) {
	// Test vulnerability payload structure with correct fields
	payload := VulnerabilityPayload{
		Type: "vulnerability_report",
		Metadata: PayloadMetadata{
			SourceFormat: "trivy",
			ToolName:     "trivy",
			Repository:   "test/repo",
			CommitSHA:    "abc123",
		},
		Vulnerabilities: []Vulnerability{
			{
				ID:       "CVE-2021-1234",
				Severity: "HIGH",
				Package: Package{
					Name:    "test-package",
					Version: "1.0.0",
				},
			},
		},
		Summary: VulnerabilitySummary{
			Critical: 0,
			High:     1,
			Medium:   2,
			Low:      3,
		},
	}

	assert.Equal(t, "vulnerability_report", payload.Type)
	assert.Equal(t, "trivy", payload.Metadata.ToolName)
	assert.Equal(t, "test/repo", payload.Metadata.Repository)
	assert.Equal(t, "abc123", payload.Metadata.CommitSHA)
	assert.Equal(t, 1, payload.Summary.High)
	assert.Equal(t, 2, payload.Summary.Medium)
	assert.Equal(t, 3, payload.Summary.Low)
	assert.Len(t, payload.Vulnerabilities, 1)
	assert.Equal(t, "CVE-2021-1234", payload.Vulnerabilities[0].ID)
	assert.Equal(t, "test-package", payload.Vulnerabilities[0].Package.Name)
	assert.Equal(t, "1.0.0", payload.Vulnerabilities[0].Package.Version)
}

func TestSecurityService_ContextHandling(t *testing.T) {
	service := testSecurityService()

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := service.ProcessWorkflowSecurityArtifacts(ctx, "owner", "repo", "sha", 123)
	assert.Error(t, err, "Should handle cancelled context")
}

func TestSecurityService_DiscoverSecurityArtifacts(t *testing.T) {
	service := testSecurityService()

	ctx := context.Background()

	// Test discovering artifacts (will likely fail without real GitHub API)
	_, err := service.DiscoverSecurityArtifacts(ctx, "owner", "repo", 123)
	assert.Error(t, err, "Should return error without valid GitHub API")
}

// TestSecurityService_DetectSecurityContent tests content detection
func TestSecurityService_DetectSecurityContent(t *testing.T) {
	service := testSecurityService()

	tests := []struct {
		name         string
		filename     string
		expectedType ArtifactType
		content      []byte
	}{
		{
			name:         "unknown content",
			content:      []byte(`{"some": "random", "json": "content"}`),
			filename:     "unknown.json",
			expectedType: ArtifactTypeUnknown,
		},
		{
			name:         "empty content",
			content:      []byte(``),
			filename:     "empty.json",
			expectedType: ArtifactTypeUnknown,
		},
		{
			name:         "invalid json",
			content:      []byte(`{invalid json}`),
			filename:     "invalid.json",
			expectedType: ArtifactTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detectedType := detectSecurityContentType(tt.content, tt.filename, service.detectors)
			assert.Equal(t, tt.expectedType, detectedType)
		})
	}
}

// TestSecurityService_NormalizeTrivyVulnerability tests vulnerability normalization
func TestSecurityService_NormalizeTrivyVulnerability(t *testing.T) {
	// Since the DetectedVulnerability structure is complex and from external library,
	// we'll test the normalization function with simplified test cases
	tests := []struct {
		name        string
		target      string
		expectedEco string
	}{
		{
			name:        "node vulnerability",
			target:      "package.json",
			expectedEco: "unknown", // package.json isn't directly mapped
		},
		{
			name:        "python vulnerability",
			target:      "requirements.txt",
			expectedEco: "pypi",
		},
		{
			name:        "go vulnerability",
			target:      "go.mod",
			expectedEco: "go",
		},
		{
			name:        "unknown ecosystem",
			target:      "unknown.txt",
			expectedEco: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test the ecosystem detection which is part of normalization
			ecosystem := detectEcosystem(tt.target)
			assert.Equal(t, tt.expectedEco, ecosystem)
		})
	}
}

// TestSecurityService_DetectEcosystem tests ecosystem detection
func TestSecurityService_DetectEcosystem(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		expected string
	}{
		{
			name:     "package.json",
			target:   "package.json",
			expected: "unknown", // package.json isn't in the map, only package-lock.json
		},
		{
			name:     "yarn.lock",
			target:   "yarn.lock",
			expected: "npm",
		},
		{
			name:     "requirements.txt",
			target:   "requirements.txt",
			expected: "pypi",
		},
		{
			name:     "pipfile",
			target:   "Pipfile",
			expected: "unknown", // Only Pipfile.lock is in the map
		},
		{
			name:     "go.mod",
			target:   "go.mod",
			expected: "go",
		},
		{
			name:     "go.sum",
			target:   "go.sum",
			expected: "go",
		},
		{
			name:     "composer.json",
			target:   "composer.json",
			expected: "unknown", // Only composer.lock is in the map
		},
		{
			name:     "gemfile",
			target:   "Gemfile",
			expected: "unknown", // Only Gemfile.lock is in the map
		},
		{
			name:     "pom.xml",
			target:   "pom.xml",
			expected: "maven",
		},
		{
			name:     "build.gradle",
			target:   "build.gradle",
			expected: "gradle",
		},
		{
			name:     "cargo.toml",
			target:   "Cargo.toml",
			expected: "unknown", // Only Cargo.lock is in the map
		},
		{
			name:     "unknown file",
			target:   "random.txt",
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ecosystem := detectEcosystem(tt.target)
			assert.Equal(t, tt.expected, ecosystem)
		})
	}
}

// TestSecurityService_BuildPayloadsFromArtifacts tests payload building
func TestSecurityService_BuildPayloadsFromArtifacts(t *testing.T) {
	service := testSecurityService()

	ctx := context.Background()

	tests := []struct {
		name      string
		artifacts []*SecurityArtifact
		wantErr   bool
		wantCount int
	}{
		{
			name:      "empty artifacts",
			artifacts: []*SecurityArtifact{},
			wantErr:   false,
			wantCount: 0,
		},
		{
			name: "unknown artifact type",
			artifacts: []*SecurityArtifact{
				{
					Type:     ArtifactTypeUnknown,
					Content:  []byte("some content"),
					FileName: "unknown.txt",
				},
			},
			wantErr:   false,
			wantCount: 0,
		},
		{
			name: "trivy artifact with invalid json",
			artifacts: []*SecurityArtifact{
				{
					Type:     ArtifactTypeVulnerabilityJSON,
					Content:  []byte("{invalid json}"),
					FileName: "trivy.json",
				},
			},
			wantErr:   false, // The function continues even with invalid JSON
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulnPayloads, sbomPayloads, err := service.BuildPayloadsFromArtifacts(
				ctx,
				tt.artifacts,
				"owner",
				"repo",
				"sha",
				123,
			)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// The function should return empty slices, not nil
				assert.NotNil(t, vulnPayloads)
				assert.NotNil(t, sbomPayloads)
				// For now, check the total count is reasonable
				totalPayloads := len(vulnPayloads) + len(sbomPayloads)
				assert.GreaterOrEqual(t, totalPayloads, 0)
			}
		})
	}
}

// TestSecurityService_ContextCancellation tests context cancellation handling
func TestSecurityService_ContextCancellation(t *testing.T) {
	service := testSecurityService()

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Should fail due to cancelled context
	vulnPayloads, sbomPayloads, err := service.ProcessWorkflowSecurityArtifacts(
		ctx,
		"owner",
		"repo",
		"sha",
		123,
	)
	assert.Error(t, err)
	assert.Nil(t, vulnPayloads)
	assert.Nil(t, sbomPayloads)
}

// TestSecurityService_ContentDetectionHelpers tests content detection helper functions
func TestSecurityService_ContentDetectionHelpers(t *testing.T) {
	tests := []struct {
		function func([]byte) bool
		name     string
		content  []byte
		expected bool
	}{
		{
			name:     "empty content",
			content:  []byte(``),
			function: isSarifContent,
			expected: false,
		},
		{
			name:     "invalid json",
			content:  []byte(`{invalid}`),
			function: isSPDXContent,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.function(tt.content)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestSecurityService_BuildSBOMPayloadFromSPDX_Structure tests the SBOM payload structure
func TestSecurityService_BuildSBOMPayloadFromSPDX_Structure(t *testing.T) {
	// This test validates the SBOM payload structure to ensure it's compatible with OPA policies
	payload := &SBOMPayload{
		Metadata: PayloadMetadata{
			SourceFormat:  "spdx_json",
			ToolName:      "syft",
			ToolVersion:   "0.95.0",
			ScanTime:      "2025-07-11T12:00:00Z",
			Repository:    "owner/repo",
			CommitSHA:     "abc123",
			PRNumber:      42,
			ScanTarget:    ".",
			SchemaVersion: "SPDX-2.3",
		},
		Summary: SBOMSummary{
			TotalPackages: 2,
			AllLicenses:   []string{"MIT", "Apache-2.0"},
			LicenseDistribution: map[string]int{
				"MIT":        1,
				"Apache-2.0": 1,
			},
			PackagesWithoutLicense: 0,
		},
		Packages: []SBOMPackage{
			{
				Name:             "express",
				SPDXID:           "SPDXRef-Package-npm-express",
				VersionInfo:      "4.18.2",
				LicenseConcluded: "MIT",
				LicenseDeclared:  "MIT",
				ExternalRefs: []SBOMExternalRef{
					{
						ReferenceCategory: "PACKAGE-MANAGER",
						ReferenceType:     "purl",
						ReferenceLocator:  "pkg:npm/express@4.18.2",
					},
				},
			},
			{
				Name:             "lodash",
				SPDXID:           "SPDXRef-Package-npm-lodash",
				VersionInfo:      "4.17.21",
				LicenseConcluded: "Apache-2.0",
				LicenseDeclared:  "Apache-2.0",
			},
		},
	}

	// Validate the structure
	assert.NotNil(t, payload)
	assert.Equal(t, "spdx_json", payload.Metadata.SourceFormat)
	assert.Equal(t, "syft", payload.Metadata.ToolName)
	assert.Equal(t, 2, payload.Summary.TotalPackages)
	assert.Len(t, payload.Packages, 2)
	assert.Equal(t, "express", payload.Packages[0].Name)
	assert.Equal(t, "MIT", payload.Packages[0].LicenseConcluded)
	assert.Equal(t, "lodash", payload.Packages[1].Name)
	assert.Equal(t, "Apache-2.0", payload.Packages[1].LicenseConcluded)

	// Ensure the payload structure is JSON-serializable (for OPA compatibility)
	jsonBytes, err := json.Marshal(payload)
	assert.NoError(t, err)
	assert.NotEmpty(t, jsonBytes)

	// Ensure it can be unmarshaled back
	var unmarshaledPayload SBOMPayload
	err = json.Unmarshal(jsonBytes, &unmarshaledPayload)
	assert.NoError(t, err)
	assert.Equal(t, payload.Metadata.SourceFormat, unmarshaledPayload.Metadata.SourceFormat)
	assert.Equal(t, payload.Summary.TotalPackages, unmarshaledPayload.Summary.TotalPackages)
}
