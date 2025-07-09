package services

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/google/go-github/v72/github"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/terrpan/polly/internal/clients"
)

// Mock GitHub Client for testing
type MockGitHubClient struct {
	mock.Mock
}

func (m *MockGitHubClient) ListWorkflowArtifacts(ctx context.Context, owner, repo string, workflowID int64) ([]*github.Artifact, error) {
	args := m.Called(ctx, owner, repo, workflowID)
	return args.Get(0).([]*github.Artifact), args.Error(1)
}

func (m *MockGitHubClient) DownloadArtifact(ctx context.Context, owner, repo string, artifactID int64) ([]byte, error) {
	args := m.Called(ctx, owner, repo, artifactID)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockGitHubClient) GetArtifact(ctx context.Context, owner, repo string, artifactID int64) (*github.Artifact, error) {
	args := m.Called(ctx, owner, repo, artifactID)
	return args.Get(0).(*github.Artifact), args.Error(1)
}

func TestNewSecurityService(t *testing.T) {
	logger := slog.Default()
	mockClient := &MockGitHubClient{}

	service := NewSecurityService(mockClient, logger)

	assert.NotNil(t, service)
	assert.Equal(t, mockClient, service.githubClient)
	assert.Equal(t, logger, service.logger)
}

func TestSecurityService_ProcessWorkflowSecurityArtifacts(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name              string
		artifacts         []*github.Artifact
		downloadedContent map[int64][]byte
		expectedPayloads  int
		expectedError     bool
	}{
		{
			name: "successful processing with trivy artifacts",
			artifacts: []*github.Artifact{
				{
					ID:   github.Int64(123),
					Name: github.String("trivy-results"),
				},
			},
			downloadedContent: map[int64][]byte{
				123: createMockTrivyZip(t),
			},
			expectedPayloads: 1,
			expectedError:    false,
		},
		{
			name: "no security artifacts found",
			artifacts: []*github.Artifact{
				{
					ID:   github.Int64(456),
					Name: github.String("regular-artifact"),
				},
			},
			downloadedContent: map[int64][]byte{
				456: []byte("regular content"),
			},
			expectedPayloads: 0,
			expectedError:    false,
		},
		{
			name:              "no artifacts",
			artifacts:         []*github.Artifact{},
			downloadedContent: map[int64][]byte{},
			expectedPayloads:  0,
			expectedError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockGitHubClient{}
			service := NewSecurityService(mockClient, logger)

			// Mock artifact listing
			mockClient.On("ListWorkflowArtifacts", mock.Anything, "owner", "repo", int64(123)).Return(tt.artifacts, nil)

			// Mock artifact downloads
			for artifactID, content := range tt.downloadedContent {
				mockClient.On("DownloadArtifact", mock.Anything, "owner", "repo", artifactID).Return(content, nil)
			}

			ctx := context.Background()
			payloads, err := service.ProcessWorkflowSecurityArtifacts(ctx, "owner", "repo", "abc123", 123)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, payloads)
			} else {
				assert.NoError(t, err)
				if tt.expectedPayloads == 0 {
					assert.Nil(t, payloads)
				} else {
					assert.Len(t, payloads, tt.expectedPayloads)
				}
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestSecurityService_DiscoverSecurityArtifacts(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name              string
		artifacts         []*github.Artifact
		downloadedContent map[int64][]byte
		expectedArtifacts int
		expectedError     bool
	}{
		{
			name: "discover trivy artifacts",
			artifacts: []*github.Artifact{
				{
					ID:   github.Int64(123),
					Name: github.String("trivy-results"),
				},
				{
					ID:   github.Int64(124),
					Name: github.String("sbom-report"),
				},
			},
			downloadedContent: map[int64][]byte{
				123: createMockTrivyZip(t),
				124: createMockSBOMZip(t),
			},
			expectedArtifacts: 2,
			expectedError:     false,
		},
		{
			name: "no matching artifacts",
			artifacts: []*github.Artifact{
				{
					ID:   github.Int64(456),
					Name: github.String("regular-build-artifact"),
				},
			},
			downloadedContent: map[int64][]byte{
				456: []byte("non-security content"),
			},
			expectedArtifacts: 0,
			expectedError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockGitHubClient{}
			service := NewSecurityService(mockClient, logger)

			// Mock artifact listing
			mockClient.On("ListWorkflowArtifacts", mock.Anything, "owner", "repo", int64(123)).Return(tt.artifacts, nil)

			// Mock artifact downloads
			for artifactID, content := range tt.downloadedContent {
				mockClient.On("DownloadArtifact", mock.Anything, "owner", "repo", artifactID).Return(content, nil)
			}

			ctx := context.Background()
			artifacts, err := service.DiscoverSecurityArtifacts(ctx, "owner", "repo", 123)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, artifacts)
			} else {
				assert.NoError(t, err)
				assert.Len(t, artifacts, tt.expectedArtifacts)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

func TestSecurityService_BuildVulnerabilityPayloadFromTrivy(t *testing.T) {
	logger := slog.Default()
	mockClient := &MockGitHubClient{}
	service := NewSecurityService(mockClient, logger)

	// Create mock Trivy report
	trivyReport := types.Report{
		SchemaVersion: 2,
		ArtifactName:  "test-image",
		ArtifactType:  types.ArtifactContainerImage,
		Metadata: types.Metadata{
			OS: &types.OS{
				Family: "debian",
				Name:   "10",
			},
		},
		Results: []types.Result{
			{
				Target: "test-package",
				Class:  types.ClassOSPkg,
				Type:   "debian",
				Vulnerabilities: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2021-1234",
						PkgName:          "test-package",
						InstalledVersion: "1.0.0",
						FixedVersion:     "1.0.1",
						Severity:         "HIGH",
						CVSS: map[string]types.CVSS{
							"nvd": {
								V3Score: 7.5,
							},
						},
						Title:       "Test vulnerability",
						Description: "A test vulnerability description",
						References:  []string{"https://example.com/cve-2021-1234"},
					},
				},
			},
		},
	}

	trivyJSON, err := json.Marshal(trivyReport)
	require.NoError(t, err)

	artifact := &SecurityArtifact{
		ArtifactName: "trivy-results",
		FileName:     "trivy-results.json",
		Content:      trivyJSON,
		Type:         ArtifactTypeVulnerabilityJSON,
	}

	ctx := context.Background()
	payload, err := service.BuildVulnerabilityPayloadFromTrivy(ctx, artifact, "owner", "repo", "abc123", 0, 123)

	assert.NoError(t, err)
	assert.NotNil(t, payload)
	assert.Equal(t, "vulnerability", payload.Type)
	assert.Equal(t, "trivy", payload.Metadata.ToolName)
	assert.Equal(t, "owner/repo", payload.Metadata.Repository)
	assert.Equal(t, "abc123", payload.Metadata.CommitSHA)
	assert.Len(t, payload.Vulnerabilities, 1)

	vuln := payload.Vulnerabilities[0]
	assert.Equal(t, "CVE-2021-1234", vuln.ID)
	assert.Equal(t, "HIGH", vuln.Severity)
	assert.Equal(t, float64(7.5), vuln.Score)
	assert.Equal(t, "test-package", vuln.Package.Name)
	assert.Equal(t, "1.0.0", vuln.Package.Version)
	assert.Equal(t, "1.0.1", vuln.FixedVersion)
}

func TestSecurityService_DetermineArtifactType(t *testing.T) {
	logger := slog.Default()
	mockClient := &MockGitHubClient{}
	service := NewSecurityService(mockClient, logger)

	tests := []struct {
		name         string
		artifactName string
		fileName     string
		content      []byte
		expectedType ArtifactType
	}{
		{
			name:         "trivy results JSON",
			artifactName: "trivy-results",
			fileName:     "results.json",
			content:      []byte(`{"SchemaVersion": 2, "ArtifactName": "test"}`),
			expectedType: ArtifactTypeVulnerabilityJSON,
		},
		{
			name:         "SARIF file",
			artifactName: "security-results",
			fileName:     "results.sarif",
			content:      []byte(`{"version": "2.1.0", "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"}`),
			expectedType: ArtifactTypeVulnerabilitySARIF,
		},
		{
			name:         "SPDX JSON",
			artifactName: "sbom-report",
			fileName:     "sbom.spdx.json",
			content:      []byte(`{"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0"}`),
			expectedType: ArtifactTypeSBOMSPDX,
		},
		{
			name:         "unknown file",
			artifactName: "build-logs",
			fileName:     "build.log",
			content:      []byte("build output logs"),
			expectedType: ArtifactTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifactType := service.determineArtifactType(tt.artifactName, tt.fileName, tt.content)
			assert.Equal(t, tt.expectedType, artifactType)
		})
	}
}

func TestSecurityService_IsSecurityArtifact(t *testing.T) {
	logger := slog.Default()
	mockClient := &MockGitHubClient{}
	service := NewSecurityService(mockClient, logger)

	tests := []struct {
		name         string
		artifactName string
		expected     bool
	}{
		{
			name:         "trivy results",
			artifactName: "trivy-results",
			expected:     true,
		},
		{
			name:         "security scan",
			artifactName: "security-scan-results",
			expected:     true,
		},
		{
			name:         "sbom report",
			artifactName: "sbom-report",
			expected:     true,
		},
		{
			name:         "vulnerability report",
			artifactName: "vulnerability-report",
			expected:     true,
		},
		{
			name:         "sarif results",
			artifactName: "sarif-results",
			expected:     true,
		},
		{
			name:         "regular build artifact",
			artifactName: "build-artifacts",
			expected:     false,
		},
		{
			name:         "test results",
			artifactName: "test-results",
			expected:     false,
		},
		{
			name:         "coverage report",
			artifactName: "coverage-report",
			expected:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.isSecurityArtifact(tt.artifactName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Helper functions to create mock zip files for testing

func createMockTrivyZip(t *testing.T) []byte {
	t.Helper()

	trivyReport := types.Report{
		SchemaVersion: 2,
		ArtifactName:  "test-image",
		ArtifactType:  types.ArtifactContainerImage,
		Results: []types.Result{
			{
				Target: "test-package",
				Class:  types.ClassOSPkg,
				Type:   "debian",
				Vulnerabilities: []types.DetectedVulnerability{
					{
						VulnerabilityID:  "CVE-2021-1234",
						PkgName:          "test-package",
						InstalledVersion: "1.0.0",
						FixedVersion:     "1.0.1",
						Severity:         "HIGH",
						Title:            "Test vulnerability",
						Description:      "A test vulnerability description",
					},
				},
			},
		},
	}

	trivyJSON, err := json.Marshal(trivyReport)
	require.NoError(t, err)

	return createZipWithFile(t, "trivy-results.json", trivyJSON)
}

func createMockSBOMZip(t *testing.T) []byte {
	t.Helper()

	spdxDoc := map[string]interface{}{
		"spdxVersion":   "SPDX-2.3",
		"dataLicense":   "CC0-1.0",
		"SPDXID":        "SPDXRef-DOCUMENT",
		"name":          "test-document",
		"documentNamespace": "https://example.com/test",
		"packages": []map[string]interface{}{
			{
				"SPDXID":           "SPDXRef-Package",
				"name":             "test-package",
				"downloadLocation": "https://example.com/package",
				"licenseConcluded": "MIT",
			},
		},
	}

	spdxJSON, err := json.Marshal(spdxDoc)
	require.NoError(t, err)

	return createZipWithFile(t, "sbom.spdx.json", spdxJSON)
}

func createZipWithFile(t *testing.T, filename string, content []byte) []byte {
	t.Helper()

	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	fileWriter, err := zipWriter.Create(filename)
	require.NoError(t, err)

	_, err = fileWriter.Write(content)
	require.NoError(t, err)

	err = zipWriter.Close()
	require.NoError(t, err)

	return buf.Bytes()
}

func TestSecurityService_ExtractFilesFromZip(t *testing.T) {
	logger := slog.Default()
	mockClient := &MockGitHubClient{}
	service := NewSecurityService(mockClient, logger)

	tests := []struct {
		name          string
		zipContent    []byte
		expectedFiles int
		expectedError bool
	}{
		{
			name:          "valid zip with trivy results",
			zipContent:    createMockTrivyZip(t),
			expectedFiles: 1,
			expectedError: false,
		},
		{
			name:          "valid zip with SBOM",
			zipContent:    createMockSBOMZip(t),
			expectedFiles: 1,
			expectedError: false,
		},
		{
			name:          "invalid zip content",
			zipContent:    []byte("not a zip file"),
			expectedFiles: 0,
			expectedError: true,
		},
		{
			name:          "empty zip",
			zipContent:    createZipWithFile(t, "", []byte{}),
			expectedFiles: 1, // Empty file is still a file
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files, err := service.extractFilesFromZip(tt.zipContent)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, files)
			} else {
				assert.NoError(t, err)
				assert.Len(t, files, tt.expectedFiles)
			}
		})
	}
}

func TestSecurityService_CalculateVulnerabilitySummary(t *testing.T) {
	logger := slog.Default()
	mockClient := &MockGitHubClient{}
	service := NewSecurityService(mockClient, logger)

	vulnerabilities := []Vulnerability{
		{ID: "CVE-1", Severity: "CRITICAL"},
		{ID: "CVE-2", Severity: "HIGH"},
		{ID: "CVE-3", Severity: "HIGH"},
		{ID: "CVE-4", Severity: "MEDIUM"},
		{ID: "CVE-5", Severity: "LOW"},
		{ID: "CVE-6", Severity: "INFO"},
	}

	summary := service.calculateVulnerabilitySummary(vulnerabilities)

	assert.Equal(t, 6, summary.TotalVulnerabilities)
	assert.Equal(t, 1, summary.Critical)
	assert.Equal(t, 2, summary.High)
	assert.Equal(t, 1, summary.Medium)
	assert.Equal(t, 1, summary.Low)
	assert.Equal(t, 1, summary.Info)
}

func TestSecurityService_ErrorHandling(t *testing.T) {
	logger := slog.Default()

	tests := []struct {
		name          string
		setupMock     func(*MockGitHubClient)
		expectedError bool
		errorContains string
	}{
		{
			name: "artifact listing error",
			setupMock: func(m *MockGitHubClient) {
				m.On("ListWorkflowArtifacts", mock.Anything, "owner", "repo", int64(123)).Return([]*github.Artifact(nil), fmt.Errorf("API error"))
			},
			expectedError: true,
			errorContains: "failed to discover security artifacts",
		},
		{
			name: "artifact download error", 
			setupMock: func(m *MockGitHubClient) {
				artifacts := []*github.Artifact{
					{
						ID:   github.Int64(123),
						Name: github.String("trivy-results"),
					},
				}
				m.On("ListWorkflowArtifacts", mock.Anything, "owner", "repo", int64(123)).Return(artifacts, nil)
				m.On("DownloadArtifact", mock.Anything, "owner", "repo", int64(123)).Return([]byte(nil), fmt.Errorf("download error"))
			},
			expectedError: true,
			errorContains: "failed to discover security artifacts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := &MockGitHubClient{}
			service := NewSecurityService(mockClient, logger)

			tt.setupMock(mockClient)

			ctx := context.Background()
			payloads, err := service.ProcessWorkflowSecurityArtifacts(ctx, "owner", "repo", "abc123", 123)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, payloads)
			} else {
				assert.NoError(t, err)
			}

			mockClient.AssertExpectations(t)
		})
	}
}
