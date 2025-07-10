package services

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/owenrumney/go-sarif/sarif"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/terrpan/polly/internal/clients"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

type SecurityService struct {
	githubClient clients.GitHubClientInterface
	logger       *slog.Logger
}

type SecurityArtifact struct {
	ArtifactName string            `json:"artifact_name"`
	FileName     string            `json:"file_name"`
	Content      []byte            `json:"content"`
	Type         ArtifactType      `json:"type"`
	Metadata     *SecurityMetadata `json:"metadata,omitempty"`
}

type SecurityMetadata struct {
	SPDXMetadata          *SPDXMetadata          `json:"spdx_metadata,omitempty"`
	VulnerabilityMetadata *VulnerabilityMetadata `json:"vulnerability_metadata,omitempty"`
}

type SPDXMetadata struct {
	DocumentName      string           `json:"document_name"`
	DocumentNamespace string           `json:"document_namespace"`
	SPDXVersion       string           `json:"spdx_version"`
	DataLicense       string           `json:"data_license"`
	Packages          []PackageInfo    `json:"packages"`
	LicensesSummary   *LicensesSummary `json:"licenses_summary"`
}

type PackageInfo struct {
	Name             string `json:"name"`
	SPDXID           string `json:"spdx_id"`
	DownloadLocation string `json:"download_location"`
	LicenseConcluded string `json:"license_concluded"`
	LicenseDeclared  string `json:"license_declared"`
	CopyrightText    string `json:"copyright_text"`
}

type LicensesSummary struct {
	TotalPackages          int            `json:"total_packages"`
	AllLicenses            []string       `json:"all_licenses"`
	LicenseDistribution    map[string]int `json:"license_distribution"`
	PackagesWithoutLicense int            `json:"packages_without_license"`
}

type VulnerabilityMetadata struct {
	SourceFormat      string               `json:"source_format"`
	ToolName          string               `json:"tool_name"`
	ToolVersion       string               `json:"tool_version"`
	SchemaVersion     string               `json:"schema_version"`
	ScanTarget        string               `json:"scan_target"`
	ResultCount       int                  `json:"result_count"`
	SeverityBreakdown map[string]int       `json:"severity_breakdown"`
	Summary           VulnerabilitySummary `json:"summary"`
}

type VulnerabilitySummary struct {
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	Critical             int `json:"critical"`
	High                 int `json:"high"`
	Medium               int `json:"medium"`
	Low                  int `json:"low"`
	Info                 int `json:"info"`
}

type VulnerabilityPayload struct {
	Type            string               `json:"type"`
	Metadata        PayloadMetadata      `json:"metadata"`
	Vulnerabilities []Vulnerability      `json:"vulnerabilities"`
	Summary         VulnerabilitySummary `json:"summary"`
}

type PayloadMetadata struct {
	SourceFormat  string `json:"source_format"`
	ToolName      string `json:"tool_name"`
	ToolVersion   string `json:"tool_version"`
	ScanTime      string `json:"scan_time"`
	Repository    string `json:"repository"`
	CommitSHA     string `json:"commit_sha"`
	PRNumber      int    `json:"pr_number,omitempty"`
	ScanTarget    string `json:"scan_target"`
	SchemaVersion string `json:"schema_version"`
}

type Vulnerability struct {
	ID           string   `json:"id"`
	Severity     string   `json:"severity"`
	Score        float64  `json:"score,omitempty"`
	Package      Package  `json:"package"`
	Location     Location `json:"location"`
	Description  string   `json:"description"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	References   []string `json:"references,omitempty"`
}

type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

type Location struct {
	File string `json:"file"`
	Line int    `json:"line,omitempty"`
}

type ArtifactType string

const (
	ArtifactTypeSBOMSPDX           ArtifactType = "sbom_spdx"
	ArtifactTypeVulnerabilitySARIF ArtifactType = "vulnerability_sarif"
	ArtifactTypeUnknown            ArtifactType = "unknown"
	ArtifactTypeVulnerabilityJSON  ArtifactType = "vulnerability_json"
)

// cvssPriority defines the order of CVSS sources to check for scores.
var cvssPriority = []dbtypes.SourceID{"nvd", "redhat", "ghsa"}

// NewSecurityService initializes a new SecurityService with the provided logger.
func NewSecurityService(githubClient clients.GitHubClientInterface, logger *slog.Logger) *SecurityService {
	return &SecurityService{
		githubClient: githubClient,
		logger:       logger,
	}
}

// ProcessWorkflowSecurityArtifacts processes security artifacts and returns normalized payloads
func (s *SecurityService) ProcessWorkflowSecurityArtifacts(ctx context.Context, owner, repo, sha string, workflowID int64) ([]*VulnerabilityPayload, error) {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "security.process_workflow_artifacts")
	defer span.End()

	s.logger.InfoContext(ctx, "Processing security artifacts",
		"owner", owner,
		"repo", repo,
		"sha", sha,
		"workflow_id", workflowID,
	)

	// 1. Discover security artifacts
	securityArtifacts, err := s.DiscoverSecurityArtifacts(ctx, owner, repo, workflowID)
	if err != nil {
		return nil, fmt.Errorf("failed to discover security artifacts: %w", err)
	}

	if len(securityArtifacts) == 0 {
		s.logger.InfoContext(ctx, "No security artifacts found")
		return nil, nil
	}

	// 2. Build payloads from artifacts
	return s.BuildPayloadsFromArtifacts(ctx, securityArtifacts, owner, repo, sha, workflowID)
}

// DiscoverSecurityArtifacts finds and downloads security-related artifacts
func (s *SecurityService) DiscoverSecurityArtifacts(ctx context.Context, owner, repo string, workflowID int64) ([]*SecurityArtifact, error) {
	return s.checkArtifactForSecurityContent(ctx, owner, repo, workflowID)
}

// BuildPayloadsFromArtifacts converts security artifacts into normalized payloads
func (s *SecurityService) BuildPayloadsFromArtifacts(ctx context.Context, artifacts []*SecurityArtifact, owner, repo, sha string, workflowID int64) ([]*VulnerabilityPayload, error) {
	var payloads []*VulnerabilityPayload

	s.logger.InfoContext(ctx, "Building payloads from security artifacts", "count", len(artifacts))

	for _, artifact := range artifacts {
		s.logger.InfoContext(ctx, "Processing security artifact",
			"type", artifact.Type,
			"filename", artifact.FileName,
			"size", len(artifact.Content),
		)

		switch artifact.Type {
		case ArtifactTypeVulnerabilityJSON:
			payload, err := s.BuildVulnerabilityPayloadFromTrivy(ctx, artifact, owner, repo, sha, 0, workflowID)
			if err != nil {
				s.logger.ErrorContext(ctx, "Failed to build vulnerability payload",
					"artifact_name", artifact.ArtifactName,
					"file_name", artifact.FileName,
					"error", err,
				)
				continue
			}
			payloads = append(payloads, payload)

		case ArtifactTypeSBOMSPDX:
			// TODO: Implement SBOM payload builder
			s.logger.DebugContext(ctx, "SBOM processing not yet implemented", "artifact", artifact.FileName)

		default:
			s.logger.WarnContext(ctx, "Unsupported artifact type",
				"type", artifact.Type,
				"filename", artifact.FileName,
			)
		}
	}

	s.logger.InfoContext(ctx, "Built payloads from security artifacts",
		"total_artifacts", len(artifacts),
		"successful_payloads", len(payloads))

	return payloads, nil
}

// checkArtifactForSecurityContent downloads and inspects for security-related content.
func (s *SecurityService) checkArtifactForSecurityContent(ctx context.Context, owner, repo string, workflowID int64) ([]*SecurityArtifact, error) {
	tracer := otel.Tracer("polly/services")
	ctx, span := tracer.Start(ctx, "security.check_artifacts")
	defer span.End()

	// List all artifacts for the workflow
	artifacts, err := s.githubClient.ListWorkflowArtifacts(ctx, owner, repo, workflowID)
	if err != nil {
		return nil, fmt.Errorf("failed to list artifacts: %w", err)
	}

	if len(artifacts) == 0 {
		s.logger.InfoContext(ctx, "No artifacts found for workflow",
			"owner", owner,
			"repo", repo,
			"workflow_id", workflowID,
		)
		return nil, nil
	}

	span.SetAttributes(
		attribute.Int("artifact.count", len(artifacts)),
		attribute.String("github.owner", owner),
		attribute.String("github.repo", repo),
		attribute.Int64("github.workflow_id", workflowID),
	)

	var securityArtifacts []*SecurityArtifact
	for _, artifact := range artifacts {
		s.logger.DebugContext(ctx, "Checking artifact for security content",
			"artifact_name", artifact.GetName(),
			"artifact_id", artifact.GetID(),
			"artifact_size", artifact.GetSizeInBytes(),
		)

		// Download the artifact content
		zipData, err := s.githubClient.DownloadArtifact(ctx, owner, repo, artifact.GetID())
		if err != nil {
			s.logger.WarnContext(ctx, "Failed to download artifact",
				"artifact_name", artifact.GetName(),
				"artifact_id", artifact.GetID(),
				"error", err,
			)
			continue
		}

		// Inspect the artifact content for security-related files
		artifactFiles, err := s.inspectZipContent(zipData, artifact.GetName())
		if err != nil {
			s.logger.WarnContext(ctx, "Failed to inspect ZIP content",
				"artifact", artifact.GetName(),
				"error", err)
			continue
		}

		securityArtifacts = append(securityArtifacts, artifactFiles...)
	}

	span.SetAttributes(attribute.Int("security_artifacts.found", len(securityArtifacts)))
	return securityArtifacts, nil
}

// inspectZipContent inspects the content of a ZIP file for security-related files.
func (s *SecurityService) inspectZipContent(zipData []byte, artifactName string) ([]*SecurityArtifact, error) {
	// Create ZIP reader
	zipReader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create zip reader: %w", err)
	}

	var securityArtifacts []*SecurityArtifact

	// Examine each file in the ZIP
	for _, file := range zipReader.File {
		if file.FileInfo().IsDir() {
			continue
		}

		s.logger.Debug("Inspecting file", "filename", file.Name)

		// Read file content
		rc, err := file.Open()
		if err != nil {
			s.logger.Warn("Failed to open file in ZIP", "filename", file.Name, "error", err)
			continue
		}

		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			s.logger.Warn("Failed to read file content", "filename", file.Name, "error", err)
			continue
		}

		// Check if this file contains security content
		artifactType := s.detectSecurityContent(content, file.Name)
		if artifactType != ArtifactTypeUnknown {
			securityArtifacts = append(securityArtifacts, &SecurityArtifact{
				ArtifactName: artifactName,
				FileName:     file.Name,
				Content:      content,
				Type:         artifactType,
			})

			s.logger.Info("Found security content",
				"type", artifactType,
				"filename", file.Name,
				"artifact", artifactName,
				"size", len(content))
		}
	}

	return securityArtifacts, nil
}

// detectSecurityContent determines if file content is SPDX or SARIF
func (s *SecurityService) detectSecurityContent(content []byte, filename string) ArtifactType {
	// Try SPDX detection first
	if isSPDXContent(content) {

		s.logger.Debug("Detected SPDX content", "filename", filename)
		return ArtifactTypeSBOMSPDX
	}

	// Try Trivy JSON detection
	if isTrivyJSONContent(content) {
		s.logger.Debug("Detected Trivy JSON content", "filename", filename)
		return ArtifactTypeVulnerabilityJSON
	}

	// Try SARIF detection
	if isSarifContent(content) {
		s.logger.Debug("Detected SARIF content", "filename", filename)
		return ArtifactTypeVulnerabilitySARIF
	}

	return ArtifactTypeUnknown
}

// BuildVulnerabilityPayloadFromTrivy creates a normalized vulnerability payload from Trivy JSON report
func (s *SecurityService) BuildVulnerabilityPayloadFromTrivy(ctx context.Context, artifact *SecurityArtifact, owner, repo, sha string, prNumber int, workflowID int64) (*VulnerabilityPayload, error) {
	// parse the trivy report
	var trivyReport types.Report
	if err := json.Unmarshal(artifact.Content, &trivyReport); err != nil {
		s.logger.ErrorContext(ctx, "Failed to parse Trivy report",
			"artifact_name", artifact.ArtifactName,
			"file_name", artifact.FileName,
			"error", err,
		)
		return nil, err
	}

	// build the metadata
	metadata := PayloadMetadata{
		SourceFormat:  "trivy_json",
		ToolName:      "trivy",
		ScanTime:      trivyReport.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		Repository:    fmt.Sprintf("%s/%s", owner, repo),
		CommitSHA:     sha,
		PRNumber:      prNumber,
		ScanTarget:    trivyReport.ArtifactName,
		SchemaVersion: fmt.Sprintf("%d", trivyReport.SchemaVersion),
	}

	// Extract vulnerabilities and build summary
	vulnerabilities := []Vulnerability{}
	severityCount := map[string]int{
		"CRITICAL": 0,
		"HIGH":     0,
		"MEDIUM":   0,
		"LOW":      0,
		"INFO":     0,
	}

	for _, result := range trivyReport.Results {
		if result.Vulnerabilities == nil {
			continue
		}

		// Extract vulnerabilities from this target
		for _, vuln := range result.Vulnerabilities {
			// Normalize the vulnerability
			normalizedVuln := normalizeTrivyVulnerability(vuln, result.Target)
			vulnerabilities = append(vulnerabilities, normalizedVuln)

			// Count severity
			if count, exists := severityCount[normalizedVuln.Severity]; exists {
				severityCount[normalizedVuln.Severity] = count + 1
			}
		}
	}

	// build the complete payload
	payload := &VulnerabilityPayload{
		Type:            "vulnerability_scan",
		Metadata:        metadata,
		Vulnerabilities: vulnerabilities,
		Summary: VulnerabilitySummary{
			TotalVulnerabilities: len(vulnerabilities),
			Critical:             severityCount["CRITICAL"],
			High:                 severityCount["HIGH"],
			Medium:               severityCount["MEDIUM"],
			Low:                  severityCount["LOW"],
			Info:                 severityCount["INFO"],
		},
	}
	// Update the artifact metadata
	artifact.Metadata = &SecurityMetadata{
		VulnerabilityMetadata: &VulnerabilityMetadata{
			SourceFormat:      "trivy_json",
			ToolName:          "trivy",
			ToolVersion:       metadata.ToolVersion,
			SchemaVersion:     metadata.SchemaVersion,
			ScanTarget:        metadata.ScanTarget,
			ResultCount:       len(trivyReport.Results),
			SeverityBreakdown: severityCount,
			Summary:           payload.Summary,
		},
	}

	s.logger.InfoContext(ctx, "Built vulnerability payload from Trivy JSON",
		"total_vulnerabilities", len(vulnerabilities),
		"critical", severityCount["CRITICAL"],
		"high", severityCount["HIGH"],
		"medium", severityCount["MEDIUM"],
		"low", severityCount["LOW"],
	)

	return payload, nil
}

// normalizeTrivyVulnerability normalizes a Trivy vulnerability into a common format.
func normalizeTrivyVulnerability(vuln types.DetectedVulnerability, target string) Vulnerability {
	// Extract CVSS score (prefer GHSA, fallback to NVD)
	score := extractCVSSScore(vuln)

	return Vulnerability{
		ID:       vuln.VulnerabilityID,
		Severity: vuln.Severity,
		Score:    score,
		Package: Package{
			Name:      vuln.PkgName,
			Version:   vuln.InstalledVersion,
			Ecosystem: detectEcosystem(target),
		},
		Location: Location{
			File: target,
			Line: 0, // Trivy does not provide line numbers
		},
		Description:  vuln.Description,
		FixedVersion: vuln.FixedVersion,
		References:   vuln.References,
	}
}

// extractCVSSScore returns the highest‐priority, non‐zero score from vuln.CVSS,
// falling back to the maximum score across all vendors.
func extractCVSSScore(vuln types.DetectedVulnerability) float64 {
	if len(vuln.CVSS) == 0 {
		return 0
	}

	// first try the priority vendors
	for _, vendor := range cvssPriority {
		if c, ok := vuln.CVSS[vendor]; ok {
			if s := bestScore(c); s > 0 {
				return s
			}
		}
	}

	// fallback: pick the single highest score among all
	var max float64
	for _, c := range vuln.CVSS {
		if s := bestScore(c); s > max {
			max = s
		}
	}
	return max
}

// bestScore prefers v4.0, then v3.x, then v2.x
func bestScore(c dbtypes.CVSS) float64 {
	if c.V40Score > 0 {
		return c.V40Score
	}
	if c.V3Score > 0 {
		return c.V3Score
	}
	if c.V2Score > 0 {
		return c.V2Score
	}
	return 0
}

// detectEcosystem determines the package ecosystem from the target file
func detectEcosystem(target string) string {
	ecosystemMap := map[string]string{
		"package-lock.json": "npm",
		"pnpm-lock.yaml":    "npm",
		"yarn.lock":         "npm",
		"Gemfile.lock":      "rubygems",
		"requirements.txt":  "pypi",
		"Pipfile.lock":      "pypi",
		"go.mod":            "go",
		"go.sum":            "go",
		"Cargo.lock":        "cargo",
		"composer.lock":     "packagist",
		"pom.xml":           "maven",
		"build.gradle":      "gradle",
		"nuget.config":      "nuget",
	}

	for pattern, ecosystem := range ecosystemMap {
		if strings.Contains(target, pattern) {
			return ecosystem
		}
	}

	// Default to "unknown" if no match found
	return "unknown"

}

// isSarifContent checks if the content is a valid SARIF document
func isSarifContent(content []byte) bool {
	// Use the go-sarif library to validate SARIF format
	doc, err := sarif.FromBytes(content)
	if err != nil {
		return false
	}
	if doc == nil {
		return false
	}

	if doc.Version == "" {
		return false
	}

	if doc.Version != "2.1.0" {
		return false
	}

	if len(doc.Runs) == 0 {
		return false
	}

	return true
}

// isSPDXContent checks if the content is a valid SPDX document
func isSPDXContent(content []byte) bool {
	doc, err := spdxjson.Read(bytes.NewReader(content))
	if err != nil {
		return false
	}

	if doc == nil {
		return false
	}

	if doc.SPDXVersion == "" {
		return false
	}

	if doc.DataLicense == "" {
		return false
	}

	if doc.SPDXIdentifier == "" {
		return false
	}

	if doc.DocumentName == "" {
		return false
	}
	if doc.DocumentNamespace == "" {
		return false
	}
	if doc.CreationInfo == nil {
		return false
	}

	if !strings.HasPrefix(doc.SPDXVersion, "SPDX-") {
		return false
	}
	if doc.DataLicense != "CC0-1.0" {
		return false
	}

	return true
}

// isTrivyJson checks if the content is a valid Trivy JSON report
func isTrivyJSONContent(content []byte) bool {
	var report types.Report

	if err := json.Unmarshal(content, &report); err != nil {
		return false
	}

	if report.SchemaVersion == 0 {
		return false
	}

	if report.ArtifactName == "" {
		return false
	}

	if report.Results == nil {
		return false
	}

	return true
}
