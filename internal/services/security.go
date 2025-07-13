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
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/terrpan/polly/internal/clients"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// SecurityService provides methods to process security artifacts from GitHub workflows.
type SecurityService struct {
	githubClient *clients.GitHubClient
	logger       *slog.Logger
}

// SecurityArtifact represents a security-related artifact found in a workflow.
type SecurityArtifact struct {
	ArtifactName string       `json:"artifact_name"`
	FileName     string       `json:"file_name"`
	Content      []byte       `json:"content"`
	Type         ArtifactType `json:"type"`
}

// PayloadMetadata contains metadata for security payloads
type VulnerabilitySummary struct {
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	Critical             int `json:"critical"`
	High                 int `json:"high"`
	Medium               int `json:"medium"`
	Low                  int `json:"low"`
	Info                 int `json:"info"`
}

// SPDX/SBOM payload (summary + packages)
type SBOMPayload struct {
	Metadata PayloadMetadata `json:"metadata"`
	Summary  SBOMSummary     `json:"summary"`
	Packages []SBOMPackage   `json:"packages"`
}

// SPDX/SBOM package details
type SBOMPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo"`
	Supplier         string            `json:"supplier,omitempty"`
	DownloadLocation string            `json:"downloadLocation,omitempty"`
	FilesAnalyzed    bool              `json:"filesAnalyzed,omitempty"`
	SourceInfo       string            `json:"sourceInfo,omitempty"`
	LicenseConcluded string            `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string            `json:"licenseDeclared,omitempty"`
	CopyrightText    string            `json:"copyrightText,omitempty"`
	ExternalRefs     []SBOMExternalRef `json:"externalRefs,omitempty"`
}

// SPDX/SBOM external reference details
type SBOMExternalRef struct {
	ReferenceCategory string `json:"referenceCategory,omitempty"`
	ReferenceType     string `json:"referenceType,omitempty"`
	ReferenceLocator  string `json:"referenceLocator,omitempty"`
}

// SBOMSummary contains summary information about the SBOM
type SBOMSummary struct {
	TotalPackages          int            `json:"total_packages"`
	AllLicenses            []string       `json:"all_licenses"`
	LicenseDistribution    map[string]int `json:"license_distribution"`
	PackagesWithoutLicense int            `json:"packages_without_license"`
}

// Vulnerability payload (summary + vulnerabilities)
type VulnerabilityPayload struct {
	Type            string               `json:"type"` // e.g. "vulnerability_scan"
	Metadata        PayloadMetadata      `json:"metadata"`
	Summary         VulnerabilitySummary `json:"summary"`
	Vulnerabilities []Vulnerability      `json:"vulnerabilities"`
}

// PayloadMetadata contains metadata about the scan and tool used
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

// Vulnerability represents a single vulnerability found in a scan.
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

// Package represents a software package with its name, version, and ecosystem.
type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem,omitempty"`
}

// Location represents the file and line number where the vulnerability was found.
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
func NewSecurityService(githubClient *clients.GitHubClient, logger *slog.Logger) *SecurityService {
	return &SecurityService{
		githubClient: githubClient,
		logger:       logger,
	}
}

// ProcessWorkflowSecurityArtifacts processes security artifacts and returns normalized payloads
func (s *SecurityService) ProcessWorkflowSecurityArtifacts(ctx context.Context, owner, repo, sha string, workflowID int64) ([]*VulnerabilityPayload, []*SBOMPayload, error) {
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
		return nil, nil, fmt.Errorf("failed to discover security artifacts: %w", err)
	}

	if len(securityArtifacts) == 0 {
		s.logger.InfoContext(ctx, "No security artifacts found")
		return nil, nil, nil
	}

	// 2. Build payloads from artifacts
	return s.BuildPayloadsFromArtifacts(ctx, securityArtifacts, owner, repo, sha, workflowID)
}

// DiscoverSecurityArtifacts finds and downloads security-related artifacts
func (s *SecurityService) DiscoverSecurityArtifacts(ctx context.Context, owner, repo string, workflowID int64) ([]*SecurityArtifact, error) {
	return s.checkArtifactForSecurityContent(ctx, owner, repo, workflowID)
}

// BuildPayloadsFromArtifacts converts security artifacts into normalized payloads
func (s *SecurityService) BuildPayloadsFromArtifacts(ctx context.Context, artifacts []*SecurityArtifact, owner, repo, sha string, workflowID int64) ([]*VulnerabilityPayload, []*SBOMPayload, error) {
	vulnPayloads := make([]*VulnerabilityPayload, 0)
	sbomPayloads := make([]*SBOMPayload, 0)

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
			vulnPayloads = append(vulnPayloads, payload)

		case ArtifactTypeSBOMSPDX:
			payload, err := s.BuildSBOMPayloadFromSPDX(ctx, artifact, owner, repo, sha, 0, workflowID)
			if err != nil {
				s.logger.ErrorContext(ctx, "Failed to build SBOM payload",
					"artifact_name", artifact.ArtifactName,
					"file_name", artifact.FileName,
					"error", err,
				)
				continue
			}
			sbomPayloads = append(sbomPayloads, payload)

		default:
			s.logger.WarnContext(ctx, "Unsupported artifact type",
				"type", artifact.Type,
				"filename", artifact.FileName,
			)
		}
	}

	s.logger.InfoContext(ctx, "Built payloads from security artifacts",
		"total_artifacts", len(artifacts),
		"vulnerability_payloads", len(vulnPayloads),
		"sbom_payloads", len(sbomPayloads))

	return vulnPayloads, sbomPayloads, nil
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
		_ = rc.Close()
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

// BuildSBOMPayloadFromSPDX builds a normalized SBOM payload from SPDX content
func (s *SecurityService) BuildSBOMPayloadFromSPDX(ctx context.Context, artifact *SecurityArtifact, owner, repo, sha string, prNumber int, workflowID int64) (*SBOMPayload, error) {
	// Parse the SPDX JSON content
	doc, err := spdxjson.Read(bytes.NewReader(artifact.Content))
	if err != nil {
		s.logger.ErrorContext(ctx, "Failed to parse SPDX document",
			"artifact_name", artifact.ArtifactName,
			"file_name", artifact.FileName,
			"error", err,
		)
		return nil, err
	}

	// Build the metadata for the payload
	var scanTime string
	if doc.CreationInfo != nil && doc.CreationInfo.Created != "" {
		scanTime = doc.CreationInfo.Created
	} else {
		scanTime = "unknown"
	}

	metadata := buildPayloadMetadata(
		"spdx_json",
		"spdx",
		fmt.Sprintf("%s/%s", owner, repo),
		sha,
		artifact.FileName, // Use the file name as the scan target
		doc.SPDXVersion,   // Use SPDX version as schema version
		prNumber,
		scanTime,
	)

	// Extract all packages from SPDX document
	packages := []SBOMPackage{}
	licenseDistribution := make(map[string]int)
	var allLicenses []string
	packagesWithoutLicense := 0
	seenLicenses := make(map[string]bool)

	for _, pkg := range doc.Packages {
		// Skip the root document package (it's not a real package)
		if pkg.PackageName == "" || pkg.PackageSPDXIdentifier == doc.SPDXIdentifier {
			continue
		}

		// Convert supplier to string
		supplierStr := ""
		if pkg.PackageSupplier != nil {
			if pkg.PackageSupplier.Supplier != "" {
				supplierStr = pkg.PackageSupplier.Supplier
			} else if pkg.PackageSupplier.SupplierType != "" {
				supplierStr = pkg.PackageSupplier.SupplierType
			}
		}

		sbomPackage := SBOMPackage{
			Name:             pkg.PackageName,
			SPDXID:           string(pkg.PackageSPDXIdentifier),
			VersionInfo:      pkg.PackageVersion,
			Supplier:         supplierStr,
			DownloadLocation: pkg.PackageDownloadLocation,
			FilesAnalyzed:    pkg.FilesAnalyzed,
			SourceInfo:       pkg.PackageSourceInfo,
			LicenseConcluded: pkg.PackageLicenseConcluded,
			LicenseDeclared:  pkg.PackageLicenseDeclared,
			CopyrightText:    pkg.PackageCopyrightText,
		}

		packages = append(packages, sbomPackage)

		// Process license information for summary
		license := extractLicenseFromPackage(pkg)
		if license == "" || license == "NOASSERTION" || license == "NONE" {
			packagesWithoutLicense++
		} else {
			licenseDistribution[license]++
			if !seenLicenses[license] {
				allLicenses = append(allLicenses, license)
				seenLicenses[license] = true
			}
		}
	}

	// Build the summary
	summary := SBOMSummary{
		TotalPackages:          len(packages),
		AllLicenses:            allLicenses,
		LicenseDistribution:    licenseDistribution,
		PackagesWithoutLicense: packagesWithoutLicense,
	}

	// Build the complete payload
	payload := &SBOMPayload{
		Metadata: metadata,
		Summary:  summary,
		Packages: packages,
	}

	s.logger.InfoContext(ctx, "Built SBOM payload from SPDX JSON",
		"total_packages", len(packages),
		"licenses_found", len(allLicenses),
		"packages_without_license", packagesWithoutLicense,
	)

	return payload, nil
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

	metadata := buildPayloadMetadata(
		"trivy_json",
		"trivy",
		fmt.Sprintf("%s/%s", owner, repo),
		sha,
		trivyReport.ArtifactName,
		fmt.Sprintf("%d", trivyReport.SchemaVersion),
		prNumber,
		trivyReport.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	)

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

// extractLicenseFromPackage extracts the best available license from an SPDX package
func extractLicenseFromPackage(pkg *v2_3.Package) string {
	// First try LicenseConcluded
	if pkg.PackageLicenseConcluded != "" && pkg.PackageLicenseConcluded != "NOASSERTION" && pkg.PackageLicenseConcluded != "NONE" {
		return pkg.PackageLicenseConcluded
	}

	// Then try LicenseDeclared
	if pkg.PackageLicenseDeclared != "" && pkg.PackageLicenseDeclared != "NOASSERTION" && pkg.PackageLicenseDeclared != "NONE" {
		return pkg.PackageLicenseDeclared
	}

	// If both are empty or NOASSERTION, return empty string
	return ""
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

// buildPayloadMetadata builds the metadata for a security payload
func buildPayloadMetadata(SourceFormat, ToolName, Repository, CommitSHA, ScanTarget, SchemaVersion string, PRNumber int, ScanTime string) PayloadMetadata {
	return PayloadMetadata{
		SourceFormat:  SourceFormat,
		ToolName:      ToolName,
		ScanTime:      ScanTime,
		Repository:    Repository,
		CommitSHA:     CommitSHA,
		PRNumber:      PRNumber,
		ScanTarget:    ScanTarget,
		SchemaVersion: SchemaVersion,
	}
}
