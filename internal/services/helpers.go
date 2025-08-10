package services

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/owenrumney/go-sarif/sarif"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/terrpan/polly/internal/telemetry"
)

// ServiceTracingHelper provides a shared tracing helper for all services
var ServiceTracingHelper = telemetry.NewTelemetryHelper("polly/services")

// NewServiceTracingHelper creates a new tracing helper for services
// This function exists for consistency with handlers, but services can also use the global ServiceTracingHelper
func NewServiceTracingHelper() *telemetry.Helper {
	return ServiceTracingHelper
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
	if pkg.PackageLicenseConcluded != "" && pkg.PackageLicenseConcluded != "NOASSERTION" &&
		pkg.PackageLicenseConcluded != "NONE" {
		return pkg.PackageLicenseConcluded
	}

	// Then try LicenseDeclared
	if pkg.PackageLicenseDeclared != "" && pkg.PackageLicenseDeclared != "NOASSERTION" &&
		pkg.PackageLicenseDeclared != "NONE" {
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
func buildPayloadMetadata(
	sourceFormat, toolName, repository, commitSHA, scanTarget, schemaVersion string,
	prNumber int,
	scanTime string,
) PayloadMetadata {
	return PayloadMetadata{
		SourceFormat:  sourceFormat,
		ToolName:      toolName,
		ScanTime:      scanTime,
		Repository:    repository,
		CommitSHA:     commitSHA,
		PRNumber:      prNumber,
		ScanTarget:    scanTarget,
		SchemaVersion: schemaVersion,
	}
}

// convertMapToVulnerabilityPolicyResult converts a map[string]interface{} to VulnerabilityPolicyResult
func convertMapToVulnerabilityPolicyResult(
	data map[string]interface{},
) (VulnerabilityPolicyResult, error) {
	// Use JSON marshaling/unmarshaling for reliable conversion
	jsonData, err := json.Marshal(data)
	if err != nil {
		return VulnerabilityPolicyResult{}, err
	}

	var result VulnerabilityPolicyResult
	if err := json.Unmarshal(jsonData, &result); err != nil {
		return VulnerabilityPolicyResult{}, err
	}

	return result, nil
}

// convertMapToSBOMPolicyResult converts a map[string]interface{} to SBOMPolicyResult
func convertMapToSBOMPolicyResult(data map[string]interface{}) (SBOMPolicyResult, error) {
	// Use JSON marshaling/unmarshaling for reliable conversion
	jsonData, err := json.Marshal(data)
	if err != nil {
		return SBOMPolicyResult{}, err
	}

	var result SBOMPolicyResult
	if err := json.Unmarshal(jsonData, &result); err != nil {
		return SBOMPolicyResult{}, err
	}

	return result, nil
}

// buildSBOMPayloadFromSPDX builds a normalized SBOM payload from SPDX content
func buildSBOMPayloadFromSPDX(
	artifact *SecurityArtifact,
	owner, repo, sha string,
	prNumber int,
) (*SBOMPayload, error) {
	// Parse the SPDX JSON content
	doc, err := spdxjson.Read(bytes.NewReader(artifact.Content))
	if err != nil {
		return nil, err
	}

	// Build the metadata for the payload
	metadata := buildSBOMMetadataFromSPDX(doc, artifact, owner, repo, sha, prNumber)

	// Process packages and extract license information
	packages, summary := processSPDXPackages(doc)

	// Build the complete payload
	payload := &SBOMPayload{
		Metadata: metadata,
		Summary:  summary,
		Packages: packages,
	}

	return payload, nil
}

// buildSBOMMetadataFromSPDX extracts metadata from SPDX document
func buildSBOMMetadataFromSPDX(
	doc *v2_3.Document,
	artifact *SecurityArtifact,
	owner, repo, sha string,
	prNumber int,
) PayloadMetadata {
	var scanTime string
	if doc.CreationInfo != nil && doc.CreationInfo.Created != "" {
		scanTime = doc.CreationInfo.Created
	} else {
		scanTime = "unknown"
	}

	return buildPayloadMetadata(
		"spdx_json",
		"spdx",
		fmt.Sprintf("%s/%s", owner, repo),
		sha,
		artifact.FileName, // Use the file name as the scan target
		doc.SPDXVersion,   // Use SPDX version as schema version
		prNumber,
		scanTime,
	)
}

// processSPDXPackages extracts packages and builds license summary from SPDX document
func processSPDXPackages(doc *v2_3.Document) ([]SBOMPackage, SBOMSummary) {
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

		sbomPackage := buildSBOMPackageFromSPDX(pkg)
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

	summary := SBOMSummary{
		TotalPackages:          len(packages),
		AllLicenses:            allLicenses,
		LicenseDistribution:    licenseDistribution,
		PackagesWithoutLicense: packagesWithoutLicense,
	}

	return packages, summary
}

// buildSBOMPackageFromSPDX converts an SPDX package to SBOMPackage
func buildSBOMPackageFromSPDX(pkg *v2_3.Package) SBOMPackage {
	// Convert supplier to string
	supplierStr := ""

	if pkg.PackageSupplier != nil {
		if pkg.PackageSupplier.Supplier != "" {
			supplierStr = pkg.PackageSupplier.Supplier
		} else if pkg.PackageSupplier.SupplierType != "" {
			supplierStr = pkg.PackageSupplier.SupplierType
		}
	}

	return SBOMPackage{
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
}

// buildVulnerabilityPayloadFromTrivy creates a normalized vulnerability payload from Trivy JSON report
func buildVulnerabilityPayloadFromTrivy(
	artifact *SecurityArtifact,
	owner, repo, sha string,
	prNumber int,
) (*VulnerabilityPayload, error) {
	// parse the trivy report
	var trivyReport types.Report
	if err := json.Unmarshal(artifact.Content, &trivyReport); err != nil {
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

	return payload, nil
}

// inspectZipContentForSecurity inspects the content of a ZIP file for security-related files
func inspectZipContentForSecurity(
	zipData []byte,
	artifactName string,
	detectors []ContentDetector,
) ([]*SecurityArtifact, error) {
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

		// Read file content
		rc, err := file.Open()
		if err != nil {
			continue
		}

		content, err := io.ReadAll(rc)
		if err := rc.Close(); err != nil {
			continue
		}

		if err != nil {
			continue
		}

		// Check if this file contains security content
		artifactType := detectSecurityContentType(content, file.Name, detectors)
		if artifactType != ArtifactTypeUnknown {
			securityArtifacts = append(securityArtifacts, &SecurityArtifact{
				ArtifactName: artifactName,
				FileName:     file.Name,
				Content:      content,
				Type:         artifactType,
			})
		}
	}

	return securityArtifacts, nil
}

// detectSecurityContentType determines the artifact type using registered detectors
func detectSecurityContentType(
	content []byte,
	filename string,
	detectors []ContentDetector,
) ArtifactType {
	// Iterate through detectors in priority order
	for _, detector := range detectors {
		if detector.CanHandle(content, filename) {
			return detector.GetArtifactType()
		}
	}

	return ArtifactTypeUnknown
}
