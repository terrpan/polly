package services

import (
	"bytes"
	"encoding/json"
	"strings"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/owenrumney/go-sarif/sarif"
	spdxjson "github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"

	"github.com/terrpan/polly/internal/otel"
)

// ServiceTracingHelper provides a shared tracing helper for all services
var ServiceTracingHelper = otel.NewTracingHelper("polly/services")

// NewServiceTracingHelper creates a new tracing helper for services
// This function exists for consistency with handlers, but services can also use the global ServiceTracingHelper
func NewServiceTracingHelper() *otel.TracingHelper {
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
	SourceFormat, ToolName, Repository, CommitSHA, ScanTarget, SchemaVersion string,
	PRNumber int,
	ScanTime string,
) PayloadMetadata {
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
