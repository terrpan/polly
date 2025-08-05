package services

// ArtifactType represents the type of security artifact
type ArtifactType string

const (
	// ArtifactTypeSBOMSPDX represents an SPDX SBOM artifact
	ArtifactTypeSBOMSPDX ArtifactType = "sbom_spdx"
	// ArtifactTypeVulnerabilitySARIF represents a SARIF vulnerability artifact
	ArtifactTypeVulnerabilitySARIF ArtifactType = "vulnerability_sarif"
	// ArtifactTypeUnknown represents an unknown artifact type
	ArtifactTypeUnknown ArtifactType = "unknown"
	// ArtifactTypeVulnerabilityJSON represents a JSON vulnerability artifact
	ArtifactTypeVulnerabilityJSON ArtifactType = "vulnerability_json"
)

// SecurityArtifact represents a security-related artifact found in a workflow.
type SecurityArtifact struct {
	ArtifactName string       `json:"artifact_name"`
	FileName     string       `json:"file_name"`
	Type         ArtifactType `json:"type"`
	Content      []byte       `json:"content"`
}

// PayloadMetadata contains metadata about the scan and tool used
type PayloadMetadata struct {
	SourceFormat  string `json:"source_format"`
	ToolName      string `json:"tool_name"`
	ToolVersion   string `json:"tool_version"`
	ScanTime      string `json:"scan_time"`
	Repository    string `json:"repository"`
	CommitSHA     string `json:"commit_sha"`
	ScanTarget    string `json:"scan_target"`
	SchemaVersion string `json:"schema_version"`
	PRNumber      int    `json:"pr_number,omitempty"`
}

// VulnerabilitySummary contains metadata for security payloads
type VulnerabilitySummary struct {
	TotalVulnerabilities int `json:"total_vulnerabilities"`
	Critical             int `json:"critical"`
	High                 int `json:"high"`
	Medium               int `json:"medium"`
	Low                  int `json:"low"`
	Info                 int `json:"info"`
}

// SBOMPayload represents SPDX/SBOM payload (summary + packages)
type SBOMPayload struct {
	Metadata PayloadMetadata `json:"metadata"`
	Packages []SBOMPackage   `json:"packages"`
	Summary  SBOMSummary     `json:"summary"`
}

// SBOMPackage represents SPDX/SBOM package details
type SBOMPackage struct {
	Name             string            `json:"name"`
	SPDXID           string            `json:"SPDXID"`
	VersionInfo      string            `json:"versionInfo"`
	Supplier         string            `json:"supplier,omitempty"`
	DownloadLocation string            `json:"downloadLocation,omitempty"`
	SourceInfo       string            `json:"sourceInfo,omitempty"`
	LicenseConcluded string            `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string            `json:"licenseDeclared,omitempty"`
	CopyrightText    string            `json:"copyrightText,omitempty"`
	ExternalRefs     []SBOMExternalRef `json:"externalRefs,omitempty"`
	FilesAnalyzed    bool              `json:"filesAnalyzed,omitempty"`
}

// SBOMExternalRef represents SPDX/SBOM external reference details
type SBOMExternalRef struct {
	ReferenceCategory string `json:"referenceCategory,omitempty"`
	ReferenceType     string `json:"referenceType,omitempty"`
	ReferenceLocator  string `json:"referenceLocator,omitempty"`
}

// SBOMSummary contains summary information about the SBOM
type SBOMSummary struct {
	LicenseDistribution    map[string]int `json:"license_distribution"`
	AllLicenses            []string       `json:"all_licenses"`
	TotalPackages          int            `json:"total_packages"`
	PackagesWithoutLicense int            `json:"packages_without_license"`
}

// VulnerabilityPayload represents vulnerability payload (summary + vulnerabilities)
type VulnerabilityPayload struct {
	Metadata        PayloadMetadata      `json:"metadata"`
	Type            string               `json:"type"`
	Vulnerabilities []Vulnerability      `json:"vulnerabilities"`
	Summary         VulnerabilitySummary `json:"summary"`
}

// Vulnerability represents a single vulnerability found in a scan.
type Vulnerability struct {
	Package      Package  `json:"package"`
	ID           string   `json:"id"`
	Severity     string   `json:"severity"`
	Description  string   `json:"description"`
	FixedVersion string   `json:"fixed_version,omitempty"`
	Location     Location `json:"location"`
	References   []string `json:"references,omitempty"`
	Score        float64  `json:"score,omitempty"`
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
