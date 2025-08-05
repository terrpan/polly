package services

import (
	"errors"

	dbtypes "github.com/aquasecurity/trivy-db/pkg/types"
)

// Content detection errors
var (
	ErrUnsupportedContentType = errors.New("unsupported content type")
	ErrContentDetectionFailed = errors.New("content detection failed")
)

// cvssPriority defines the order of CVSS sources to check for scores.
var cvssPriority = []dbtypes.SourceID{"nvd", "redhat", "ghsa"}

// ContentDetector interface for strategy pattern
type ContentDetector interface {
	CanHandle(content []byte, filename string) bool
	GetContentType() string
	GetArtifactType() ArtifactType
	GetPriority() int // Lower numbers = higher priority
}

// SPDXDetector handles SPDX content detection
type SPDXDetector struct{}

// CanHandle determines if the content is SPDX format
func (d *SPDXDetector) CanHandle(content []byte, filename string) bool {
	return isSPDXContent(content)
}

// GetContentType returns the content type for SPDX
func (d *SPDXDetector) GetContentType() string {
	return "spdx"
}

// GetArtifactType returns the artifact type for SPDX
func (d *SPDXDetector) GetArtifactType() ArtifactType {
	return ArtifactTypeSBOMSPDX
}

// GetPriority returns the priority (1 = highest priority)
func (d *SPDXDetector) GetPriority() int {
	return 1
}

// TrivyJSONDetector handles Trivy JSON content detection
type TrivyJSONDetector struct{}

// CanHandle determines if the content is Trivy JSON format
func (d *TrivyJSONDetector) CanHandle(content []byte, filename string) bool {
	return isTrivyJSONContent(content)
}

// GetContentType returns the content type for Trivy JSON
func (d *TrivyJSONDetector) GetContentType() string {
	return "trivy-json"
}

// GetArtifactType returns the artifact type for Trivy JSON
func (d *TrivyJSONDetector) GetArtifactType() ArtifactType {
	return ArtifactTypeVulnerabilityJSON
}

// GetPriority returns the priority (2 = second priority)
func (d *TrivyJSONDetector) GetPriority() int {
	return 2
}

// SARIFDetector handles SARIF content detection
type SARIFDetector struct{}

// CanHandle determines if the content is SARIF format
func (d *SARIFDetector) CanHandle(content []byte, filename string) bool {
	return isSarifContent(content)
}

// GetContentType returns the content type for SARIF
func (d *SARIFDetector) GetContentType() string {
	return "sarif"
}

// GetArtifactType returns the artifact type for SARIF
func (d *SARIFDetector) GetArtifactType() ArtifactType {
	return ArtifactTypeVulnerabilitySARIF
}

// GetPriority returns the priority (3 = third priority)
func (d *SARIFDetector) GetPriority() int {
	return 3
}

// DefaultSecurityDetectors returns the standard set of content detectors
func DefaultSecurityDetectors() []ContentDetector {
	return []ContentDetector{
		&SPDXDetector{},
		&TrivyJSONDetector{},
		&SARIFDetector{},
	}
}
