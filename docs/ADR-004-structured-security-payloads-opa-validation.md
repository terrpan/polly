# ADR-004: Structured Security Payloads for OPA Validation

## Status
Accepted

## Context
The Polly system needs to evaluate security data from multiple sources including SPDX (Software Package Data Exchange), SARIF (Static Analysis Results Interchange Format), and Trivy JSON files for policy compliance. The existing OPA (Open Policy Agent) integration requires structured, normalized data to make effective policy decisions about vulnerabilities, licenses, and other security concerns.

The key challenges include:
1. **Heterogeneous data sources**: SPDX, SARIF, and Trivy JSON have different structures and purposes
2. **Format complexity**: SARIF is verbose and deeply nested, making parsing complex and error-prone
3. **Policy granularity**: Need to support fine-grained policies (e.g., CVE-specific blocking)
4. **Actionable feedback**: Developers need clear, contextual feedback on policy violations
5. **Extensibility**: System must scale to support future security data types and policy sophistication
6. **Maintainability**: Parsing logic should be simple and leverage existing libraries where possible

## Decision
We will implement a structured payload system that:
1. Extracts and normalizes security data from SPDX, SARIF, and Trivy JSON files
2. Creates standardized JSON payloads for OPA evaluation using generic structures
3. Supports granular policy enforcement with rich metadata
4. Provides contextual information for actionable developer feedback
5. Uses Trivy JSON as the primary format for vulnerability data due to its simpler structure
6. Maintains support for SARIF when required for external integrations (e.g., GitHub Security tab)

### Format Selection Rationale
- **Trivy JSON**: Chosen as the primary vulnerability format because it's easier to parse, has less nesting, and provides direct access to vulnerability metadata
- **SARIF**: Maintained for external tool compatibility but avoided for internal processing due to complexity
- **Generic Payload Structure**: Enables consistent processing regardless of source format while maintaining extensibility

### Payload Structure

#### Vulnerability Payload (Generic - supports both SARIF and Trivy JSON)
```json
{
  "type": "vulnerability_scan",
  "metadata": {
    "source_format": "trivy_json",
    "tool_name": "trivy",
    "tool_version": "0.50.0",
    "scan_time": "2024-01-15T10:30:00Z",
    "repository": "owner/repo",
    "commit_sha": "abc123",
    "pr_number": 42,
    "scan_target": ".",
    "schema_version": "2"
  },
  "vulnerabilities": [
    {
      "id": "CVE-2023-1234",
      "severity": "HIGH",
      "score": 8.5,
      "package": {
        "name": "lodash",
        "version": "4.17.20",
        "ecosystem": "npm"
      },
      "location": {
        "file": "package-lock.json",
        "line": 42
      },
      "description": "Prototype pollution vulnerability in lodash",
      "fixed_version": "4.17.21",
      "references": [
        "https://github.com/advisories/GHSA-...",
        "https://nvd.nist.gov/vuln/detail/CVE-2023-1234"
      ]
    }
  ],
  "summary": {
    "total_vulnerabilities": 15,
    "critical": 2,
    "high": 5,
    "medium": 6,
    "low": 2,
    "info": 0
  }
}
```

#### License Payload (from SPDX)
```json
{
  "type": "license_scan",
  "metadata": {
    "source": "spdx",
    "tool": "syft",
    "version": "0.95.0",
    "scan_time": "2024-01-15T10:30:00Z",
    "repository": "owner/repo",
    "commit_sha": "abc123",
    "pr_number": 42
  },
  "licenses": [
    {
      "id": "MIT",
      "name": "MIT License",
      "category": "permissive",
      "packages": [
        {
          "name": "example-package",
          "version": "1.2.3",
          "ecosystem": "npm",
          "location": "node_modules/example-package"
        }
      ],
      "text": "Copyright (c) 2023...",
      "url": "https://opensource.org/licenses/MIT"
    }
  ],
  "packages": [
    {
      "name": "example-package",
      "version": "1.2.3",
      "ecosystem": "npm",
      "license": "MIT",
      "location": "node_modules/example-package",
      "supplier": "Example Corp",
      "download_location": "https://registry.npmjs.org/example-package/-/example-package-1.2.3.tgz"
    }
  ],
  "summary": {
    "total_packages": 1,
    "unique_licenses": 1,
    "license_categories": {
      "permissive": 1,
      "copyleft": 0,
      "proprietary": 0,
      "unknown": 0
    }
  }
}
```

## Implementation Details

### Data Extraction Process
1. **Artifact Download**: Download SPDX/SARIF/Trivy JSON files from GitHub Actions artifacts
2. **Content Detection**: Identify file types and validate structure using format-specific libraries
3. **Parsing**: Use official libraries (`spdx/tools-golang`, `owenrumney/go-sarif`, `aquasecurity/trivy`)
4. **Normalization**: Transform to standardized payload format using generic structures
5. **OPA Evaluation**: Send structured payloads to policy engine

### Library Selection
- **SPDX**: `github.com/spdx/tools-golang` - Official SPDX parser with comprehensive support
- **SARIF**: `github.com/owenrumney/go-sarif` - Well-maintained with good API design
- **Trivy JSON**: `github.com/aquasecurity/trivy/pkg/types` - Official Trivy types for reliable parsing

### Generic Payload Architecture
The system uses generic Go structures that can represent data from multiple sources:

```go
type SecurityMetadata struct {
    SPDXMetadata          *SPDXMetadata          `json:"spdx_metadata,omitempty"`
    VulnerabilityMetadata *VulnerabilityMetadata `json:"vulnerability_metadata,omitempty"`
}

type VulnerabilityMetadata struct {
    SourceFormat      string               `json:"source_format"`      // "sarif", "trivy_json"
    ToolName          string               `json:"tool_name"`          // "trivy", "semgrep", etc.
    ToolVersion       string               `json:"tool_version"`
    SchemaVersion     string               `json:"schema_version"`
    ScanTarget        string               `json:"scan_target"`
    ResultCount       int                  `json:"result_count"`
    SeverityBreakdown map[string]int       `json:"severity_breakdown"`
    Summary           VulnerabilitySummary `json:"summary"`
}
```

This approach allows the same payload processing logic to work regardless of whether the source was SARIF or Trivy JSON.

### OPA Policy Integration
Policies can leverage the structured data for granular decisions:

```rego
# Example: Block specific CVEs
package security.vulnerabilities

deny[msg] {
    input.type == "vulnerability_scan"
    vuln := input.vulnerabilities[_]
    vuln.id in data.blocked_cves
    msg := sprintf("Blocked CVE detected: %s in package %s", [vuln.id, vuln.package.name])
}

# Example: License compliance
package security.licenses

deny[msg] {
    input.type == "license_scan"
    license := input.licenses[_]
    license.id in data.prohibited_licenses
    msg := sprintf("Prohibited license detected: %s", [license.name])
}
```

## Rationale

### Structured Approach Benefits
1. **Consistency**: Normalized payloads regardless of source format
2. **Extensibility**: Easy to add new data sources or fields
3. **Policy Clarity**: Clear data contracts for policy authors
4. **Developer Experience**: Rich metadata enables actionable feedback

### Payload Design Principles
1. **Hierarchical Organization**: Logical grouping of related data
2. **Metadata Rich**: Sufficient context for debugging and auditing
3. **Summary Statistics**: Quick overview without parsing full payload
4. **Location Information**: Precise file/line references for feedback

### Alternative Approaches Considered
1. **Direct Format Passing**: Would require policies to understand SPDX/SARIF formats
2. **Minimal Payloads**: Would limit policy sophistication and feedback quality
3. **Database Normalization**: Would add complexity without clear benefits for this use case

## Consequences

### Positive
- **Enhanced Policy Capabilities**: Granular control over security decisions
- **Better Developer Experience**: Clear, actionable feedback on violations
- **Maintainable Policies**: Structured data makes policies easier to write and understand
- **Future-Proof**: Architecture supports additional security data types
- **Audit Trail**: Rich metadata supports compliance and debugging
- **Simplified Parsing**: Trivy JSON as primary format reduces complexity while maintaining SARIF compatibility
- **Format Flexibility**: Generic structures allow processing of multiple input formats with consistent output

### Negative
- **Payload Size**: Structured payloads are larger than minimal representations
- **Processing Overhead**: Additional transformation step before OPA evaluation
- **Schema Evolution**: Changes to payload structure require policy updates
- **Dual Format Support**: Maintaining compatibility with both SARIF and Trivy JSON adds complexity

### Mitigation Strategies
- **Efficient Serialization**: Use efficient JSON serialization for large payloads
- **Incremental Processing**: Process artifacts incrementally for large repositories
- **Schema Versioning**: Include schema version in metadata for backward compatibility
- **Documentation**: Maintain clear documentation of payload structure for policy authors
- **Format Detection**: Robust content detection ensures proper parsing regardless of source format

## Future Considerations

### Performance Optimization
- **Worker Pools**: Concurrent processing of multiple artifacts
- **Caching**: Cache parsed results for repeated evaluations
- **Streaming**: Stream large payloads for memory efficiency

### Enhanced Policies
- **Contextual Rules**: Policies based on file types, repository characteristics
- **Risk Scoring**: Combined vulnerability and license risk assessment
- **Exemption Management**: Structured exemption handling with expiration

### Additional Data Sources
- **Container Scanning**: Extend to support container image security data
- **Code Analysis**: Integration with additional static analysis tools
- **Dependency Graphs**: Enhanced dependency relationship modeling

## Implementation Status
- ✅ Artifact download and content detection
- ✅ SPDX parsing integration
- ✅ SARIF parsing integration
- ✅ Trivy JSON parsing integration with official library
- ✅ Generic structured payload generation
- ✅ Multi-format content detection (SPDX, SARIF, Trivy JSON)
- ✅ Basic OPA integration patterns
- 🔄 Policy evaluation endpoint integration
- 🔄 PR comment feedback implementation
- ⏳ Performance optimization (worker pools)
- ⏳ Enhanced policy examples
