# OPA Compliance Policies

This directory contains Open Policy Agent (OPA) policies for security compliance checking, specifically designed to work with Software Bill of Materials (SBOM) and vulnerability data from security scanning tools.

---

## Overview

The OPA policies provide:
- **License Compliance**: Check SBOM packages against allowed/blocked license lists
- **Vulnerability Compliance**: Validate vulnerability scan results against severity thresholds and CVE blocklists
- **Data-Driven Configuration**: All rules and thresholds are configurable via JSON data files

## Architecture

### Bundle Structure
```
bundle/
├── compliance/
│   ├── main.rego          # Core policy logic
│   ├── main_test.rego     # Test suite
│   └── data.json          # Configuration data
```

### Configuration (data.json)
The policies are entirely data-driven, with all configuration stored in `data.json`:

```json
{
  "license_config": {
    "allowed_licenses": ["MIT", "Apache-2.0", "BSD-2-Clause", ...],
    "conditionally_allowed_licenses": ["GPL-2.0", "GPL-3.0", "AGPL-3.0"],
    "blocked_licenses": ["GPL-2.0-only", "GPL-3.0-only"]
  },
  "vulnerability_config": {
    "max_allowed_severity": "MEDIUM",
    "severity_order": {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1},
    "blocked_cves": ["CVE-2021-23369", ...]
  }
}
```

## Usage

### Start OPA Server
```bash
opa run --server --bundle bundle/ --watch
```

### API Endpoints

#### Vulnerability Compliance
```bash
curl -s -X POST http://localhost:8181/v1/data/compliance/vulnerability_report \
  -H "Content-Type: application/json" \
  -d @sample/vuln_trivy_sample.json | jq
```

#### License Compliance
```bash
curl -s -X POST http://localhost:8181/v1/data/compliance/license_report \
  -H "Content-Type: application/json" \
  -d @sample/sbom_sample.json | jq
```

#### SBOM Compliance Check
```bash
curl -s -X POST http://localhost:8181/v1/data/compliance/sbom_compliant \
  -H "Content-Type: application/json" \
  -d @sample/sbom_sample.json | jq
```

## Policy Details

### License Policy
- **Input**: SPDX-format SBOM with packages array
- **Logic**: Combines allowed licenses with conditionally allowed licenses, minus blocked licenses
- **Output**: Compliance status, non-compliant packages, and detailed report

Key rules:
- `sbom_compliant`: Returns true if all packages have allowed licenses
- `license_report`: Comprehensive compliance report with counts and details
- `allowed_licenses`: Dynamically computed from configuration

### Vulnerability Policy
- **Input**: Vulnerability scan results (Trivy format)
- **Logic**: Checks severity levels and CVE blocklists
- **Output**: Compliance status and non-compliant vulnerability details

Key rules:
- `vulnerabilities_compliant`: Returns true if all vulnerabilities meet criteria
- `vulnerability_report`: Comprehensive vulnerability report
- `non_compliant_vulnerabilities`: List of failing vulnerabilities

## Testing

Run the comprehensive test suite:
```bash
opa test bundle/
```

The test suite includes:
- License compliance scenarios (compliant/non-compliant)
- Vulnerability compliance scenarios (various severity levels)
- SPDX license field handling (licenseConcluded/licenseDeclared)
- Edge cases (empty packages, unknown licenses)

## Sample Data

### SBOM Sample (`sample/sbom_sample.json`)
Contains example SPDX document with mixed license compliance:
- Compliant packages: MIT, Apache-2.0, BSD-3-Clause
- Non-compliant package: GPL-2.0-only (blocked)

### Vulnerability Sample (`sample/vuln_trivy_sample.json`)
Contains example Trivy vulnerability scan with:
- Various severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- Mix of compliant and non-compliant vulnerabilities
- Blocked CVE examples

## Configuration Management

### Adding New Blocked Licenses
Edit `bundle/compliance/data.json`:
```json
{
  "license_config": {
    "blocked_licenses": ["GPL-2.0-only", "GPL-3.0-only", "AGPL-3.0"]
  }
}
```

### Changing Vulnerability Thresholds
Edit `bundle/compliance/data.json`:
```json
{
  "vulnerability_config": {
    "max_allowed_severity": "LOW",
    "blocked_cves": ["CVE-2021-23369"]
  }
}
```

## Integration

### With Security Services
The policies are designed to work with:
- **SPDX SBOM**: Standard format for software bill of materials
- **Trivy**: Vulnerability scanner output format
- **Custom Security Payloads**: SBOMPayload and VulnerabilityPayload structures

### Response Format
All endpoints return consistent JSON with:
- `compliant`: Boolean compliance status
- `total_*`: Count of total items processed
- `non_compliant_*`: Details of non-compliant items
- Additional metadata and configuration details

## Future Enhancements

### Planned Features
- [ ] OCI registry support for storing policies
- [ ] Policy versioning and rollback capabilities
- [ ] Advanced license compatibility matrix
- [ ] Integration with CI/CD pipelines
- [ ] Webhook support for real-time compliance checking
