package compliance_test

import rego.v1

import data.compliance as policy

# Test SBOM license compliance - New SBOMPayload format

import data.compliance

test_sbom_all_compliant if {
	# Test new SBOMPayload format
	compliant_sbom := {
		"metadata": {
			"source_format": "spdx_json",
			"tool_name": "spdx-tools",
			"scan_time": "2025-01-15T10:30:00Z",
			"repository": "test/repo",
			"commit_sha": "abc123",
			"scan_target": "test.spdx.json",
			"schema_version": "SPDX-2.3",
		},
		"summary": {
			"total_packages": 3,
			"all_licenses": ["MIT", "Apache-2.0", "BSD-3-Clause"],
			"license_distribution": {"MIT": 1, "Apache-2.0": 1, "BSD-3-Clause": 1},
			"packages_without_license": 0,
		},
		"packages": [
			{
				"name": "express",
				"SPDXID": "SPDXRef-Package-express",
				"versionInfo": "4.18.0",
				"licenseConcluded": "MIT",
				"licenseDeclared": "MIT",
			},
			{
				"name": "lodash",
				"SPDXID": "SPDXRef-Package-lodash",
				"versionInfo": "4.17.21",
				"licenseConcluded": "Apache-2.0",
				"licenseDeclared": "Apache-2.0",
			},
			{
				"name": "react",
				"SPDXID": "SPDXRef-Package-react",
				"versionInfo": "18.2.0",
				"licenseConcluded": "BSD-3-Clause",
				"licenseDeclared": "BSD-3-Clause",
			},
		],
	}
	policy.sbom_compliant with input as compliant_sbom
}

test_sbom_non_compliant if {
	# Test new SBOMPayload format with non-compliant license
	non_compliant_sbom := {
		"metadata": {
			"source_format": "spdx_json",
			"tool_name": "spdx-tools",
			"scan_time": "2025-01-15T10:30:00Z",
			"repository": "test/repo",
			"commit_sha": "abc123",
			"scan_target": "test.spdx.json",
			"schema_version": "SPDX-2.3",
		},
		"summary": {
			"total_packages": 2,
			"all_licenses": ["MIT", "GPL-2.0-only"],
			"license_distribution": {"MIT": 1, "GPL-2.0-only": 1},
			"packages_without_license": 0,
		},
		"packages": [
			{
				"name": "express",
				"SPDXID": "SPDXRef-Package-express",
				"versionInfo": "4.18.0",
				"licenseConcluded": "MIT",
				"licenseDeclared": "MIT",
			},
			{
				"name": "bad-lib",
				"SPDXID": "SPDXRef-Package-bad-lib",
				"versionInfo": "1.0.0",
				"licenseConcluded": "GPL-2.0-only",
				"licenseDeclared": "GPL-2.0-only",
			},
		],
	}
	not policy.sbom_compliant with input as non_compliant_sbom
}

test_sbom_empty_packages if {
	# Test new SBOMPayload format with empty packages
	empty_sbom := {
		"metadata": {
			"source_format": "spdx_json",
			"tool_name": "spdx-tools",
			"scan_time": "2025-01-15T10:30:00Z",
			"repository": "test/repo",
			"commit_sha": "abc123",
			"scan_target": "test.spdx.json",
			"schema_version": "SPDX-2.3",
		},
		"summary": {
			"total_packages": 0,
			"all_licenses": [],
			"license_distribution": {},
			"packages_without_license": 0,
		},
		"packages": [],
	}
	not policy.sbom_compliant with input as empty_sbom
}

test_non_compliant_licenses if {
	# Test new SBOMPayload format with blocked licenses
	mixed_sbom := {
		"metadata": {
			"source_format": "spdx_json",
			"tool_name": "spdx-tools",
			"scan_time": "2025-01-15T10:30:00Z",
			"repository": "test/repo",
			"commit_sha": "abc123",
			"scan_target": "test.spdx.json",
			"schema_version": "SPDX-2.3",
		},
		"summary": {
			"total_packages": 3,
			"all_licenses": ["MIT", "GPL-2.0-only", "GPL-3.0-only"],
			"license_distribution": {"MIT": 1, "GPL-2.0-only": 1, "GPL-3.0-only": 1},
			"packages_without_license": 0,
		},
		"packages": [
			{
				"name": "good-lib",
				"SPDXID": "SPDXRef-Package-good-lib",
				"versionInfo": "1.0.0",
				"licenseConcluded": "MIT",
				"licenseDeclared": "MIT",
			},
			{
				"name": "bad-lib1",
				"SPDXID": "SPDXRef-Package-bad-lib1",
				"versionInfo": "1.0.0",
				"licenseConcluded": "GPL-2.0-only",
				"licenseDeclared": "GPL-2.0-only",
			},
			{
				"name": "bad-lib2",
				"SPDXID": "SPDXRef-Package-bad-lib2",
				"versionInfo": "1.0.0",
				"licenseConcluded": "GPL-3.0-only",
				"licenseDeclared": "GPL-3.0-only",
			},
		],
	}
	expected := {"GPL-2.0-only", "GPL-3.0-only"}
	policy.non_compliant_licenses == expected with input as mixed_sbom
}

test_spdx_license_declared_fallback if {
	# Test new SBOMPayload format with licenseDeclared fallback
	spdx_sbom := {
		"metadata": {
			"source_format": "spdx_json",
			"tool_name": "spdx-tools",
			"scan_time": "2025-01-15T10:30:00Z",
			"repository": "test/repo",
			"commit_sha": "abc123",
			"scan_target": "test.spdx.json",
			"schema_version": "SPDX-2.3",
		},
		"summary": {
			"total_packages": 2,
			"all_licenses": ["MIT", "Apache-2.0"],
			"license_distribution": {"MIT": 1, "Apache-2.0": 1},
			"packages_without_license": 0,
		},
		"packages": [
			{
				"name": "lib1",
				"SPDXID": "SPDXRef-Package-lib1",
				"versionInfo": "1.0.0",
				"licenseConcluded": "NOASSERTION",
				"licenseDeclared": "MIT",
			},
			{
				"name": "lib2",
				"SPDXID": "SPDXRef-Package-lib2",
				"versionInfo": "1.0.0",
				"licenseConcluded": "Apache-2.0",
				"licenseDeclared": "Apache-2.0",
			},
		],
	}
	policy.sbom_compliant with input as spdx_sbom
}

test_license_report_fields if {
	# Test new SBOMPayload format license report structure
	test_sbom := {
		"metadata": {
			"source_format": "spdx_json",
			"tool_name": "spdx-tools",
			"scan_time": "2025-01-15T10:30:00Z",
			"repository": "test/repo",
			"commit_sha": "abc123",
			"scan_target": "test.spdx.json",
			"schema_version": "SPDX-2.3",
		},
		"summary": {
			"total_packages": 2,
			"all_licenses": ["MIT", "Apache-2.0"],
			"license_distribution": {"MIT": 1, "Apache-2.0": 1},
			"packages_without_license": 0,
		},
		"packages": [
			{
				"name": "lib1",
				"SPDXID": "SPDXRef-Package-lib1",
				"versionInfo": "1.0.0",
				"licenseConcluded": "MIT",
				"licenseDeclared": "MIT",
			},
			{
				"name": "lib2",
				"SPDXID": "SPDXRef-Package-lib2",
				"versionInfo": "1.0.0",
				"licenseConcluded": "Apache-2.0",
				"licenseDeclared": "Apache-2.0",
			},
		],
	}

	# Test that the license report has expected structure
	report := policy.license_report with input as test_sbom
	is_object(report)
	count(report) > 0
	report.total_components == 2
	report.compliant_components == 2
	report.compliant == true
}

# Test vulnerabilities policy - compliant cases
test_vulnerabilities_compliant if {
	# New nested payload format with valid CVE IDs and acceptable severity
	sample := {"type": "trivy", "metadata": {}, "vulnerabilities": [
		{"id": "CVE-2025-0001", "package": {"name": "pkg1", "version": "1.0.0"}, "severity": "LOW"},
		{"id": "CVE-2025-0002", "package": {"name": "pkg2", "version": "2.0.0"}, "severity": "MEDIUM"},
	]}
	policy.vulnerabilities_compliant with input as sample
}

test_vulnerabilities_non_compliant_blocked_cve if {
	# Test blocked CVE is rejected (even with low severity)
	sample := {"type": "trivy", "metadata": {}, "vulnerabilities": [{"id": "CVE-2021-23369", "package": {"name": "pkg1", "version": "1.0.0"}, "severity": "LOW"}]}
	not policy.vulnerabilities_compliant with input as sample
}

test_vulnerabilities_non_compliant_high_severity if {
	# Test HIGH severity is blocked (severity-based blocking)
	sample := {"type": "trivy", "metadata": {}, "vulnerabilities": [{"id": "CVE-2025-0001", "package": {"name": "pkg1", "version": "1.0.0"}, "severity": "HIGH"}]}
	not policy.vulnerabilities_compliant with input as sample
}

test_vulnerabilities_non_compliant_critical_severity if {
	# Test CRITICAL severity is blocked (severity-based blocking)
	sample := {"type": "trivy", "metadata": {}, "vulnerabilities": [{"id": "CVE-2025-0002", "package": {"name": "pkg1", "version": "1.0.0"}, "severity": "CRITICAL"}]}
	not policy.vulnerabilities_compliant with input as sample
}

test_vulnerabilities_compliant_with_non_cve_id if {
	# Test that non-CVE IDs are now allowed (GHSA, NSWG, etc.)
	sample := {"type": "trivy", "metadata": {}, "vulnerabilities": [{"id": "GHSA-vjh7-7g9h-fjfh", "package": {"name": "pkg1", "version": "1.0.0"}, "severity": "LOW"}]}
	policy.vulnerabilities_compliant with input as sample
}

test_non_compliant_vulnerabilities_list if {
	sample := {"type": "trivy", "metadata": {}, "vulnerabilities": [
		{"id": "CVE-2025-0001", "package": {"name": "pkg1", "version": "1.0.0"}, "severity": "HIGH"},
		{"id": "CVE-2021-23369", "package": {"name": "pkg2", "version": "2.0.0"}, "severity": "LOW"},
	]}

	# Convert array to set for comparison - HIGH severity and blocked CVE should be non-compliant
	expected := {v | some v in sample.vulnerabilities}
	policy.non_compliant_vulnerabilities == expected with input as sample
}
