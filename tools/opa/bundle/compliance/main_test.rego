package compliance_test

import rego.v1

import data.compliance

# Test SBOM license compliance
test_sbom_all_compliant if {
	compliant_sbom := {"packages": [
		{"name": "express", "licenseConcluded": "MIT"},
		{"name": "lodash", "licenseConcluded": "Apache-2.0"},
		{"name": "react", "licenseConcluded": "BSD-3-Clause"},
	]}
	compliance.sbom_compliant with input as compliant_sbom
}

test_sbom_non_compliant if {
	non_compliant_sbom := {"packages": [
		{"name": "express", "licenseConcluded": "MIT"},
		{"name": "bad-lib", "licenseConcluded": "Proprietary"},
	]}
	not compliance.sbom_compliant with input as non_compliant_sbom
}

test_sbom_empty_packages if {
	empty_sbom := {"packages": []}
	not compliance.sbom_compliant with input as empty_sbom
}

test_non_compliant_licenses if {
	mixed_sbom := {"packages": [
		{"name": "good-lib", "licenseConcluded": "MIT"},
		{"name": "bad-lib1", "licenseConcluded": "Proprietary"},
		{"name": "bad-lib2", "licenseConcluded": "WTFPL"},
	]}
	expected := {"Proprietary", "WTFPL"}
	compliance.non_compliant_licenses == expected with input as mixed_sbom
}

test_spdx_license_declared_fallback if {
	spdx_sbom := {"packages": [
		{"name": "lib1", "licenseConcluded": "NOASSERTION", "licenseDeclared": "MIT"},
		{"name": "lib2", "licenseConcluded": "Apache-2.0"},
	]}
	compliance.sbom_compliant with input as spdx_sbom
}

test_license_report_fields if {
	test_sbom := {"packages": [
		{"name": "lib1", "licenseConcluded": "MIT"},
		{"name": "lib2", "licenseConcluded": "Apache-2.0"},
	]}

	# Test that the license report has expected structure
	report := compliance.license_report with input as test_sbom
	is_object(report)
	count(report) > 0
}

# Test vulnerabilities policy - compliant cases
test_vulnerabilities_compliant if {
	# New nested payload format with valid CVE IDs and acceptable severity
	sample := {"type": "trivy", "metadata": {}, "vulnerabilities": [
		{"id": "CVE-2025-0001", "package": {"name": "pkg1", "version": "1.0.0"}, "severity": "LOW"},
		{"id": "CVE-2025-0002", "package": {"name": "pkg2", "version": "2.0.0"}, "severity": "MEDIUM"},
	]}
	compliance.vulnerabilities_compliant with input as sample
}

test_vulnerabilities_non_compliant_blocked_cve if {
	# Test blocked CVE is rejected (even with low severity)
	sample := {"type": "trivy", "metadata": {}, "vulnerabilities": [{"id": "CVE-2021-23369", "package": {"name": "pkg1", "version": "1.0.0"}, "severity": "LOW"}]}
	not compliance.vulnerabilities_compliant with input as sample
}

test_vulnerabilities_non_compliant_high_severity if {
	# Test HIGH severity is blocked (severity-based blocking)
	sample := {"type": "trivy", "metadata": {}, "vulnerabilities": [{"id": "CVE-2025-0001", "package": {"name": "pkg1", "version": "1.0.0"}, "severity": "HIGH"}]}
	not compliance.vulnerabilities_compliant with input as sample
}

test_vulnerabilities_non_compliant_critical_severity if {
	# Test CRITICAL severity is blocked (severity-based blocking)
	sample := {"type": "trivy", "metadata": {}, "vulnerabilities": [{"id": "CVE-2025-0002", "package": {"name": "pkg1", "version": "1.0.0"}, "severity": "CRITICAL"}]}
	not compliance.vulnerabilities_compliant with input as sample
}

test_vulnerabilities_compliant_with_non_cve_id if {
	# Test that non-CVE IDs are now allowed (GHSA, NSWG, etc.)
	sample := {"type": "trivy", "metadata": {}, "vulnerabilities": [{"id": "GHSA-vjh7-7g9h-fjfh", "package": {"name": "pkg1", "version": "1.0.0"}, "severity": "LOW"}]}
	compliance.vulnerabilities_compliant with input as sample
}

test_non_compliant_vulnerabilities_list if {
	sample := {"type": "trivy", "metadata": {}, "vulnerabilities": [
		{"id": "CVE-2025-0001", "package": {"name": "pkg1", "version": "1.0.0"}, "severity": "HIGH"},
		{"id": "CVE-2021-23369", "package": {"name": "pkg2", "version": "2.0.0"}, "severity": "LOW"},
	]}

	# Convert array to set for comparison - HIGH severity and blocked CVE should be non-compliant
	expected := {v | some v in sample.vulnerabilities}
	compliance.non_compliant_vulnerabilities == expected with input as sample
}
