package compliance

import rego.v1

# SBOM License Policy - New SBOMPayload Format Support
# This policy works with the new SBOMPayload structure that contains metadata, summary, and packages
# All configuration data is loaded from data.json

# Get allowed licenses from data.json configuration
allowed_licenses := licenses if {
	# Convert JSON arrays to sets for set operations
	base_allowed := {license | some license in data.compliance.license_config.allowed_licenses}
	conditional := {license | some license in data.compliance.license_config.conditionally_allowed_licenses}
	blocked := {license | some license in data.compliance.license_config.blocked_licenses}

	# Final allowed licenses = base + (conditional - blocked)
	licenses := base_allowed | (conditional - blocked)
}

# Extract license from SPDX package (handles new SBOMPackage structure)
package_license(pkg) := license if {
	# Direct licenseConcluded field
	license := pkg.licenseConcluded
	license != "NOASSERTION"
	license != "NONE"
	license != ""
} else := license if {
	# licenseDeclared field as fallback
	license := pkg.licenseDeclared
	license != "NOASSERTION"
	license != "NONE"
	license != ""
} else := "UNKNOWN"

# Check if new SBOM payload is compliant (all packages have allowed licenses)
default sbom_compliant := false

sbom_compliant if {
	# New SBOMPayload format with packages array
	count(input.packages) > 0
	every pkg in input.packages {
		license := package_license(pkg)
		license in allowed_licenses
		license != "UNKNOWN"
	}
}

# Get all non-compliant licenses found in SBOM
non_compliant_licenses contains license if {
	# New SBOMPayload format
	some pkg in input.packages
	license := package_license(pkg)
	not license in allowed_licenses
	license != "UNKNOWN"
}

# Get packages with non-compliant licenses
non_compliant_components contains pkg if {
	# New SBOMPayload format
	some pkg in input.packages
	license := package_license(pkg)
	not license in allowed_licenses
}

# Get all conditional components (conditionally allowed licenses)
conditional_components contains pkg if {
	# New SBOMPayload format
	some pkg in input.packages
	license := package_license(pkg)
	license in data.compliance.license_config.conditionally_allowed_licenses
	not license in data.compliance.license_config.blocked_licenses
	license != "UNKNOWN"
}

# Check if a specific component is compliant
component_compliant(component) if {
	license := package_license(component)
	license in allowed_licenses
	license != "UNKNOWN"
}

# Generate license compliance report for new SBOMPayload format
license_report := {
	"compliant": sbom_compliant,
	"total_components": count(input.packages),
	"compliant_components": count([pkg |
		some pkg in input.packages
		license := package_license(pkg)
		license in allowed_licenses
		license != "UNKNOWN"
	]),
	"non_compliant_licenses": non_compliant_licenses,
	"non_compliant_components": non_compliant_components,
	"allowed_licenses": allowed_licenses,
	"conditional_components": conditional_components,
}

# Vulnerability Policy - Combined severity and blocklist-based compliance
# Configuration is loaded from data.json for easier maintenance
# To update severity levels, max allowed severity, or blocked vulnerability IDs,
# edit the vulnerability_config section in data.json

# Default to non-compliant
default vulnerabilities_compliant := false

# Compliant if all vulnerabilities meet criteria:
# 1. Are at or below the max allowed severity level (configured in data.json)
# 2. Are not in the blocked vulnerability IDs list (extra failsafe)
vulnerabilities_compliant if {
	count(input.vulnerabilities) > 0
	config := data.compliance.vulnerability_config
	max_allowed_severity := config.max_allowed_severity
	max_allowed_order := config.severity_order[max_allowed_severity]

	every v in input.vulnerabilities {
		# Block vulnerabilities above max allowed severity using data from JSON
		config.severity_order[v.severity] <= max_allowed_order

		# Extra failsafe: Check vulnerability ID is not in blocklist from JSON
		not v.id in config.blocked_cves
	}
}

# List vulnerabilities that fail compliance
non_compliant_vulnerabilities contains v if {
	some v in input.vulnerabilities
	config := data.compliance.vulnerability_config
	max_allowed_severity := config.max_allowed_severity
	max_allowed_order := config.severity_order[max_allowed_severity]

	# Severity too high (above max allowed) using data from JSON
	config.severity_order[v.severity] > max_allowed_order
}

non_compliant_vulnerabilities contains v if {
	some v in input.vulnerabilities
	config := data.compliance.vulnerability_config

	# In the blocked vulnerability IDs list from JSON
	v.id in config.blocked_cves
}

# Single comprehensive vulnerability_report endpoint with simplified output
vulnerability_report := {
	"compliant": vulnerabilities_compliant,
	"total_vulnerabilities": count(input.vulnerabilities),
	"compliant_count": count(input.vulnerabilities) - count(non_compliant_vulnerabilities),
	"non_compliant_count": count(non_compliant_vulnerabilities),
	"non_compliant_vulnerabilities": non_compliant_simple,
}

# Simplified non-compliant vulnerability list with only essential fields
non_compliant_simple contains vuln_simple if {
	some vuln in non_compliant_vulnerabilities
	vuln_simple := {
		"id": vuln.id,
		"severity": vuln.severity,
		"package": object.get(object.get(vuln, "package", {}), "name", object.get(vuln, "package", "")),
		"version": object.get(object.get(vuln, "package", {}), "version", object.get(vuln, "version", "")),
		"fixed_version": object.get(vuln, "fixed_version", ""),
	}
}
