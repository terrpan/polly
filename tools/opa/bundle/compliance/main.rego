package compliance

import rego.v1

# SBOM License Policy - JSON-SPDX Format Support

# Define allowed open source licenses
allowed_licenses := {
	"MIT",
	"Apache-2.0",
	"BSD-2-Clause",
	"BSD-3-Clause",
	"ISC",
	"GPL-3.0",
	"LGPL-2.1",
	"LGPL-3.0",
	"MPL-2.0",
}

# Extract license from SPDX package (handles various SPDX license formats)
package_license(pkg) := license if {
	# Direct licenseConcluded field
	license := pkg.licenseConcluded
	license != "NOASSERTION"
	license != "NONE"
} else := license if {
	# licenseDeclared field as fallback
	license := pkg.licenseDeclared
	license != "NOASSERTION"
	license != "NONE"
} else := license if {
	# Extract from licenseInfoFromFiles array
	count(pkg.licenseInfoFromFiles) > 0
	license := pkg.licenseInfoFromFiles[0]
	license != "NOASSERTION"
	license != "NONE"
} else := "UNKNOWN"

# Check if SPDX SBOM is compliant (all licenses are allowed)
sbom_compliant if {
	# SPDX format with packages array
	count(input.packages) > 0
	every pkg in input.packages {
		license := package_license(pkg)
		license in allowed_licenses
	}
} else if {
	# Simple format with components array
	count(input.components) > 0
	every component in input.components {
		component.license in allowed_licenses
	}
}

# Get all non-compliant licenses found in SPDX SBOM
non_compliant_licenses contains license if {
	# SPDX format
	some pkg in input.packages
	license := package_license(pkg)
	not license in allowed_licenses
	license != "UNKNOWN"
}

non_compliant_licenses contains license if {
	# Simple format
	some component in input.components
	license := component.license
	not license in allowed_licenses
}

# Get packages with non-compliant licenses
non_compliant_components contains pkg if {
	# SPDX format
	some pkg in input.packages
	license := package_license(pkg)
	not license in allowed_licenses
}

non_compliant_components contains component if {
	# Simple format
	some component in input.components
	not component.license in allowed_licenses
}

# Check if a specific component is compliant
component_compliant(component) if {
	license := package_license(component)
	license in allowed_licenses
}

# Generate license compliance report
license_report := {
	"compliant": sbom_compliant,
	"total_components": count(object.get(input, "packages", object.get(input, "components", []))),
	"compliant_components": count([c |
		packages := object.get(input, "packages", object.get(input, "components", []))
		some c in packages
		license := package_license(c)
		license in allowed_licenses
	]),
	"non_compliant_licenses": non_compliant_licenses,
	"non_compliant_components": non_compliant_components,
	"allowed_licenses": allowed_licenses,
}

# Vulnerability Policy - Combined severity and blocklist-based compliance
# Configuration is loaded from data.json for easier maintenance
# To update severity levels or blocked vulnerability IDs, edit the vulnerability_config section in data.json

# Default to non-compliant
default vulnerabilities_compliant := false

# Compliant if all vulnerabilities meet criteria:
# 1. Are MEDIUM or below severity (HIGH and above are blocked)
# 2. Are not in the blocked vulnerability IDs list (extra failsafe)
vulnerabilities_compliant if {
	count(input.vulnerabilities) > 0
	config := data.compliance.vulnerability_config
	every v in input.vulnerabilities {
		# Block HIGH and above severity using data from JSON
		config.severity_order[v.severity] <= config.severity_order.MEDIUM

		# Extra failsafe: Check vulnerability ID is not in blocklist from JSON
		not v.id in config.blocked_cves
	}
}

# List vulnerabilities that fail compliance
non_compliant_vulnerabilities contains v if {
	some v in input.vulnerabilities
	config := data.compliance.vulnerability_config

	# Severity too high (HIGH or above) using data from JSON
	config.severity_order[v.severity] > config.severity_order.MEDIUM
}

non_compliant_vulnerabilities contains v if {
	some v in input.vulnerabilities
	config := data.compliance.vulnerability_config

	# In the blocked vulnerability IDs list from JSON
	v.id in config.blocked_cves
}

# Single comprehensive vulnerability endpoint with simplified output
vulnerability := {
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
