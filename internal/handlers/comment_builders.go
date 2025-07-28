package handlers

import (
	"fmt"
	"strings"

	"github.com/terrpan/polly/internal/services"
)

// buildVulnerabilityViolationComment generates a markdown comment for vulnerability policy violations.
func buildVulnerabilityViolationComment(vulns []services.VulnerabilityPolicyVuln) string {
	vulnComments := make([]string, 0, len(vulns))
	for _, vuln := range vulns {
		comment := fmt.Sprintf("**Package:** `%s@%s`\n**Vulnerability:** %s\n**Severity:** %s",
			vuln.Package, vuln.Version, vuln.ID, vuln.Severity)

		if vuln.Score > 0 {
			comment += fmt.Sprintf("\n**CVSS Score:** %.1f", vuln.Score)
		}

		if vuln.FixedVersion != "" {
			comment += fmt.Sprintf("\n**Fixed Version:** `%s`", vuln.FixedVersion)
		}

		vulnComments = append(vulnComments, comment)
	}

	return fmt.Sprintf(
		"❌ **Vulnerability Policy Violation - %d vulnerabilities blocked**\n\n<details>\n<summary>Click to view policy violation details</summary>\n\n%s\n\n</details>",
		len(vulnComments),
		strings.Join(vulnComments, "\n\n---\n\n"),
	)
}

// buildLicenseComment generates a single markdown comment for both license violations and conditional licenses.
func buildLicenseComment(
	violations []services.SBOMPolicyComponent,
	conditionals []services.SBOMPolicyComponent,
) string {
	var sections []string

	if len(violations) > 0 {
		violationSection := buildLicenseViolationSection(violations)
		sections = append(sections, violationSection)
	}

	if len(conditionals) > 0 {
		conditionalSection := buildLicenseConditionalSection(conditionals)
		sections = append(sections, conditionalSection)
	}

	return strings.Join(sections, "\n\n")
}

// buildLicenseViolationSection creates the violations section of the license comment
func buildLicenseViolationSection(violations []services.SBOMPolicyComponent) string {
	violationComments := make([]string, 0, len(violations))
	for _, component := range violations {
		comment := buildComponentComment(component)
		violationComments = append(violationComments, comment)
	}

	return fmt.Sprintf(
		"❌ **License Violations Found - %d packages**\n\nThe following packages have licenses that violate our policy and must be addressed:\n\n<details>\n<summary>Click to view license violations</summary>\n\n%s\n\n</details>",
		len(violationComments),
		strings.Join(violationComments, "\n\n---\n\n"),
	)
}

// buildLicenseConditionalSection creates the conditional licenses section of the license comment
func buildLicenseConditionalSection(conditionals []services.SBOMPolicyComponent) string {
	conditionalComments := make([]string, 0, len(conditionals))
	for _, component := range conditionals {
		comment := buildComponentComment(component)
		conditionalComments = append(conditionalComments, comment)
	}

	return fmt.Sprintf(
		"ℹ️ **Conditionally Allowed Licenses Found - %d packages require consideration**\n\nThe following packages use licenses that are allowed but should be used with consideration. Please review these packages and their licenses to ensure they meet your project's requirements:\n\n<details>\n<summary>Click to view conditionally allowed licenses</summary>\n\n%s\n\n</details>",
		len(conditionalComments),
		strings.Join(conditionalComments, "\n\n---\n\n"),
	)
}

// buildComponentComment creates a markdown comment for a single SBOM component
func buildComponentComment(component services.SBOMPolicyComponent) string {
	comment := fmt.Sprintf("**Package:** `%s`", component.Name)

	if component.VersionInfo != "" {
		comment += fmt.Sprintf("@%s", component.VersionInfo)
	}

	if component.LicenseDeclared != "" {
		comment += fmt.Sprintf("\n**License Declared:** %s", component.LicenseDeclared)
	} else if component.LicenseConcluded != "" {
		comment += fmt.Sprintf("\n**License Concluded:** %s", component.LicenseConcluded)
	}

	if component.Supplier != "" {
		comment += fmt.Sprintf("\n**Supplier:** %s", component.Supplier)
	}

	if component.SPDXID != "" {
		comment += fmt.Sprintf("\n**SPDX ID:** `%s`", component.SPDXID)
	}

	return comment
}
