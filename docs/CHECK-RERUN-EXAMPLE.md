# Check Rerun Example Walkthrough

This document shows a complete example of how the check rerun functionality works in practice.

## Scenario

A developer creates a PR that initially passes security checks, but later the security policies are updated to be more strict. The developer wants to rerun the license check to see if their code still complies with the new policies.

## Step-by-Step Flow

### 1. Initial Workflow Run (Day 1)

**PR Event**: Developer pushes commit `abc123` to PR #42

**Workflow Execution**:
```
Workflow "Security Scan" starts
├── Trivy vulnerability scan → creates vuln-report.json
├── SBOM generation → creates sbom.json
└── Workflow completes successfully (run ID: 556677)
```

**Webhook Processing**:
```
workflow_run event (action: completed, conclusion: success)
├── Store: sha "abc123" → workflow_run_id 556677
├── Process artifacts from workflow 556677
├── Create vulnerability check (ID: 111) → PASS
└── Create license check (ID: 222) → PASS
```

**Result**: Both checks pass, PR is ready to merge.

### 2. Policy Update (Day 2)

Security team updates license policy to be more restrictive:
- Previously allowed: MIT, Apache-2.0, BSD-3-Clause
- Now allowed: MIT, Apache-2.0 only (BSD-3-Clause removed)

### 3. Developer Reruns Check (Day 2)

Developer notices policy change and wants to verify compliance.

**GitHub UI**: Developer clicks "Re-run" on the "License Check"

**Webhook Received**:
```json
{
  "action": "rerequested",
  "check_run": {
    "id": 222,
    "name": "License Check",
    "head_sha": "abc123",
    "pull_requests": [{"number": 42}]
  }
}
```

**Webhook Processing**:
```
check_run event (action: rerequested)
├── Identify: "License Check" → license check type
├── Store: check_run_id 222 for sha "abc123"
├── Store: PR #42 context for sha "abc123"
├── Lookup: sha "abc123" → workflow_run_id 556677 ✓
├── Process stored artifacts from workflow 556677
├── Re-evaluate SBOM with NEW license policy
├── Find: 3 packages with BSD-3-Clause license (now non-compliant)
├── Post comment: "License violations found..."
└── Complete check: FAILURE
```

**Result**: License check now fails with the updated policy, showing which packages violate the new rules.

## Key Benefits Demonstrated

1. **No CI Re-run**: The original security scans (Trivy, SBOM) didn't need to run again
2. **Policy Updates**: New policies were applied to existing scan data
3. **Fast Feedback**: Results available in seconds, not minutes
4. **Accurate Results**: Same scan data ensures consistent baseline for comparison
5. **Detailed Feedback**: Updated comments show exactly which packages now violate policy

## Technical Details

**Memory Storage** (in webhook handler):
```go
// After initial workflow
artifactStore["abc123"] = 556677
prContextStore["abc123"] = 42
licenseCheckStore["abc123"] = 222

// During rerun
workflowRunID := artifactStore["abc123"]  // → 556677
prNumber := prContextStore["abc123"]      // → 42
checkRunID := licenseCheckStore["abc123"] // → 222
```

**Service Calls**:
```go
// Start the check in "in_progress" state
checkService.StartLicenseCheck(ctx, owner, repo, 222)

// Process original artifacts with current policies
securityService.ProcessWorkflowSecurityArtifacts(ctx, owner, repo, "abc123", 556677)

// Complete with new results
checkService.CompleteLicenseCheck(ctx, owner, repo, 222, "failure", result)
```

This approach provides immediate feedback on policy compliance without requiring expensive CI pipeline re-execution.
