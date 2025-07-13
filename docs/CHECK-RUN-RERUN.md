# Check Run Rerun Implementa### How It Works

1. **Workflow Completion**: When a workflow completes successfully with artifacts:
   - The system stores the workflow run ID for the commit SHA
   - Security artifacts are processed and check runs are completed

2. **Check Run Event Reception**: When a user clicks "Re-run" on a check:
   - GitHub sends a `check_run` webhook with action `"rerequested"`

3. **Check Type Identification**: The handler examines the `check_run.name` field to determine the type:
   - Contains "Vulnerability" → Vulnerability check
   - Contains "License" → License check
   - Other → Unknown (logged and skipped)

4. **Context Restoration**:
   - Extracts PR context from the check run's `pull_requests` field
   - Stores the PR number for the SHA in the context store
   - Stores the check run ID in the appropriate check store (vulnerability or license)

5. **Artifact Lookup**:
   - Looks up the stored workflow run ID for the commit SHA
   - If found, processes the original artifacts from that workflow run
   - If not found, completes the check as "neutral" (no artifacts to analyze)

6. **Check Processing**:
   - Calls `ProcessWorkflowSecurityArtifacts()` with the stored workflow run ID
   - Re-evaluates the same security scan results with current policy
   - Posts updated comments if violations are found
   - Completes the check run with current results

The webhook handler now supports rerunning individual security checks when a user clicks "Re-run" on a failed check in the GitHub UI.

## Implementation Details

### Artifact Storage System

The webhook handler now maintains an in-memory store that maps SHA commits to workflow run IDs:

```go
artifactStore map[string]int64 // sha -> workflow_run_id
```

This enables the system to:
1. **Store Artifacts**: When a workflow completes successfully, store the workflow run ID for the commit SHA
2. **Retrieve Artifacts**: When a check is rerun, look up the original workflow run ID to access stored artifacts
3. **Process Historical Data**: Re-evaluate the same security scan results that were originally processed

### Supported Check Types

The system can identify and restart two types of security checks based on the check run name:

1. **Vulnerability Checks** - Any check run with "Vulnerability" in the name
2. **License Checks** - Any check run with "License" in the name

### How It Works

1. **Check Run Event Reception**: When a user clicks "Re-run" on a check, GitHub sends a `check_run` webhook with action `"rerequested"`

2. **Check Type Identification**: The handler examines the `check_run.name` field to determine the type:
   - Contains "Vulnerability" → Vulnerability check
   - Contains "License" → License check
   - Other → Unknown (logged and skipped)

3. **Context Restoration**:
   - Extracts PR context from the check run's `pull_requests` field
   - Stores the PR number for the SHA in the context store
   - Stores the check run ID in the appropriate check store (vulnerability or license)

4. **Check Restart**: Calls the appropriate service method:
   - `checkService.StartVulnerabilityCheck()` for vulnerability checks
   - `checkService.StartLicenseCheck()` for license checks

### Example Payload

Based on the provided payload, a "License Check" rerun would:

```json
{
  "action": "rerequested",
  "check_run": {
    "id": 45860128821,
    "name": "License Check",
    "head_sha": "d815b044b1560799e9016d5fc76dd3e4853ace11",
    "pull_requests": [
      {
        "number": 36
      }
    ]
  },
  "repository": {
    "owner": { "login": "terrpan" },
    "name": "test-repo"
  }
}
```

This would result in:
1. Identification as a license check
2. Storage of PR #36 context for SHA `d815b044b1560799e9016d5fc76dd3e4853ace11`
3. Storage of check run ID `45860128821` in the license check store
4. Lookup of stored workflow run ID for the SHA
5. Re-processing of SBOM artifacts from the original workflow run
6. Re-evaluation with current license policies
7. Updated check run completion with current results

### Workflow Flow

#### Initial Workflow Run
```
PR Created/Updated
    ↓
Workflow Triggered → Security Scans → Artifacts Generated
    ↓                                       ↓
Check Runs Created ←←←←←←←←←←←← Artifacts Processed & Stored
    ↓                                       ↓
Check Results Posted             Workflow Run ID Stored (SHA → ID)
```

#### Check Rerun Flow
```
User Clicks "Re-run"
    ↓
Check Run Webhook → Check Type Identified → Stored Workflow ID Retrieved
    ↓                                                ↓
Check Started → Original Artifacts Re-processed → Policies Re-evaluated
    ↓                                                ↓
New Comments Posted ←←←←←←←← Updated Check Results ←←←←←←←←
```

### Benefits

- **Artifact Persistence**: Original security scan results are preserved and can be re-evaluated
- **Policy Updates**: Changes to security policies can be applied to existing scan results without re-running CI
- **Granular Control**: Users can rerun individual failed checks without rerunning the entire CI pipeline
- **Efficient Resource Usage**: Re-uses existing artifacts instead of regenerating security scans
- **Better User Experience**: Faster feedback loop for developers fixing security issues
- **Consistent Results**: Same scan data is used, ensuring consistent baseline for policy evaluation

### Testing

The implementation includes comprehensive tests covering:
- Action filtering (only `"rerequested"` actions are processed)
- Check type identification logic
- Context storage and retrieval
- Artifact storage and lookup functionality
- Error handling for unknown check types
- Error handling for missing artifacts

### Edge Cases Handled

- **No Stored Artifacts**: If no workflow run ID is found for a SHA, the check completes as "neutral"
- **Missing PR Context**: Checks can be processed without PR context (no comments posted)
- **Failed Artifact Processing**: If artifact retrieval fails, the check completes as "neutral"
- **Empty Artifacts**: If no security artifacts are found in the workflow run, check completes as "neutral"

### Future Enhancements

- Support for additional check types beyond vulnerability and license
- More sophisticated check name pattern matching
- Enhanced error handling and retry logic
