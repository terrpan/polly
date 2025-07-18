# Polly - System Architecture

## Overview
Polly is a GitHub App that validates pull requests against Open Policy Agent (OPA) policies. It receives GitHub webhooks, evaluates configurable policies, and reports results via GitHub check runs.

## System Architecture

### High-Level Flow
```
GitHub PR/CheckRun Event → Webhook Handler → Policy Service → OPA Evaluation → Check Run Update → GitHub
```

### Component Architecture

#### 1. Entry Point (`cmd/server/`)
- **Purpose**: Application bootstrap and dependency injection
- **Responsibilities**:
  - Load configuration from environment variables
  - Initialize GitHub and OPA clients
  - Wire up services with dependency injection
  - Start HTTP server on configured port

#### 2. Webhook Handler (`internal/handlers/webhook.go`)
- **Purpose**: Process GitHub webhook events
- **Responsibilities**:
  - Parse pull request and check run events
  - Create and manage GitHub check runs
  - Coordinate policy validation workflow
  - Handle event-specific logic (new PR vs re-run)
- **Key Features**:
  - Generic `getEventInfo()` function for type-safe event handling
  - Separate handlers for PR events and check run re-requests
  - Helper functions for clean code organization

#### 3. Policy Service (`internal/services/policy.go`)
- **Purpose**: OPA policy evaluation with type safety
- **Responsibilities**:
  - Execute policy evaluations against OPA server
  - Provide type-safe policy evaluation using generics
  - Handle OPA request/response formatting
  - Support flexible policy bundle integration
- **Key Features**:
  - Generic `evaluatePolicy[T, R]()` helper function
  - Automatic payload wrapping in `{"input": {...}}` format
  - Extensible for multiple policy types without code changes

#### 4. Check Service (`internal/services/checks.go`)
- **Purpose**: GitHub check run lifecycle management
- **Responsibilities**:
  - Create security check runs for commits (vulnerability and license checks)
  - Update check run status (queued → in_progress → completed)
  - Set check run conclusions (success/failure/neutral)
  - Format check run results with titles, summaries, and details
- **Key Features**:
  - Dual-track security validation (vulnerability + license)
  - Generic check run management with type safety
  - Support for concurrent check run processing

#### 5. Security Service (`internal/services/security.go`)
- **Purpose**: Security artifact processing and normalization
- **Responsibilities**:
  - Download and analyze GitHub workflow artifacts
  - Parse Trivy vulnerability reports and SPDX SBOM files
  - Convert security data into normalized payloads
  - Detect and classify security content types
- **Key Features**:
  - Multi-format artifact support (Trivy JSON, SPDX)
  - Concurrent artifact processing
  - Ecosystem detection for vulnerability context

#### 6. State Service (`internal/services/state.go`)
- **Purpose**: PR context and check run state management
- **Responsibilities**:
  - Store and retrieve PR numbers by commit SHA
  - Manage vulnerability and license check run IDs
  - Handle workflow run ID tracking for re-runs
  - Provide thread-safe access to state data
- **Key Features**:
  - Generic state management with type safety
  - Storage abstraction supporting memory and Valkey backends
  - Automatic key formatting and validation
  - Concurrent access support

#### 7. Storage Layer (`internal/storage/`)
- **Purpose**: Configurable storage abstraction for state persistence
- **Components**:
  - **Interface** (`interface.go`): Common storage contract with context support
  - **Memory Store** (`memory.go`): In-memory implementation for development
  - **Valkey Store** (`valkey.go`): Distributed storage for production
  - **Factory** (`factory.go`): Configuration-driven store creation
- **Key Features**:
  - Pluggable backends via interface abstraction
  - Automatic expiration support
  - JSON serialization for complex data types
  - Thread-safe operations with context cancellation

#### 8. External Clients (`internal/clients/`)
- **GitHub Client** (`github.go`): GitHub API integration with app authentication
- **OPA Client** (`opa.go`): OPA server communication with generic policy evaluation

#### 9. Configuration (`internal/config/config.go`)
- **Purpose**: Environment-based configuration with validation
- **Features**:
  - Automatic environment variable binding using reflection
  - Support for nested configuration structures
  - GitHub App and OPA server configuration
  - Build-time version information injection

## Security Check Run System

Polly implements a **dual-track security validation system** where vulnerability and license checks operate independently but in parallel. For detailed information about the check run flow, see [CHECK-RUN-FLOW.md](./CHECK-RUN-FLOW.md).

### Quick Overview
- **Two Check Types**: Vulnerability checks (Trivy reports) and License checks (SPDX SBOM)
- **Event-Driven**: Triggered by GitHub PR and workflow events
- **Concurrent Processing**: Parallel evaluation and completion of security checks
- **Policy-Based**: Uses OPA for configurable security policy enforcement

## Data Flow Patterns

### 1. Security Check Run Processing
```
GitHub PR opened/reopened
    ↓
handlers.WebhookHandler.handlePullRequestEvent()
    ↓
services.StateService.StorePRNumber() - Store SHA → PR number mapping
    ↓
Create Vulnerability + License Check Runs (Concurrent)
    ↓
services.StateService.StoreVulnCheckRunID() + StoreLicenseCheckRunID()
    ↓
GitHub Workflow completed
    ↓
handlers.WebhookHandler.handleWorkflowCompleted()
    ↓
services.StateService.GetPRNumber() - Retrieve PR context by SHA
    ↓
services.SecurityService.ProcessWorkflowSecurityArtifacts()
    ↓
services.PolicyService.CheckVulnerabilityPolicy() + CheckSBOMPolicy() (Concurrent)
    ↓
clients.OPAClient.EvaluatePolicy()
    ↓
services.CheckService.CompletePolicyCheck()
    ↓
clients.GitHubClient.UpdateCheckRun()
```

### 2. Check Run Re-request Processing
```
GitHub check run re-requested
    ↓
handlers.WebhookHandler.handleCheckRunEvent()
    ↓
services.StateService.GetPRNumber() - Retrieve PR context
    ↓
services.StateService.GetWorkflowRunID() - Find associated workflow
    ↓
services.CheckService.StartPolicyCheck()
    ↓
Re-process workflow artifacts and complete check run
```

### 3. Generic Event Information Extraction
```go
// Type-safe event handling with generics
func getEventInfo[T github.PullRequestPayload | github.CheckRunPayload](event T) (owner, repo, sha string, id int64)
```

## Key Design Patterns

### 1. Generic Policy Evaluation
```go
// Type-safe policy evaluation with compile-time guarantees
func evaluatePolicy[T any, R any](ctx context.Context, service *PolicyService, policyPath string, input T) (R, error)
```
- **Benefits**: Type safety, compile-time checking, flexible policy support
- **Usage**: `result, err := evaluatePolicy[HelloInput, bool](ctx, service, "/v1/data/playground/hello", input)`

### 2. Dependency Injection Pattern
- Services receive dependencies through constructors
- Clear dependency graph: Handlers → Services → Clients
- Easy testing with interface mocking
- Configuration injected at startup

### 3. Event-Driven Processing
- Webhook events trigger policy evaluations
- Asynchronous check run updates
- Support for re-running failed checks
- Stateless processing for horizontal scaling

## Key Design Decisions

### 1. Go Generics for Type Safety
- **Benefit**: Compile-time type checking for policy evaluation
- **Trade-off**: Requires Go 1.18+ and more complex syntax
- **Rationale**: Eliminates runtime type assertions and improves API safety

### 2. Environment-Based Configuration
- **Benefit**: 12-factor app compliance, container-friendly
- **Trade-off**: Runtime configuration only
- **Rationale**: Cloud-native deployment and GitOps workflows

### 3. Generic Event Handling
- **Benefit**: Single function handles multiple webhook payload types
- **Trade-off**: Requires type switches and `any()` conversion
- **Rationale**: DRY principle and consistent event processing

### 4. Policy Service Abstraction
- **Benefit**: Supports any OPA policy bundle without code changes
- **Trade-off**: Less type safety for unknown policies
- **Rationale**: Extensibility for user-defined policies

### 5. Structured Logging with Context
- **Benefit**: Rich debugging information and request tracing
- **Trade-off**: More verbose code
- **Rationale**: Production observability requirements

## Policy Integration

### OPA Communication Pattern
```
Input: {"input": {"message": "hello"}}
Policy Path: /v1/data/playground/hello
Output: {"result": true}
```

### Policy Bundle Structure
```
playground/
├── hello          # Simple message validation
├── allow          # Authorization rules
├── greeting       # Dynamic response generation
└── user_permissions # Role-based access control
```

### Adding New Policies
1. Deploy OPA bundle to server
2. Call `policyService.EvaluatePolicy(ctx, "/v1/data/bundle/rule", input)`
3. Handle typed response based on policy output

No code changes required for new policy bundles.
## Future Considerations

### Scalability
- Horizontal scaling with stateless design
- Event queue for high-volume repositories
- Policy result caching for identical evaluations
- Webhook processing rate limiting

### Policy Management
- Policy bundle versioning and rollback
- A/B testing for policy changes
- Policy dry-run mode for testing
- Policy performance monitoring

### Security Enhancements
- Webhook signature validation
- Rate limiting per repository/organization
- Audit logging for compliance
- Secret rotation automation

### Observability
- Prometheus metrics for policy evaluation
- Distributed tracing across components
- Dashboard for policy success rates
- Alerting on policy evaluation failures

### Enhanced Features
- Support for additional GitHub events (pushes, releases)
- Multi-step policy workflows
- Custom policy result formatting
- Integration with other policy engines

## Vulnerability Check System

The vulnerability check system processes security artifacts from GitHub Actions workflows and evaluates them against OPA policies. This system runs parallel to policy checks and provides automated security review for pull requests.

### Vulnerability Check Flow

```
GitHub Workflow Event → Security Artifact Discovery → Payload Normalization → OPA Policy Evaluation → Check Run Update & PR Comments
```

### Key Components

#### 1. Security Service (`internal/services/security.go`)
- **Purpose**: Discover, download, and normalize security artifacts from GitHub workflows
- **Responsibilities**:
  - Download artifacts from completed GitHub Actions workflows
  - Detect security report formats (Trivy JSON, SARIF, SPDX SBOM)
  - Normalize different formats into unified `VulnerabilityPayload` structure
  - Extract vulnerability metadata, CVSS scores, and package information

#### 2. Vulnerability Check Orchestration (`internal/handlers/webhook.go`)
- **Purpose**: Coordinate the vulnerability scanning workflow
- **Responsibilities**:
  - Create pending vulnerability check runs when workflows start
  - Process completed workflows to extract security artifacts
  - Coordinate OPA policy evaluation for vulnerability data
  - Post PR comments with policy violation details
  - Complete check runs with appropriate success/failure status

#### 3. Vulnerability Policy Evaluation (`internal/services/policy.go`)
- **Purpose**: Evaluate complete vulnerability payloads against OPA policies
- **Responsibilities**:
  - Send full `VulnerabilityPayload` to OPA vulnerability policies
  - Process policy results to determine compliance status
  - Extract non-compliant vulnerabilities for user feedback

### Workflow Lifecycle

#### Phase 1: Workflow Start Detection
```go
// When GitHub workflow starts (action: "requested" or "in_progress")
handleWorkflowStarted() {
    1. Check if SHA has associated PR context
    2. Create pending vulnerability check run
    3. Store check run ID for later completion
}
```

#### Phase 2: Workflow Completion Processing
```go
// When GitHub workflow completes (action: "completed")
handleWorkflowCompleted() {
    1. Check workflow conclusion (only process "success")
    2. Download and inspect workflow artifacts
    3. Discover security reports (Trivy, SARIF, SBOM)
    4. Normalize artifacts into VulnerabilityPayload structures
    5. Evaluate payloads against OPA vulnerability policies
    6. Post PR comments for policy violations
    7. Complete vulnerability check run with final status
}
```

### Vulnerability Payload Structure

The system normalizes all security artifacts into a unified `VulnerabilityPayload`:

```go
type VulnerabilityPayload struct {
    Type            string                   // "vulnerability_json", "vulnerability_sarif", etc.
    Metadata        PayloadMetadata          // Scan context and tool information
    Vulnerabilities []Vulnerability          // Normalized vulnerability data
    Summary         VulnerabilitySummary     // Aggregated statistics
}

type PayloadMetadata struct {
    SourceFormat  string  // "trivy", "sarif", "spdx"
    ToolName      string  // "trivy", "snyk", "github-security-advisories"
    ToolVersion   string  // Tool version for compatibility
    ScanTime      string  // ISO timestamp of scan
    Repository    string  // "owner/repo"
    CommitSHA     string  // Git commit being scanned
    PRNumber      int     // Associated PR number
    ScanTarget    string  // File being scanned (package.json, Dockerfile)
    SchemaVersion string  // Payload schema version
}
```

### OPA Policy Integration

#### Full Context Policy Evaluation
The system passes complete vulnerability payloads to OPA policies, providing rich context:

```json
{
  "input": {
    "type": "vulnerability_json",
    "metadata": {
      "source_format": "trivy",
      "tool_name": "trivy",
      "tool_version": "0.50.0",
      "scan_time": "2024-01-15T10:30:00Z",
      "repository": "owner/repo",
      "commit_sha": "abc123def456",
      "pr_number": 42,
      "scan_target": "package.json",
      "schema_version": "1.0"
    },
    "vulnerabilities": [
      {
        "id": "CVE-2021-3749",
        "severity": "CRITICAL",
        "score": 9.8,
        "package": {
          "name": "axios",
          "version": "0.21.1",
          "ecosystem": "npm"
        },
        "location": {
          "file": "package.json",
          "line": 15
        },
        "description": "Axios is vulnerable to Server-Side Request Forgery",
        "fixed_version": "0.21.2",
        "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3749"]
      }
    ],
    "summary": {
      "total_vulnerabilities": 49,
      "critical": 2,
      "high": 22,
      "medium": 20,
      "low": 5,
      "info": 0
    }
  }
}
```

#### Policy Response Structure
OPA policies return structured results indicating compliance:

```json
{
  "result": {
    "compliant": false,
    "compliant_count": 25,
    "non_compliant_count": 24,
    "non_compliant_vulnerabilities": [
      {
        "id": "CVE-2021-3749",
        "package": "axios",
        "version": "0.21.1",
        "severity": "CRITICAL",
        "score": 9.8
      }
    ],
    "total_vulnerabilities": 49
  }
}
```

### Advanced Policy Capabilities

#### Context-Aware Decision Making
OPA policies can make sophisticated decisions based on:

- **Scan Target Context**: Different rules for `package.json` vs `Dockerfile` vs `requirements.txt`
- **Repository Context**: Per-repo or org-specific policy overrides
- **Tool Compatibility**: Version-specific behavior for different scanning tools
- **PR Context**: Different approval workflows for different types of changes
- **Temporal Context**: Time-based policies (emergency patches, maintenance windows)

#### Example Policy Logic
```rego
# Block critical vulnerabilities in production dependencies
allow = false {
    input.metadata.scan_target == "package.json"
    input.vulnerabilities[_].severity == "CRITICAL"
    input.vulnerabilities[_].package.ecosystem == "npm"
}

# Allow specific CVEs that have been manually reviewed
allow = true {
    input.vulnerabilities[_].id in data.approved_cves
}

# Different rules for different repositories
allow = true {
    input.metadata.repository == "owner/internal-tool"
    input.summary.critical == 0
    input.summary.high <= 5
}
```

### Security Artifact Support

#### Supported Formats
1. **Trivy JSON**: Complete vulnerability reports with CVSS scores and fix information
2. **SARIF**: Static analysis results interchange format for broader tool compatibility
3. **SPDX SBOM**: Software bill of materials for license and dependency analysis

#### Artifact Discovery
```go
// Automatic detection of security content in workflow artifacts
detectSecurityContent(content []byte, filename string) ArtifactType {
    // 1. Try SPDX JSON detection (document structure)
    // 2. Try Trivy JSON detection (vulnerability schema)
    // 3. Try SARIF detection (static analysis schema)
    // 4. Return unknown if no match
}
```

### Error Handling and Fallbacks

#### Graceful Degradation
- If OPA policy evaluation fails, falls back to simple severity-based rules
- If no artifacts found, completes check as "neutral" with informative message
- If workflow fails, marks vulnerability check as "skipped"

#### User Feedback
- **Expandable PR Comments**: Summary with collapsible details to avoid overwhelming conversations
- **Rich Check Run Details**: Complete vulnerability information in GitHub check runs
- **Policy Violation Context**: Clear explanations of why specific vulnerabilities were blocked

### Performance Considerations

#### Efficient Processing
- Streams large artifact downloads to avoid memory issues
- Concurrent artifact processing for multiple security reports
- Caches vulnerability data to avoid redundant OPA evaluations

#### Scalability
- In-memory PR context storage with planned ValKey migration
- Stateless processing for horizontal scaling
- Background artifact processing to avoid blocking webhook responses

### Future Enhancements

#### Planned Features
- **Multiple Security Tools**: Support for Snyk, GitHub Security Advisories, etc.
- **Historical Tracking**: Vulnerability trend analysis across commits
- **Auto-Fix Suggestions**: Integration with dependency update tools
- **Risk Scoring**: Composite scores based on multiple factors
- **Compliance Reporting**: Generate reports for security audits

#### Extensibility
- Plugin architecture for new security tool integrations
- Custom payload transformation rules
- Webhook integrations for external security platforms
- API endpoints for external vulnerability data sources
