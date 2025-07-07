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
  - Create policy check runs for commits
  - Update check run status (queued → in_progress → completed)
  - Set check run conclusions (success/failure/error)
  - Format check run results with titles, summaries, and details

#### 5. External Clients (`internal/clients/`)
- **GitHub Client** (`github.go`): GitHub API integration with app authentication
- **OPA Client** (`opa.go`): OPA server communication with generic policy evaluation

#### 6. Configuration (`internal/config/config.go`)
- **Purpose**: Environment-based configuration with validation
- **Features**:
  - Automatic environment variable binding using reflection
  - Support for nested configuration structures
  - GitHub App and OPA server configuration
  - Build-time version information injection

## Data Flow Patterns

### 1. Pull Request Event Processing
```
GitHub PR opened/reopened
    ↓
handlers.WebhookHandler.handlePullRequestEvent()
    ↓
services.CheckService.CreatePolicyCheck()
    ↓
services.CheckService.StartPolicyCheck()
    ↓
services.PolicyService.CheckHelloPolicy()
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
services.CheckService.StartPolicyCheck()
    ↓
[Same policy evaluation flow as above]
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
