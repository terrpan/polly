# Feature Development Guide

Practical, end-to-end checklist for adding a new feature to Polly while staying aligned with existing architectural patterns (service registry DI, strategy processors, modular handlers, clean services, and storage abstraction). Use this guide as a living blueprint. Keep each step small; prefer composition over reinvention.

---
## 0. Decision Checklist (Fast Triage)

Before writing code answer:
| Question | YES → | NO → |
|----------|-------|------|
| Does existing service already cover 80%? | Extend it safely | Create new service |
| Is this just a variation of an existing policy? | Add new PolicyEvaluator | Full new processing pipeline |
| Does it require persisted state across webhooks? | Add StateService methods | Keep state ephemeral |
| Does it depend on new GitHub API endpoints? | Add GitHub client methods | Reuse existing methods |
| Large/expensive recomputation? | Consider caching layer | Skip cache |
| Architectural risk or irreversible direction? | Write ADR | Skip ADR |

If 3+ YES answers in left column → draft an ADR first (see `docs/ADR-*.md` examples).

---
## 1. Minimal Example Scenario (Reference)

Example feature: Add a new “Secret Scan Policy” that evaluates a custom artifact (e.g., `secret-scan.json`) and produces a dedicated check run with pass/fail + comments.

---
## 2. Repository Touch Points Overview

1. `internal/clients/` → New GitHub API method(s) if needed
2. `internal/services/` → New service OR extend existing (policy, checks, security)
3. `internal/storage/` → Only if new persisted state required (avoid if possible)
4. `internal/app/container.go` → Service registration (constructor pattern)
5. `internal/handlers/` → Event handler changes / new processor / check creation
6. `internal/handlers/policy_processing.go` → New PolicyProcessor (if policy-like)
7. `internal/services/policy.go` → New PolicyEvaluator (if OPA-based)
8. `internal/services/policy_cache.go` → Add cached method (if evaluation benefits)
9. `docs/` → Architecture updates + feature notes + ADR (if significant)
10. Tests across layers (unit, integration, handler E2E)

---
## 3. Add / Update GitHub Client

Only add if Polly must call a new GitHub REST/GraphQL endpoint.

Steps:
1. Locate `internal/clients/github.go`
2. Follow existing method pattern: `func (c *GitHubClient) DoThing(ctx context.Context, owner, repo string, ...) (ResultType, error)`
3. Add structured logging + span: `ctx, span := c.telemetry.StartSpan(ctx, "github.do_thing")`
4. Use existing HTTP helpers (do not duplicate auth or retry logic)
5. Write a focused unit test in `github_test.go` with an httptest server
6. Add mock (if required) for handler/service tests (can create a tiny test double inline instead of large mock generator)

Rules:
- Keep method body <80 lines
- Wrap errors: `fmt.Errorf("github doThing failed: %w", err)`
- Add attributes: owner, repo, endpoint slug

---
## 4. Service Layer Design

Decide: Extend or New?

| Case | Action |
|------|--------|
| Feature augments existing policy evaluation | Add new `PolicyEvaluator` |
| Produces a new kind of check run but uses same infra | Reuse `CheckService` APIs |
| Introduces a new cohesive capability | New service + constructor + registration |

Pattern for new service:
```go
type SecretScanService struct {
    logger    *slog.Logger
    opaClient *clients.OPAClient // if using OPA
    telemetry *telemetry.Helper
}

func NewSecretScanService(logger *slog.Logger, opa *clients.OPAClient, telemetry *telemetry.Helper) *SecretScanService {
    return &SecretScanService{logger: logger, opaClient: opa, telemetry: telemetry}
}
```

Add to `createServiceRegistrations()` in `container.go`—return a constructor closure similar to existing entries.

OPA Policy? → Implement `SecretScanEvaluator` (see `PolicyEvaluator` pattern) and append inside evaluator registration after base service creation.

Caching? → Add `CheckSecretScanPolicyWithCache()` to `PolicyCacheService` (mirror existing naming) only if performance justified.

---
## 5. Storage / State Changes (Only If Necessary)

Preferred order:
1. Reuse existing state keys (PR number, check run IDs) if semantics align
2. If new unique ID must persist across events → Add targeted methods to `StateService` (e.g., `StoreSecretScanCheckRunID`)
3. Avoid expanding `storage.Store` interface unless *every* backend must implement new operation
4. If just caching computed results → Use `PolicyCacheService` rather than raw store

Steps for new state key:
1. Add constants & methods in `state.go` (store + get, wrap errors)
2. Write unit tests in `state_test.go`
3. (Optional) Add retrieval aggregation to `GetAllState` if broadly useful
4. Update `docs/STORAGE.md` with new key pattern

Key naming pattern: `{owner}:{repo}:secret_scan_check_run_id:{sha}` (match existing style)

---
## 6. Dependency Injection (Container)

1. Open `internal/app/container.go`
2. In `createServiceRegistrations()` append a new registration:
```go
{
    Name: "secretScanService",
    Build: func(c *Container) (any, error) {
        return services.NewSecretScanService(c.logger, c.clients.opaClient, c.telemetryHelper), nil
    },
    Assign: func(c *Container, svc any) { c.services.secretScanService = svc.(*services.SecretScanService) },
},
```
3. Add private field in services struct & optional accessor if needed elsewhere
4. Update `container_test.go` to assert non-nil construction

Do NOT inject services directly into handlers—handlers receive constructed dependencies via `BaseWebhookHandler`.

---
## 7. Handler / Event Wiring

Scenario A: Existing event (e.g., workflow completion) now triggers new processing
1. Update relevant handler (e.g., `webhook_workflow.go`)—keep method small, delegate to helper
2. Use existing artifact processing or add a new artifact type + detector

Scenario B: New GitHub event type
1. Create `webhook_secretscan.go`
2. Define struct embedding `*BaseWebhookHandler`
3. Add constructor `NewSecretScanHandler(base *BaseWebhookHandler) *SecretScanHandler`
4. Register route in `webhook_router.go` switch
5. Add tests in `webhook_secretscan_test.go`

Tracing pattern inside handler:
```go
ctx, span := h.telemetry.StartSpan(ctx, "webhook.secret_scan")
defer span.End()
span.SetAttributes(attribute.String("github.owner", owner), attribute.String("github.repo", repo))
```

Delegation: convert raw inputs → service call → check run creation via `CheckService` → comments via `CommentService`.

---
## 8. Policy Processing Strategy (If Policy-Like)

If your feature evaluates batches of payloads similarly to vulnerability/license flows:
1. Create `SecretScanPolicyProcessor` implementing `PolicyProcessor`
2. Follow existing processors: cast payload slice, loop, call cache service, aggregate into `PolicyProcessingResult`
3. Add test in `policy_processing_test.go` or a new file
4. Reuse `processPoliciesWithStrategy` generic executor

If result format diverges significantly → consider dedicated struct; still return a populated `PolicyProcessingResult` (extend with new slice field if needed).

---
## 9. Check Run Creation

Reuse `CheckService` methods: create initial in-progress check then conclude with result. If output formatting mimics existing vulnerability/license patterns, consider extracting a new `CheckResultBuilder` (see proposals in `ARCHITECTURE_PATTERNS.md`).

Checklist:
- Consistent naming: `Secret Scan Check`
- Include summary count metrics in `CheckRunResult.Summary`
- For failures include actionable lines, not raw dumps

---
## 10. Telemetry & Logging

Span naming conventions:
| Layer | Pattern |
|-------|---------|
| Handler | `webhook.<event>` |
| Service | `service.<domain>.<action>` |
| Policy Eval | `policy.check_<type>` |
| Cache | `policy_cache.check_<type>` |
| GitHub | `github.<operation>` |

Attributes to include early:
- `github.owner`, `github.repo`, `git.sha`
- For policies: `policy.type`, `input.count`
- Cache: `cache.hit`, `cache.key`

Log levels:
- Debug → granular processing details
- Info → successful evaluation summaries
- Warn → non-fatal cache/store issues
- Error → failures that change outcome

---
## 11. Testing Strategy

| Layer | Test Type | Notes |
|-------|-----------|-------|
| Client | Unit | httptest server, simulate GitHub responses |
| Service | Unit | Mock downstream (OPA, store) |
| Policy Evaluator | Unit | Payload edge cases, error path |
| Cache Path | Unit | Hit vs miss, disabled config |
| State | Unit | New getters/setters (memory + valkey integration) |
| Handler | Unit | Use mock services; assert delegated calls + result mapping |
| Integration | Optional | Only if new external dependency or complex store behavior |

Edge cases to cover:
1. Empty artifact list
2. Malformed payload → graceful skip
3. Large payload (performance) – maybe size threshold logic
4. Cache disabled vs enabled
5. Re-run scenario (state recall + idempotency)

---
## 12. Documentation Updates

Update:
- `ARCHITECTURE.md` (new component mention if architectural)
- `ARCHITECTURE_PATTERNS.md` (if you introduced a new pattern or realized an opportunity)
- `POLICY_DEVELOPMENT_GUIDE.md` (if new policy type)
- `WEBHOOK_DEVELOPMENT_GUIDE.md` (if new handler)
- `STORAGE.md` (if new state key)
- New ADR if change is structural or strategic
- Add short bullet to README only if user-facing capability

Consistency: cross-link from any new section back to related guide (policy ↔ patterns, webhook ↔ check run system).

---
## 13. Quality Gates Before Commit

1. `go build ./...` passes
2. `go test -short ./...` green
3. Added tests for new logic (no uncovered critical paths)
4. `golangci-lint run` clean (funlen, dupl, errcheck, etc.)
5. Functions <80 lines (split helpers if needed)
6. No unused exported symbols
7. No direct storage usage from handlers (only via services)

Optional pre-flight script:
```bash
go build ./... && \
golangci-lint run && \
go test -short ./...
```

---
## 14. Pull Request Checklist (Copy/Paste)

```
[ ] Added / updated GitHub client methods (if required)
[ ] New / extended service with constructor pattern
[ ] Service registered in container (and tests updated)
[ ] Handler logic delegates to helpers (no large inline blocks)
[ ] Optional: New PolicyEvaluator & Processor implemented
[ ] StateService updated (only if persistence needed)
[ ] Tests: client, service, processor, handler
[ ] Cache integration (if feature benefits) documented
[ ] Telemetry spans + attributes added
[ ] Documentation updated (ARCHITECTURE / STORAGE / POLICY / WEBHOOK)
[ ] ADR created (if architectural)
[ ] Lint & tests pass locally
```

---
## 15. When to Refactor Mid-Feature

Refactor *before* adding feature logic if you notice:
- You would copy >20 lines from an existing handler/service
- A function would exceed 80 lines after changes
- You need a third near-identical variant of a pattern → convert to strategy/builder first

Keep refactors surgical and documented in commit messages (`refactor: extract shared X for new feature Y`).

---
## 16. Anti-Patterns to Avoid

| Anti-Pattern | Why Bad | Correct Approach |
|--------------|---------|------------------|
| Handler writing directly to storage | Breaks layering | Add method to StateService |
| Duplicating vulnerability/license logic for new policy | Increases maintenance | Implement PolicyEvaluator + Processor |
| Large switch inside handler for feature logic | Hard to extend | Move to processor or helper |
| Putting caching logic inside PolicyService | Violates separation | Keep in PolicyCacheService |
| Creating new global singletons | Hidden dependencies | Use container registry |

---
## 17. Escalation / ADR Triggers

Create an ADR when:
- Introducing a new external system (queue, database, API gateway)
- Changing policy evaluation architecture
- Modifying container/service registration pattern
- Introducing a new caching layer beyond PolicyCacheService

ADR Template Essentials:
1. Context
2. Decision
3. Alternatives Considered
4. Consequences (positive & negative)

---
## 18. Example Micro Walkthrough (Secret Scan)

1. Add `SecretScanEvaluator` → register in `NewStandardEvaluators`
2. Add `CheckSecretScanPolicyWithCache` method
3. Implement `SecretScanPolicyProcessor` (strategy)
4. Add detector + artifact type if file format new
5. Extend workflow handler to collect artifacts & call processor
6. Create new check run via `CheckService`
7. Add state methods if re-run requires same check run IDs
8. Tests across: evaluator, cache, processor, handler
9. Docs: update POLICY + WEBHOOK + ARCHITECTURE_PATTERNS (if new pattern)
10. PR with checklist

---
## 19. Fast Reference Summary

| Step | Action | File(s) |
|------|--------|---------|
| Client | Add API method | `internal/clients/github.go` |
| Evaluator | New policy type | `internal/services/policy.go` |
| Processor | Strategy for payloads | `internal/handlers/policy_processing.go` |
| Service | Business logic | `internal/services/*.go` |
| Cache | Add wrapper method | `policy_cache.go` |
| State | Add getters/setters | `state.go` |
| Handler | Wire event logic | `webhook_*.go` |
| DI | Register service | `container.go` |
| Tests | Unit + integration | Matching *_test.go |
| Docs | Cross-links + ADR | `docs/*.md` |

---
## 20. Final Notes

Prefer *small*, composable additions. If a feature PR exceeds ~400 lines excluding tests/docs, consider splitting:
1. Enabling refactor
2. Core feature logic
3. Follow-up enhancers (cache, docs elaboration)

Happy building.
