# Policy Implementation Guide

## Overview

This guide explains how to implement new policy types in Polly using the current service layer architecture. The system uses a **Strategy Pattern** with **Factory Registry** for extensible policy evaluation while maintaining type safety and consistent telemetry.

## Architecture Overview

### Core Components

1. **PolicyEvaluator Interface**: Defines the contract for policy evaluation strategies
2. **PolicyService**: Central service with evaluator registry for policy dispatch
3. **Policy Processors**: Strategy implementations for webhook-level policy processing
4. **Helper Functions**: Utility functions for data transformation and payload building
5. **Telemetry Integration**: Consistent observability across all policy types

### Current Policy Types

- **Vulnerability Policies**: Evaluate security vulnerabilities using Trivy JSON reports
- **SBOM/License Policies**: Evaluate software bill of materials and license compliance using SPDX documents

## Implementation Steps

### Step 1: Define Payload Types

Create type-safe structures for your policy input and result in `internal/services/security_types.go`:

```go
// Input payload for your policy
type CustomPolicyPayload struct {
    Metadata PayloadMetadata `json:"metadata"`
    // Your specific fields
    CustomData []CustomItem `json:"custom_data"`
    Summary    CustomSummary `json:"summary"`
}

type CustomItem struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    // Policy-specific fields
    RiskLevel   string `json:"risk_level"`
    Compliance  bool   `json:"compliance"`
}

type CustomSummary struct {
    TotalItems      int `json:"total_items"`
    CompliantItems  int `json:"compliant_items"`
    RiskDistribution map[string]int `json:"risk_distribution"`
}

// Result type for policy evaluation
type CustomPolicyResult struct {
    Compliant            bool                `json:"compliant"`
    TotalItems          int                 `json:"total_items"`
    CompliantItems      int                 `json:"compliant_items"`
    NonCompliantItems   []CustomPolicyItem  `json:"non_compliant_items"`
    Details             []string            `json:"details,omitempty"`
}

type CustomPolicyItem struct {
    ID          string `json:"id"`
    Name        string `json:"name"`
    RiskLevel   string `json:"risk_level"`
    Reason      string `json:"reason"`
}
```

### Step 2: Implement PolicyEvaluator

Create a new evaluator in `internal/services/policy.go`:

```go
// CustomPolicyEvaluator handles custom policy evaluation
type CustomPolicyEvaluator struct {
    service *PolicyService
}

func (c *CustomPolicyEvaluator) PolicyType() string {
    return "custom"  // Used for registry key and routing
}

func (c *CustomPolicyEvaluator) PolicyPath() string {
    return "/v1/data/compliance/custom_policy"  // OPA policy path
}

func (c *CustomPolicyEvaluator) Evaluate(ctx context.Context, payload any) (any, error) {
    customPayload, ok := payload.(*CustomPolicyPayload)
    if !ok {
        return nil, fmt.Errorf(
            "%w: expected *CustomPolicyPayload, got %T",
            ErrPolicyEvaluation,
            payload,
        )
    }

    ctx, span := c.service.telemetry.StartSpan(ctx, "policy.check_custom")
    defer span.End()

    c.service.telemetry.SetPolicyAttributes(span, "custom")
    span.SetAttributes(
        attribute.Int("input.item_count", len(customPayload.CustomData)),
        attribute.String("input.scan_target", customPayload.Metadata.ScanTarget),
        attribute.String("input.tool_name", customPayload.Metadata.ToolName),
    )

    c.service.logger.DebugContext(ctx, "Checking custom policy",
        "item_count", len(customPayload.CustomData),
        "scan_target", customPayload.Metadata.ScanTarget,
        "tool_name", customPayload.Metadata.ToolName)

    // Use the generic policy evaluation helper
    result, err := evaluatePolicy[*CustomPolicyPayload, CustomPolicyResult](
        ctx,
        c.service,
        c.PolicyPath(),
        customPayload,
    )

    if err != nil {
        c.service.telemetry.SetErrorAttribute(span, err)
        return result, err
    }

    span.SetAttributes(
        attribute.Bool("result.compliant", result.Compliant),
        attribute.Int("result.total_items", result.TotalItems),
        attribute.Int("result.compliant_items", result.CompliantItems),
    )

    c.service.logger.InfoContext(ctx, "Custom policy evaluation completed",
        "compliant", result.Compliant,
        "total_items", result.TotalItems,
        "compliant_items", result.CompliantItems)

    return result, nil
}
```

### Step 3: Add to Standard Evaluators

Update the `NewStandardEvaluators` function in `internal/services/policy.go`:

```go
// NewStandardEvaluators creates the default set of policy evaluators
func NewStandardEvaluators(service *PolicyService) []PolicyEvaluator {
    return []PolicyEvaluator{
        &VulnerabilityEvaluator{service: service},
        &SBOMEvaluator{service: service},
        &CustomPolicyEvaluator{service: service},  // Add your evaluator
    }
}
```

### Step 4: Add PolicyService Methods

Add convenience methods to `PolicyService` in `internal/services/policy.go`:

```go
// CheckCustomPolicy evaluates custom policies
func (p *PolicyService) CheckCustomPolicy(ctx context.Context, payload *CustomPolicyPayload) (CustomPolicyResult, error) {
    return p.Evaluate(ctx, "custom", payload)
}
```

### Step 5: Create Helper Functions

Add helper functions for payload building in `internal/services/helpers.go`:

```go
// buildCustomPayloadFromData creates a normalized custom payload from raw data
func buildCustomPayloadFromData(
    artifact *SecurityArtifact,
    owner, repo, sha string,
    prNumber int,
) (*CustomPolicyPayload, error) {
    // Parse your specific data format
    var rawData CustomRawData
    if err := json.Unmarshal(artifact.Content, &rawData); err != nil {
        return nil, err
    }

    // Build metadata
    metadata := buildPayloadMetadata(
        "custom_format",
        "custom_tool",
        fmt.Sprintf("%s/%s", owner, repo),
        sha,
        artifact.FileName,
        rawData.SchemaVersion,
        prNumber,
        rawData.ScanTime,
    )

    // Transform raw data to policy format
    customItems := make([]CustomItem, 0, len(rawData.Items))
    compliantCount := 0
    riskDistribution := make(map[string]int)

    for _, item := range rawData.Items {
        customItem := CustomItem{
            ID:         item.ID,
            Name:       item.Name,
            RiskLevel:  item.Risk,
            Compliance: item.IsCompliant,
        }
        customItems = append(customItems, customItem)

        if item.IsCompliant {
            compliantCount++
        }
        riskDistribution[item.Risk]++
    }

    summary := CustomSummary{
        TotalItems:       len(customItems),
        CompliantItems:   compliantCount,
        RiskDistribution: riskDistribution,
    }

    return &CustomPolicyPayload{
        Metadata:   metadata,
        CustomData: customItems,
        Summary:    summary,
    }, nil
}
```

### Step 6: Add Content Detection

If your policy works with specific file formats, add detection in `internal/services/security_detectors.go`:

```go
// CustomDetector identifies custom policy files
type CustomDetector struct{}

func (d *CustomDetector) CanHandle(content []byte, filename string) bool {
    // Check file extension
    if !strings.HasSuffix(filename, ".custom") {
        return false
    }

    // Validate content structure
    return isCustomContent(content)
}

func (d *CustomDetector) GetArtifactType() ArtifactType {
    return ArtifactTypeCustom  // Add this constant to security_types.go
}

func (d *CustomDetector) GetPriority() int {
    return 30  // Lower number = higher priority
}

// Helper function to validate custom content
func isCustomContent(content []byte) bool {
    var data map[string]interface{}
    if err := json.Unmarshal(content, &data); err != nil {
        return false
    }

    // Check for required fields that identify your format
    if _, ok := data["custom_format_version"]; ok {
        return true
    }
    if _, ok := data["custom_schema"]; ok {
        return true
    }

    return false
}
```

### Step 7: Integrate with Security Service

Update `BuildPayloadsFromArtifacts` in `internal/services/security.go`:

```go
// In the switch statement, add your case:
case ArtifactTypeCustom:
    payload, err := buildCustomPayloadFromData(
        artifact,
        owner,
        repo,
        sha,
        0, // prNumber
    )
    if err != nil {
        s.logger.ErrorContext(ctx, "Failed to build custom payload",
            "artifact_name", artifact.ArtifactName,
            "file_name", artifact.FileName,
            "error", err,
        )
        continue
    }

    customPayloads = append(customPayloads, payload)
```

### Step 8: Create Policy Processor (Optional)

For webhook-level processing, implement a strategy in `internal/handlers/policy_processing.go`:

```go
// CustomPolicyProcessor handles custom policy processing in webhooks
type CustomPolicyProcessor struct{}

func (p *CustomPolicyProcessor) ProcessPayloads(
    ctx context.Context,
    logger *slog.Logger,
    policyService PolicyServiceInterface,
    payloads []*services.CustomPolicyPayload,
    owner, repo, sha string,
) PolicyProcessingResult {
    result := PolicyProcessingResult{
        AllPassed:     true,
        PolicyType:    "custom",
        NonCompliantCustomItems: []services.CustomPolicyItem{},
    }

    for _, payload := range payloads {
        logger.InfoContext(ctx, "Processing custom policy",
            "items", len(payload.CustomData),
            "scan_target", payload.Metadata.ScanTarget)

        policyResult, err := policyService.CheckCustomPolicy(ctx, payload)
        if err != nil {
            logger.ErrorContext(ctx, "Custom policy evaluation failed", "error", err)
            // Handle fallback logic here
            continue
        }

        if !policyResult.Compliant {
            result.AllPassed = false
            result.NonCompliantCustomItems = append(
                result.NonCompliantCustomItems,
                policyResult.NonCompliantItems...,
            )
        }
    }

    return result
}

func (p *CustomPolicyProcessor) GetPolicyType() string {
    return "custom"
}
```

### Step 9: Add Tests

Create comprehensive tests in `internal/services/policy_test.go`:

```go
func TestCustomPolicyEvaluator_Evaluate(t *testing.T) {
    service := createTestPolicyService(t)
    evaluator := &CustomPolicyEvaluator{service: service}

    tests := []struct {
        name        string
        payload     any
        expectError bool
    }{
        {
            name: "valid custom payload",
            payload: &CustomPolicyPayload{
                CustomData: []CustomItem{
                    {ID: "item1", Name: "Test Item", RiskLevel: "LOW", Compliance: true},
                },
                Metadata: PayloadMetadata{ScanTarget: ".", ToolName: "custom_tool"},
            },
            expectError: false,
        },
        {
            name:        "invalid payload type",
            payload:     "invalid",
            expectError: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            ctx := context.Background()
            result, err := evaluator.Evaluate(ctx, tt.payload)

            if tt.expectError {
                assert.Error(t, err)
                assert.Nil(t, result)
            } else {
                assert.NoError(t, err)
                assert.NotNil(t, result)
            }
        })
    }
}
```

## Best Practices

### 1. Type Safety
- Always use strongly typed payload and result structures
- Implement proper type assertions in evaluators
- Use generics for reusable patterns

### 2. Error Handling
- Provide meaningful error messages with context
- Use error wrapping with `fmt.Errorf("%w: ...", ErrPolicyEvaluation, ...)`
- Handle OPA communication failures gracefully

### 3. Observability
- Use consistent telemetry patterns with spans and attributes
- Log at appropriate levels (Debug for details, Info for results, Error for failures)
- Include relevant context in logs and traces

### 4. Performance
- Keep payloads efficient - avoid unnecessary data transformation
- Use streaming for large datasets when possible
- Consider caching for expensive operations

### 5. Testing
- Test all evaluator methods independently
- Mock OPA responses for unit tests
- Include integration tests with real OPA policies
- Test error conditions and edge cases

## OPA Policy Development

Your OPA policy should follow this structure:

```rego
package compliance.custom_policy

import rego.v1

# Main policy decision
default allow := false

allow if {
    compliant_items_count >= required_threshold
}

# Calculate compliance metrics
compliant_items_count := count([item |
    some item in input.custom_data
    item.compliance == true
])

required_threshold := input.summary.total_items * 0.8  # 80% compliance required

# Detailed results for the response
result := {
    "compliant": allow,
    "total_items": count(input.custom_data),
    "compliant_items": compliant_items_count,
    "non_compliant_items": non_compliant_items
}

non_compliant_items := [item_result |
    some item in input.custom_data
    item.compliance == false
    item_result := {
        "id": item.id,
        "name": item.name,
        "risk_level": item.risk_level,
        "reason": sprintf("Item '%s' failed compliance check", [item.name])
    }
]
```

## Registration and Service Initialization

The policy evaluators are automatically registered when creating a `PolicyService`. The initialization follows this pattern:

```go
// In your service initialization (internal/app/container.go)
policyService := services.NewPolicyService(
    opaClient,
    logger,
    telemetryHelper,
    []services.PolicyEvaluator{}, // Empty initially
)

// Create evaluators with service reference
evaluators := services.NewStandardEvaluators(policyService)
for _, evaluator := range evaluators {
    policyService.evaluators[evaluator.PolicyType()] = evaluator
}
```

This pattern avoids circular dependency issues during service construction while maintaining the factory registry pattern.

## Extension Points

The architecture provides several extension points:

1. **New Evaluators**: Implement `PolicyEvaluator` interface
2. **New Content Types**: Implement `ContentDetector` interface
3. **New Processors**: Implement `PolicyProcessor` interface
4. **New Helper Functions**: Add to `helpers.go` for data transformation
5. **New Check Types**: Extend webhook handlers for specialized processing

This modular approach ensures that new policy types can be added without modifying existing code, following the Open/Closed Principle.
