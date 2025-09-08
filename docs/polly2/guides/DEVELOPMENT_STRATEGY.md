<!-- Moved from docs/DEVELOPMENT_STRATEGY.md -->
# Polly 2.0 Development Strategy

## Challenge: Managing Massive Architectural Change

Polly 2.0 represents a fundamental rewrite that could take 6+ weeks with multiple developers. We need a strategy that:
- Enables parallel development without conflicts
- Allows testing components independently  
- Provides rollback capability at each phase
- Maintains main branch stability
- Enables early feedback and iteration

## Recommended Development Strategy

### 1. Go Workspace Architecture

Use Go workspaces to develop the plugin system alongside the existing application:

```
polly/
├── go.work                    # Workspace root
├── go.work.sum
├── polly-core/               # Existing application (renamed)
│   ├── go.mod
│   ├── go.sum
│   ├── cmd/server/
│   ├── internal/
│   └── ...
├── polly-v2/                 # New plugin-based architecture
│   ├── go.mod                # Independent module
│   ├── go.sum
│   ├── cmd/server/
│   ├── internal/
│   │   ├── plugins/          # Plugin manager
│   │   ├── events/           # Event bus
│   │   └── helpers/          # Helper services
│   └── pkg/
│       └── sdk/              # Plugin SDK
├── plugins/                  # Official plugins (separate modules)
│   ├── vulnerability-plugin/
│   │   ├── go.mod
│   │   ├── main.go
│   │   └── ...
│   └── license-plugin/
│       ├── go.mod
│       ├── main.go
│       └── ...
└── tools/
    └── migration/            # Migration utilities
```

#### Go Workspace Setup

```bash
# Initialize workspace
cd /Users/danielterry/git/polly
go work init

# Create polly-core (move existing code)
mkdir polly-core
git mv cmd internal pkg polly-core/
cp go.mod polly-core/
cp go.sum polly-core/

# Update polly-core module path
cd polly-core
go mod edit -module github.com/terrpan/polly/polly-core

# Create polly-v2 (new architecture)
mkdir polly-v2
cd polly-v2
go mod init github.com/terrpan/polly/polly-v2

# Create plugin modules
mkdir -p plugins/vulnerability-plugin
cd plugins/vulnerability-plugin
go mod init github.com/terrpan/polly/plugins/vulnerability-plugin

mkdir ../license-plugin
cd ../license-plugin
go mod init github.com/terrpan/polly/plugins/license-plugin

# Add all modules to workspace
cd ../..  # Back to repo root
go work use ./polly-core ./polly-v2 ./plugins/vulnerability-plugin ./plugins/license-plugin
```

### 2. Branching Strategy

Use a **feature branch per major component** with integration branch:

```
main
├── feature/plugin-architecture-foundation
├── feature/event-bus-system
├── feature/plugin-manager
├── feature/helper-services
├── feature/vulnerability-plugin-extraction
├── feature/license-plugin-extraction
├── feature/integration-testing
└── polly-v2-integration          # Integration branch
```

#### Branch Organization

**Phase 1 Branches (Weeks 1-2):**
```bash
# Foundation infrastructure
git checkout -b feature/plugin-architecture-foundation
git checkout -b feature/event-bus-system  
git checkout -b feature/helper-services
```

**Phase 2 Branches (Weeks 3-4):**
```bash
# Plugin extraction
git checkout -b feature/vulnerability-plugin-extraction
git checkout -b feature/license-plugin-extraction
```

**Phase 3 Branches (Weeks 5-6):**
```bash
# Integration and testing
git checkout -b feature/integration-testing
git checkout -b feature/backward-compatibility
```

**Integration Branch:**
```bash
# Long-running integration branch
git checkout -b polly-v2-integration
```

### 3. Development Workflow

#### Step 1: Set Up Parallel Development Environment

```bash
# Clone and set up workspace
git clone https://github.com/terrpan/polly.git
cd polly
git checkout -b setup/go-workspace

# Set up workspace structure (as described above)
# Commit workspace setup
git add .
git commit -m "feat: set up Go workspace for Polly 2.0 development"
git push -u origin setup/go-workspace

# Create PR for workspace setup (get team buy-in)
```

#### Step 2: Create Integration Branch

```bash
# Create long-running integration branch
git checkout -b polly-v2-integration
git push -u origin polly-v2-integration

# This branch will integrate all feature branches
```

#### Step 3: Parallel Feature Development

**Developer 1: Plugin Architecture Foundation**
```bash
git checkout polly-v2-integration
git checkout -b feature/plugin-architecture-foundation

# Implement core plugin interfaces and RPC
# Files: polly-v2/internal/plugins/, polly-v2/pkg/sdk/

# Regular commits and pushes
git add .
git commit -m "feat: implement core plugin interface and RPC foundation"
git push -u origin feature/plugin-architecture-foundation

# Create PR to polly-v2-integration (not main)
```

**Developer 2: Event Bus System**
```bash
git checkout polly-v2-integration
git checkout -b feature/event-bus-system

# Implement event processing pipeline
# Files: polly-v2/internal/events/

git add .
git commit -m "feat: implement GitHub webhook to enriched event pipeline"
git push -u origin feature/event-bus-system
```

**Developer 3: Helper Services**
```bash
git checkout polly-v2-integration  
git checkout -b feature/helper-services

# Implement PollyHelpers interface
# Files: polly-v2/internal/helpers/

git add .
git commit -m "feat: implement plugin helper services for GitHub/OPA/files"
git push -u origin feature/helper-services
```

#### Step 4: Integration Testing

```bash
# Regularly merge feature branches into integration branch
git checkout polly-v2-integration

# Merge completed features
git merge feature/plugin-architecture-foundation
git merge feature/event-bus-system  
git merge feature/helper-services

# Test integration
cd polly-v2
go build ./cmd/server
go test ./...

# Push integration updates
git push origin polly-v2-integration
```

### 4. Testing Strategy

#### Independent Component Testing

Each feature branch has its own test suite:

```bash
# Test plugin foundation in isolation
cd polly-v2
go test ./internal/plugins/...

# Test event bus in isolation  
go test ./internal/events/...

# Test helper services in isolation
go test ./internal/helpers/...
```

#### Integration Testing

```bash
# Integration tests run on the integration branch
cd polly-v2
go test -tags=integration ./...

# End-to-end tests with both systems
go test -tags=e2e ./...
```

#### Backward Compatibility Testing

```bash
# Run existing test suite against polly-core
cd polly-core
go test ./...

# Ensure no regression in current functionality
```

### 5. Development Phases with Workspace

#### Phase 1: Foundation (Weeks 1-2)

**Goals:**
- ✅ Basic plugin manager working
- ✅ Event bus converting webhooks to enriched events  
- ✅ Helper services providing GitHub/OPA integration
- ✅ Simple local plugin loading

**Workspace State:**
```
polly-core/     # Unchanged, still working
polly-v2/       # New foundation components
plugins/        # Empty plugin templates
```

**Validation:**
- Can start a local plugin process
- Can convert webhook to enriched event
- Can fetch files via helper services
- All tests pass

#### Phase 2: Plugin Extraction (Weeks 3-4)

**Goals:**
- ✅ Extract VulnerabilityPolicyProcessor to plugin
- ✅ Extract LicensePolicyProcessor to plugin
- ✅ Plugins process events via event bus
- ✅ Feature parity with embedded processors

**Workspace State:**
```
polly-core/                    # Still working (fallback)
polly-v2/                      # Event bus + plugin manager
plugins/
  ├── vulnerability-plugin/    # Working plugin
  └── license-plugin/          # Working plugin
```

**Validation:**
- Vulnerability scanning works via plugin
- License scanning works via plugin
- Performance within 10% of embedded version
- All existing tests pass with plugin versions

#### Phase 3: Integration (Weeks 5-6)

**Goals:**
- ✅ End-to-end webhook processing
- ✅ Backward compatibility testing
- ✅ Migration tooling
- ✅ Documentation and deployment guides

**Workspace State:**
```
polly-core/     # Legacy version (for rollback)
polly-v2/       # Complete system
plugins/        # Production-ready plugins
tools/
  └── migration/ # Migration utilities
```

### 6. Advantages of This Approach

#### ✅ **Parallel Development**
- Multiple developers can work independently
- No merge conflicts between major components
- Each feature can be tested in isolation

#### ✅ **Risk Mitigation** 
- polly-core remains fully functional as fallback
- Each phase can be validated before proceeding
- Easy rollback at any point
- Gradual migration possible

#### ✅ **Quality Control**
- Component-level testing before integration
- Feature branches reviewed independently
- Integration branch continuously tested
- Performance comparison between versions

#### ✅ **Team Collaboration**
- Clear ownership of components
- Regular integration points
- Independent development velocity
- Early feedback on interfaces

#### ✅ **Deployment Flexibility**
- Can deploy polly-core while developing v2
- Can test v2 in parallel environments
- Gradual rollout possible (A/B testing)
- Easy feature flagging

### 7. Example Development Timeline

**Week 1:**
- **Monday**: Set up Go workspace, create branches
- **Wednesday**: Plugin interface + RPC working
- **Friday**: Event bus converting webhooks

**Week 2:**
- **Monday**: Helper services implemented  
- **Wednesday**: First integration test passes
- **Friday**: Plugin manager loading local plugins

**Week 3:**
- **Monday**: Start vulnerability plugin extraction
- **Wednesday**: Vulnerability plugin processing events
- **Friday**: License plugin extraction starts

**Week 4:**
- **Monday**: Both plugins feature-complete
- **Wednesday**: Performance testing vs embedded
- **Friday**: Integration branch fully tested

**Week 5:**
- **Monday**: End-to-end testing
- **Wednesday**: Migration tooling
- **Friday**: Documentation and deployment

**Week 6:**
- **Monday**: Production deployment testing
- **Wednesday**: Performance optimization
- **Friday**: Ready for production migration

### 8. Migration to Production

#### Phase 1: Parallel Deployment
```bash
# Deploy both versions in parallel
kubectl apply -f k8s/polly-core.yaml    # Current version
kubectl apply -f k8s/polly-v2.yaml      # New version (different namespace)

# Route small percentage to v2
# Compare metrics and performance
```

#### Phase 2: Gradual Migration
```bash
# Increase traffic to v2 gradually
# 10% → 25% → 50% → 75% → 100%

# Monitor error rates, latencies, functionality
```

#### Phase 3: Complete Migration
```bash
# Once v2 is proven stable:
git checkout main
git merge polly-v2-integration

# Clean up workspace structure
# Move polly-v2/* to root
# Archive polly-core/
```

This strategy minimizes risk while enabling efficient parallel development of a major architectural change!
