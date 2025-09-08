<!-- Moved from docs/IMPLEMENTATION_STEPS.md -->
# Polly 2.0 Implementation Steps

This is the step-by-step guide to implement the development strategy for Polly 2.0.

## Step 1: Set Up Go Workspace (Day 1)

### 1.1 Create workspace structure

```bash
cd /Users/danielterry/git/polly

# Create feature branch for workspace setup
git checkout -b setup/go-workspace

# Initialize Go workspace
go work init

# Create directory structure
mkdir -p polly-core polly-v2 plugins/vulnerability-plugin plugins/license-plugin tools/migration

# Move existing code to polly-core
git mv cmd internal pkg scripts tools/*.go polly-core/ 2>/dev/null || true
cp go.mod polly-core/
cp go.sum polly-core/
```

### 1.2 Set up polly-core module

```bash
cd polly-core

# Update module path to avoid conflicts
go mod edit -module github.com/terrpan/polly/polly-core

# Update internal imports in all Go files
find . -name "*.go" -exec sed -i '' 's|github.com/terrpan/polly/internal|github.com/terrpan/polly/polly-core/internal|g' {} \;
find . -name "*.go" -exec sed -i '' 's|github.com/terrpan/polly/pkg|github.com/terrpan/polly/polly-core/pkg|g' {} \;

# Test that existing code still works
go mod tidy
go build ./cmd/server
go test ./...

cd ..
```

### 1.3 Set up polly-v2 module

```bash
cd polly-v2

# Initialize new module
go mod init github.com/terrpan/polly/polly-v2

# Create basic directory structure
mkdir -p cmd/server internal/{plugins,events,helpers} pkg/sdk

# Create basic main.go
cat > cmd/server/main.go << 'EOF'
package main

import (
    "fmt"
    "log"
)

func main() {
    fmt.Println("Polly 2.0 - Plugin Architecture")
    log.Println("Starting in development mode...")
    
    // TODO: Implement event bus and plugin manager
}
EOF

# Add dependencies
go get github.com/hashicorp/go-plugin@latest

go mod tidy
cd ..
```

### 1.4 Set up plugin modules

```bash
# Vulnerability plugin
cd plugins/vulnerability-plugin
go mod init github.com/terrpan/polly/plugins/vulnerability-plugin

mkdir internal
cat > main.go << 'EOF'
package main

import (
    "context"
    "log"
    
    "github.com/hashicorp/go-plugin"
)

// TODO: Implement vulnerability plugin

func main() {
    log.Println("Vulnerability Plugin starting...")
    
    plugin.Serve(&plugin.ServeConfig{
        HandshakeConfig: plugin.HandshakeConfig{
            ProtocolVersion:  1,
            MagicCookieKey:   "POLLY_PLUGIN",
            MagicCookieValue: "polly-plugin",
        },
        Plugins: map[string]plugin.Plugin{
            "policy": &VulnerabilityPlugin{},
        },
    })
}

type VulnerabilityPlugin struct{}

// TODO: Implement plugin interface
EOF

go get github.com/hashicorp/go-plugin@latest
go mod tidy
cd ../..

# License plugin (similar structure)
cd plugins/license-plugin
go mod init github.com/terrpan/polly/plugins/license-plugin

cat > main.go << 'EOF'
package main

import (
    "log"
    
    "github.com/hashicorp/go-plugin"
)

func main() {
    log.Println("License Plugin starting...")
    
    plugin.Serve(&plugin.ServeConfig{
        HandshakeConfig: plugin.HandshakeConfig{
            ProtocolVersion:  1,
            MagicCookieKey:   "POLLY_PLUGIN",
            MagicCookieValue: "polly-plugin",
        },
        Plugins: map[string]plugin.Plugin{
            "policy": &LicensePlugin{},
        },
    })
}

type LicensePlugin struct{}
EOF

go get github.com/hashicorp/go-plugin@latest
go mod tidy
cd ../..
```

### 1.5 Add modules to workspace

```bash
# Add all modules to workspace
go work use ./polly-core ./polly-v2 ./plugins/vulnerability-plugin ./plugins/license-plugin

# Verify workspace
go work sync
```

### 1.6 Create workspace root files

```bash
# Create README for workspace
cat > README-WORKSPACE.md << 'EOF'
# Polly Workspace Development

This workspace contains multiple modules for Polly 2.0 development:

- `polly-core/`: Existing Polly application (v1.x)
- `polly-v2/`: New plugin-based architecture (v2.0) 
- `plugins/`: Official plugins
- `tools/`: Migration and development utilities

## Running Current Version
```bash
cd polly-core
go run cmd/server/main.go
```

## Running New Version (WIP)
```bash
cd polly-v2  
go run cmd/server/main.go
```

## Building Plugins
```bash
cd plugins/vulnerability-plugin
go build -o vulnerability-plugin main.go

cd ../license-plugin
go build -o license-plugin main.go
```
EOF

# Update root .gitignore
cat >> .gitignore << 'EOF'

# Workspace specific
go.work.sum

# Plugin binaries
plugins/*/vulnerability-plugin
plugins/*/license-plugin
EOF

# Commit workspace setup
git add .
git commit -m "feat: set up Go workspace for Polly 2.0 development

- Move existing code to polly-core module
- Create polly-v2 module for new architecture  
- Set up plugin modules with basic structure
- Configure Go workspace with all modules"

git push -u origin setup/go-workspace
```

## Step 2: Create Integration Branch (Day 1)

```bash
# Create long-running integration branch
git checkout -b polly-v2-integration
git push -u origin polly-v2-integration

echo "Integration branch created. All feature branches will merge here first."
```

## Step 3: Phase 1 Development (Week 1-2)

### 3.1 Plugin Architecture Foundation

```bash
git checkout polly-v2-integration
git checkout -b feature/plugin-architecture-foundation

cd polly-v2

# Create plugin interface
mkdir -p pkg/api
cat > pkg/api/plugin.go << 'EOF'
package api

import (
    "context"
    "net/rpc"
    
    "github.com/hashicorp/go-plugin"
)

// PolicyPlugin is the interface that plugins must implement
type PolicyPlugin interface {
    Name() string
    Version() string
    HandleEvent(ctx context.Context, event EnrichedEvent, helpers PollyHelpers) (*PolicyResult, error)
    Initialize(config PluginConfig) error
    Shutdown() error
    Health() error
}

// Plugin RPC implementation
type PolicyPluginRPC struct{ client *rpc.Client }
type PolicyPluginRPCServer struct{ Impl PolicyPlugin }

// Implementation of go-plugin interfaces
var _ plugin.Plugin = &PolicyPluginGRPC{}

type PolicyPluginGRPC struct {
    plugin.Plugin
    Impl PolicyPlugin
}

func (p *PolicyPluginGRPC) GRPCServer(broker *plugin.GRPCBroker, s *grpc.Server) error {
    // TODO: Implement gRPC server
    return nil
}

func (p *PolicyPluginGRPC) GRPCClient(ctx context.Context, broker *plugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
    // TODO: Implement gRPC client  
    return nil, nil
}
EOF
```

### 3.2 Event Bus System

```bash
git checkout polly-v2-integration
git checkout -b feature/event-bus-system

cd polly-v2

# Create event bus
cat > internal/events/bus.go << 'EOF'
package events

import (
    "context"
    "encoding/json"
    "log"
)

type EventProcessor struct {
    plugins []PolicyPlugin
    logger  *log.Logger
}

func NewEventProcessor() *EventProcessor {
    return &EventProcessor{
        plugins: make([]PolicyPlugin, 0),
        logger:  log.Default(),
    }
}

func (ep *EventProcessor) ProcessWebhook(ctx context.Context, eventType string, payload []byte) error {
    // Parse GitHub webhook
    event, err := ep.parseWebhookEvent(eventType, payload)
    if err != nil {
        return err
    }
    
    // Enrich event with common data
    enrichedEvent, err := ep.enrichEvent(ctx, event)
    if err != nil {
        return err
    }
    
    // Process through all plugins
    return ep.processEventThroughPlugins(ctx, enrichedEvent)
}

func (ep *EventProcessor) parseWebhookEvent(eventType string, payload []byte) (interface{}, error) {
    // TODO: Implement webhook parsing based on existing webhook handlers
    return nil, nil
}

func (ep *EventProcessor) enrichEvent(ctx context.Context, event interface{}) (*EnrichedEvent, error) {
    // TODO: Implement event enrichment
    return nil, nil
}

func (ep *EventProcessor) processEventThroughPlugins(ctx context.Context, event *EnrichedEvent) error {
    // TODO: Implement plugin processing
    return nil
}
EOF
```

### 3.3 Integration Testing Setup

```bash
# Create integration tests
mkdir -p polly-v2/tests/integration

cat > polly-v2/tests/integration/plugin_test.go << 'EOF'
//go:build integration

package integration

import (
    "context"
    "testing"
    
    "github.com/terrpan/polly/polly-v2/internal/plugins"
)

func TestPluginManager(t *testing.T) {
    manager := plugins.NewManager()
    
    err := manager.Start(context.Background())
    if err != nil {
        t.Fatalf("Failed to start plugin manager: %v", err)
    }
    
    defer manager.Stop()
    
    // TODO: Add integration tests
}
EOF
```

## Step 4: Regular Integration and Testing

### 4.1 Daily Integration

```bash
# Daily integration routine
git checkout polly-v2-integration

# Pull latest integration changes  
git pull origin polly-v2-integration

# Merge ready feature branches
git merge feature/plugin-architecture-foundation
git merge feature/event-bus-system

# Test integration
cd polly-v2
go build ./cmd/server
go test ./...
go test -tags=integration ./tests/integration/...

# Push if tests pass
git push origin polly-v2-integration
```

### 4.2 Weekly Reviews

```bash
# Weekly code review routine

# Create PR from feature branch to integration branch
gh pr create --base polly-v2-integration --title "feat: plugin architecture foundation" --body "Implements core plugin interface and RPC communication"

# After review and approval, merge feature branch
git checkout polly-v2-integration
git merge feature/plugin-architecture-foundation
git push origin polly-v2-integration

# Delete merged feature branch
git branch -d feature/plugin-architecture-foundation
git push origin --delete feature/plugin-architecture-foundation
```

## Step 5: Migration to Production (Week 6+)

### 5.1 Prepare for Production

```bash
# Once all features are integrated and tested
git checkout main
git pull origin main

# Create migration PR
git checkout polly-v2-integration
gh pr create --base main --title "feat: Polly 2.0 - Plugin Architecture" --body "Complete architectural transformation to plugin-based system"
```

### 5.2 Production Migration

```bash
# After PR approval and merge
git checkout main
git pull origin main

# Clean up workspace structure (move v2 to root)
mv polly-v2/* .
mv polly-v2/.* . 2>/dev/null || true
rmdir polly-v2

# Archive polly-core
mkdir archive
mv polly-core archive/

# Update workspace
go work edit -dropuse ./polly-v2
go work edit -dropuse ./polly-core
go work edit -use .

# Commit final structure
git add .
git commit -m "chore: finalize Polly 2.0 migration

- Move polly-v2 to root directory
- Archive polly-core for reference  
- Update Go workspace configuration"

git push origin main
```

## Benefits of This Implementation Strategy

✅ **Parallel Development**: Teams can work independently on different components  
✅ **Risk Mitigation**: Existing system remains functional throughout development  
✅ **Continuous Integration**: Regular merging and testing prevents integration hell  
✅ **Quality Control**: Feature branches reviewed before integration  
✅ **Rollback Capability**: Can revert to working state at any point  
✅ **Production Ready**: Clear migration path to production deployment  

This approach transforms a risky "big bang" rewrite into manageable, parallel development with continuous validation!
