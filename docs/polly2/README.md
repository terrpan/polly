# Polly 2.0 Documentation Hub

This directory consolidates all Polly 2.0 (event bus + plugin ecosystem) design and implementation documents.

## Structure

- `adr/` – Architectural Decision Records specific to Polly 2.0 evolution
- `api/` – Canonical API specifications (authoritative surfaces)
- `guides/` – Implementation, strategy, file & artifact access, development workflows
- `examples/` – Copy-paste ready plugin examples

## Core Entry Points

| Topic | File |
|-------|------|
| Architectural Rationale & Transformation | `adr/ADR-012-plugin-system-policy-extraction.md` |
| Canonical Plugin API (authoritative) | `api/PLUGIN_API_REFERENCE.md` |
| Event Bus Architecture & Diagrams | `guides/event-bus-architecture.md` |
| System Implementation Guide (detailed) | `guides/PLUGIN_SYSTEM_IMPLEMENTATION_GUIDE.md` |
| Development Strategy & Phasing | `guides/DEVELOPMENT_STRATEGY.md` |
| Step-by-Step Implementation Tasks | `guides/IMPLEMENTATION_STEPS.md` |
| Dependency Discipline (Polly 2.0) | `guides/DEPENDENCY_ANALYSIS.md` |
| File & Artifact Access Guide | `guides/PLUGIN_FILE_ACCESS_GUIDE.md` |
| PR Commenting Example Plugin | `examples/plugin-pr-comments-example.md` |

## Canonical Source of Truth
The Plugin API spec in `api/PLUGIN_API_REFERENCE.md` is authoritative. If other documents drift, update them to align with the API reference (never redefine structures elsewhere).

## Migration Notes
Legacy exploratory docs retained for historical context but should not be updated going forward:
- `guides/plugin-interface-refined.md` (superseded by API reference)

## Pending Cleanup / Enhancements
- Archive or mark superseded exploratory docs explicitly
- Add index of official plugin repositories once published
- Introduce version negotiation details post v0.1 stabilization

---
For questions or updates, open a PR referencing this hub.
