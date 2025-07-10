# CI/CD Pipeline Documentation

## Overview
This repository includes a comprehensive GitHub Actions pipeline that runs automated tests on pull requests only, ensuring code quality and security before merging.

## Pipeline Triggers
The test pipeline runs automatically when:
- A pull request is opened against `main` or `develop` branches
- Changes are made to Go files (`**.go`), Go modules (`go.mod`, `go.sum`), or the workflow itself
- The pipeline does NOT run on direct pushes to main branches

## Pipeline Jobs

### 1. Test Job
**Purpose**: Run unit tests with coverage reporting
**Includes**:
- Go 1.21 setup with module caching
- Dependency verification
- `go vet` static analysis
- Unit tests with race detection (`go test -v -race`)
- Coverage reporting with 30% minimum threshold
- Codecov integration for coverage tracking

### 2. Lint Job
**Purpose**: Ensure code quality and consistency
**Includes**:
- golangci-lint with comprehensive linter configuration
- Custom rules for test files
- 5-minute timeout for large codebases

### 3. Security Job
**Purpose**: Identify security vulnerabilities and issues
**Includes**:
- Gosec security scanner for Go-specific security issues
- Trivy vulnerability scanner for dependencies and containers
- SARIF report upload to GitHub Security tab

## Configuration Files

### `.github/workflows/test.yml`
Main CI pipeline configuration with three parallel jobs for comprehensive testing.

### `.golangci.yml`
Linter configuration with enabled rules:
- Code formatting (gofmt, goimports)
- Error checking (errcheck, govet)
- Code quality (staticcheck, gosimple, unused)
- Security (gosec)
- Code complexity (gocyclo, dupl)
- Naming conventions (revive)

### `.github/pull_request_template.md`
Template encouraging good PR practices:
- Clear description and categorization
- Testing checklist
- Security considerations
- Code quality checklist

## Current Test Coverage
- **Overall**: 37.3% (exceeds 30% threshold)
- **internal/services**: 44.4%
- **internal/clients**: 64.6%
- **internal/config**: 73.7%
- **internal/handlers**: 21.0%
- **internal/app**: 10.2%
- **cmd/server**: 3.2%

## Status Badges
The README includes status badges for:
- CI/CD pipeline status
- Go Report Card grade
- Codecov coverage percentage

## Benefits
1. **Automated Quality Gates**: Prevents broken code from reaching main branches
2. **Security First**: Identifies vulnerabilities before deployment
3. **Coverage Tracking**: Maintains and improves test coverage over time
4. **Consistent Standards**: Enforces coding standards across the team
5. **Fast Feedback**: Parallel jobs provide quick feedback to developers

## Usage
1. Create a pull request against `main` or `develop`
2. Pipeline automatically runs all checks
3. Review results in the GitHub Actions tab
4. Address any failures before requesting review
5. Merge when all checks pass

## Troubleshooting
- **Coverage Below Threshold**: Add more unit tests to increase coverage
- **Lint Failures**: Run `golangci-lint run` locally to see issues
- **Security Issues**: Review Gosec and Trivy reports in GitHub Security tab
- **Test Failures**: Run `go test -v ./...` locally to debug
