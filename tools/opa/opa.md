# OPA Compliance Policies

---

## Usage
To use the OPA policies in this directory, you can run the following command:

```bash
opa run --server --bundle bundle/ --watch
```

```bash
curl -s -X POST http://localhost:8181/v1/data/compliance/vulnerability -H "Content-Type: application/json" -d @sample/vuln_trivy_sample.json | jq
```

Endpoints:
`v1/data/compliance/vulnerability` - Check vulnerability compliance
`v1/data/compliance/license` - Check license compliance - TODO: Implement

### TODO:
- [ ] Implement license compliance checks in the OPA policies.
- [ ] Define allowed licenses and extract license information from input.
- [ ] OCI registry support for storing policies.
