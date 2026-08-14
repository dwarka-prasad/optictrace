## What & why

<!-- Summary of the change and its motivation. Link issues with "Fixes #123". -->

## Checklist

- [ ] `go vet ./... && go test ./...` pass
- [ ] Governance invariants hold (no mutation of proxied traffic; no leak of restricted/redacted data) — covered by a test if this PR touches capture/redaction
- [ ] Engine ports (Go / JS / Python) kept in sync if matching/redaction semantics changed
- [ ] Docs updated (README / CONTRIBUTING) if behavior or schema changed
