# Contributing to OpticTrace

Thanks for helping build OpticTrace! This guide gets you productive quickly.

## Development setup

```bash
# Go agent (Go ≥ 1.23)
go build ./... && go test ./...

# Dashboard (Node ≥ 20)
cd ui && npm install && npm run dev     # dev server on :3000, agent on :9095

# SDKs
cd sdks/express && npm install && npm test
cd sdks/fastapi && python3 test_middleware.py
cd sdks/gin && go build ./...
```

Run the full local stack: `./scripts/demo.sh`.

## Ground rules

1. **Governance invariants are non-negotiable.** Proxied traffic is never
   mutated; redaction/restriction applies only to recorded telemetry; the
   telemetry pipeline must never block or fail a request. Any PR that could
   leak a restricted or redacted value needs a test proving it doesn't.
2. **The rule engine is portable.** `internal/engine` (Go),
   `sdks/express/engine.js`, and `sdks/fastapi/.../engine.py` must stay
   semantically identical. If you change matching or redaction semantics,
   change all three and their parity tests.
3. **Hot path discipline.** Per-request work in `internal/proxy` should not
   allocate beyond the policy/record. Benchmark if in doubt.
4. **Config changes are schema changes.** New `optic.yaml` fields need:
   strict validation, defaults in `applyTelemetryDefaults`/`Parse`, docs in
   the README reference, and a validation test.

## Pull requests

- Fork, branch from `main`, keep PRs focused.
- `go vet ./... && gofmt -l . && go test ./...` must pass; UI changes need `npm run build` to succeed.
- Add tests for behavior changes; update docs in the same PR.
- Use conventional commit prefixes when convenient (`feat:`, `fix:`, `docs:`).

## Reporting issues

Use the issue templates. For **suspected telemetry leaks** (sensitive data
appearing in logs/store/metrics despite rules), please email the maintainers
instead of opening a public issue — treat it as a security report.

## Project roadmap ideas

Good areas to pick up:

- Additional `LogStore` drivers (ClickHouse, Postgres)
- OpenTelemetry trace export
- SDKs: Rails, Spring, Laravel, Koa/Fastify
- Rule testing CLI (`optictrace test` — assert a request matches a policy)
- Dashboard: diff view for config reloads, saved inspector filters
