.PHONY: setup dev build test test-all lint ui demo seed fixture docker clean validate rules scan bench help

help: ## List targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | awk 'BEGIN{FS=":.*?## "};{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

setup: ## First-time local setup: dependencies, dashboard, binaries
	@command -v go >/dev/null || { echo "go is not on PATH (this project uses Go 1.25)"; exit 1; }
	go mod download
	$(MAKE) ui
	$(MAKE) build
	@echo
	@echo "  ready. next:"
	@echo "    make dev     agent + mock upstream + seeded traffic, dashboard on :9095"
	@echo "    make rules   governance assertions"
	@echo "    make test    Go tests"

dev: build ui ## Run the local stack and open the dashboard
	./scripts/demo.sh

seed: build ## Generate realistic traffic against a running agent
	./scripts/seed.sh

fixture: build ## Regenerate examples/traffic-sample.jsonl from a real run
	./scripts/gen-fixture.sh

test-all: ## Tests for every module, including the satellite ones
	go test ./...
	cd examples/memstore  && go test ./...
	cd examples/adminauth && go test ./...
	cd sdks/gin           && go test ./...

build: ## Build agent + mock target
	go build -o bin/ ./cmd/...

test: ## Run Go tests
	go test ./...

lint: ## Vet + formatting check
	go vet ./...
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

ui: ## Build the dashboard (static export served by the agent)
	cd ui && npm install --no-audit --no-fund && npm run build

validate: build ## Lint optic.yaml
	./bin/optictrace validate -config optic.yaml

rules: build ## Run governance rule assertions (optic.test.yaml)
	./bin/optictrace test -config optic.yaml -tests optic.test.yaml

scan: build ## Find sensitive values your rules missed (needs captured traffic)
	./bin/optictrace scan -config optic.yaml -window 24h

bench: ## Measure interceptor overhead vs a bare handler
	go test ./internal/proxy -bench=. -benchmem -run='^$$' -benchtime=2s

demo: dev ## Alias for `make dev`

docker: ## Build the production image
	docker build -t optictrace:dev .

clean: ## Remove build output and the local store
	rm -rf bin ui/out ui/.next optictrace.db*
	rm -rf examples/lead-pipeline/.run examples/lead-pipeline/pipeline.db*
