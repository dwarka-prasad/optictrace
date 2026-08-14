.PHONY: build test lint ui demo docker clean validate

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

demo: build ## Run the local end-to-end demo
	./scripts/demo.sh

docker: ## Build the production image
	docker build -t optictrace:dev .

clean:
	rm -rf bin ui/out ui/.next optictrace.db*
