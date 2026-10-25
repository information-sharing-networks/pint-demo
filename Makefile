# Docker-based Makefile for pint-demo
# Uses tools installed in Docker containers instead of local installations

.PHONY: help check-env check-containers \
	docker-up docker-down docker-reset docker-build docker-up-db docker-down-db docker-up-app docker-down-app docker-restart-app restart logs \
	psql db-migrate-up db-migrate-down delete-envelopes \
	generate sqlc docs swag-fmt \
	check fmt vet lint security vuln test update-tools clean

export GO_VERSION := $(shell grep '^go ' app/go.mod | awk '{print $$2}')

# Docker compose service name
APP_SERVICE = app
DB_ACCOUNT = pint-dev
DB_NAME = pint_demo

# run a command in the app container from the app directory
APP_EXEC = docker compose exec $(APP_SERVICE) sh -c

# Default target - show available commands
help:
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Go version: $(GO_VERSION) (from app/go.mod)'
	@echo ''
	@echo 'Available targets:'
	@echo "  make docker-up          - Start Docker containers"
	@echo "  make docker-down        - Stop Docker containers"
	@echo "  make docker-reset       - Drop the database and restart the containers"
	@echo "  make docker-build       - Build the app container"
	@echo "  make docker-up-db       - Start the database container (detached mode)"
	@echo "  make docker-down-db     - Stop the database container"
	@echo "  make docker-up-app      - Start the app container (detached mode)"
	@echo "  make docker-down-app    - Stop the app container"
	@echo "  make docker-restart-app - Restart the app container (alias: make restart)"
	@echo "  make logs               - Follow docker app logs"
	@echo "  make psql               - Run psql against the dev database"
	@echo "  make db-migrate-up      - Run database migrations (goose up)"
	@echo "  make db-migrate-down    - Reset database and reapply migrations (goose down-to 0 > up)"
	@echo "  make delete-envelopes   - Delete all envelopes from the database"
	@echo "  make generate           - Generate docs and code (swagger + sqlc)"
	@echo "  make sqlc               - Generate sqlc code"
	@echo "  make docs               - Generate swagger documentation"
	@echo "  make swag-fmt           - Format swag comments"
	@echo "  make check              - Run all pre-commit checks (recommended before committing)"
	@echo "  make fmt                - Format code"
	@echo "  make vet                - Run go vet"
	@echo "  make lint               - Run staticcheck"
	@echo "  make security           - Run gosec security analysis"
	@echo "  make vuln               - Run govulncheck vulnerability scan"
	@echo "  make test               - Run tests (requires a local Go installation)"
	@echo "  make update-tools       - Upgrade the go tools in app/go.mod (run after bumping the Go version)"
	@echo "  make clean              - Clean build artifacts"

# Check the .env file needed to run the app in dev mode exists
check-env:
	@if [ ! -f .env ]; then \
		echo "❌ A .env file is needed to run the app in dev mode"; \
		echo ""; \
		echo "Please create a .env file in the project root."; \
		echo "You can copy the example file:"; \
		echo ""; \
		echo "  cp .env-example .env"; \
		echo ""; \
		echo "See README.md for more details."; \
		exit 1; \
	fi

# Check the app container is running (needed by targets that exec into it)
check-containers:
	@docker compose ps --status running --services | grep -qx "$(APP_SERVICE)" || \
		(echo "❌ App container not running. Run 'make docker-up' or 'make docker-up-app' first." && exit 1)

# Docker management
docker-up: check-env
	@echo "🐳 Starting Docker containers..."
	@echo "Using Go version: $(GO_VERSION)"
	@docker compose up

docker-down:
	@echo "🐳 Stopping Docker containers..."
	@docker compose down

docker-up-db:
	@echo "🐳 Starting database container (detached mode)..."
	@docker compose up db -d

docker-up-app: check-env
	@echo "🐳 Starting app container (detached mode)..."
	@docker compose up app -d

docker-down-db:
	@echo "🐳 Stopping database container..."
	@docker compose down db

docker-down-app:
	@echo "🐳 Stopping app container..."
	@docker compose down app

docker-restart-app:
	@echo "🐳 Restarting app container..."
	@docker compose restart app

restart: docker-restart-app

docker-build:
	@echo "🐳 Building app container..."
	@echo "Using Go version: $(GO_VERSION)"
	@docker compose build app

# drop the db volume, rebuild the app container with latest dependencies, restart the containers
docker-reset: check-env
	@echo "🔄 Resetting database..."
	@$(MAKE) docker-down
	@docker volume rm pint-demo_db-data-dev || true
	@$(MAKE) docker-build
	@docker compose up

logs:
	@echo "🐳 Following docker logs..."
	@docker compose logs -f app

# Run psql on the docker database
psql:
	@echo "🐘 Connecting to PostgreSQL..."
	@docker compose exec -it db psql -U $(DB_ACCOUNT) -d $(DB_NAME)

# Run database migrations
db-migrate-up: check-containers
	@echo "🔄 Running database migrations..."
	@$(APP_EXEC) 'cd /pint-demo/app && go tool goose -dir sql/schema postgres "$$DATABASE_URL" -env=none up'

# Reset database and reapply migrations
db-migrate-down: check-containers
	@echo "🔄 Resetting database..."
	@$(APP_EXEC) 'cd /pint-demo/app && go tool goose -dir sql/schema postgres "$$DATABASE_URL" -env=none down-to 0'
	@$(MAKE) db-migrate-up

# Delete the envelopes from the database
delete-envelopes: check-containers
	@echo "🗑️ Deleting envelopes..."
	@$(APP_EXEC) 'psql "$$DATABASE_URL" -c "DELETE FROM envelopes;"'

# Generate all code and documentation
generate: docs sqlc swag-fmt

# Generate type-safe SQL code
sqlc: check-containers
	@echo "🔄 Generating sqlc code..."
	@$(APP_EXEC) 'cd /pint-demo/app && go tool sqlc generate'

# Generate swagger documentation
docs: check-containers
	@echo "🔄 Generating swagger documentation..."
	@$(APP_EXEC) 'cd /pint-demo/app && go tool swag init --parseInternal -g ./cmd/pint-server/main.go'

# Format swag comments
swag-fmt: check-containers
	@echo "🔄 Formatting swag comments..."
	@$(APP_EXEC) 'cd /pint-demo/app && go tool swag fmt'

# Format code
fmt: check-containers
	@echo "🔄 Formatting code..."
	@$(APP_EXEC) 'cd /pint-demo/app && go fmt ./...'

# Run go vet
vet: check-containers
	@echo "🔍 Running go vet..."
	@$(APP_EXEC) 'cd /pint-demo/app && go vet ./...'

# Run staticcheck linter
lint: check-containers
	@echo "🔄 Running staticcheck..."
	@$(APP_EXEC) 'cd /pint-demo/app && go tool staticcheck ./...'

# Run security analysis
security: check-containers
	@echo "🔄 Running security analysis..."
	@$(APP_EXEC) 'cd /pint-demo/app && go tool gosec -exclude-generated ./...'

# Run vulnerability scan
vuln: check-containers
	@echo "🔍 Running vulnerability scan..."
	@$(APP_EXEC) 'cd /pint-demo/app && go tool govulncheck ./...'

# Run tests (requires a local installation of go)
test:
	@echo "🧪 Running tests..."
	@cd app && go test ./...
	@echo "🧪 Running integration tests..."
	@cd app && go test -v -count=1 -tags=integration ./test/integration/

# Upgrade the go tools listed in app/go.mod (staticcheck, govulncheck, sqlc etc).
# Run after bumping the go version in app/go.mod and rebuilding the image (make docker-build) -
# the tools must support the new Go version.
# Afterwards rebuild the image again so the new tool versions are precompiled - otherwise
# `go tool` compiles them inside the memory-limited app container and can get OOM killed
# (gosec pulls in some very large dependencies). Then run make check and commit app/go.mod and app/go.sum.
update-tools: check-containers
	@echo "🔧 Updating go tools..."
	@$(APP_EXEC) 'cd /pint-demo/app && go get tool && go mod tidy'
	@echo ""
	@echo "⚠️  Now run 'make docker-build' and restart the app container to precompile the updated tools"

# Main target: run all checks before committing
check: generate fmt vet lint security vuln test
	@echo ""
	@echo "✅ All checks passed! Ready to commit."

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf app/bin/ app/tmp/
	@rm -rf app/internal/database/
	@cd app && go clean -testcache
	@echo "Clean complete!"
