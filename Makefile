# Docker-based Makefile for pint-demo

.PHONY: help build test clean db-migrate db-reset sqlc docker-up docker-down docker-reset docker-up-db docker-down-db docker-app-up docker-app-down docker-restart-app docker-build restart logs psql check fmt vet vuln

export GO_VERSION := $(shell grep '^go ' app/go.mod | awk '{print $$2}')

# Docker compose service name
APP_SERVICE = app
DB_ACCOUNT = pint-dev
DB_NAME = pint_demo

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Go version: $(GO_VERSION) (from app/go.mod)'
	@echo ''
	@echo 'Available targets:'
	@echo "  make help               - Show this help message"
	@echo "  make docker-up          - Start Docker containers"
	@echo "  make docker-down        - Stop Docker containers"
	@echo "  make docker-reset       - Drop the database and restart the containers"
	@echo "  make docker-build       - Build the app container"
	@echo "  make docker-up-db       - Start the database container (detached mode)"
	@echo "  make docker-down-db     - Stop the database container"
	@echo "  make docker-up-app      - Start the app container (detached mode)"
	@echo "  make docker-down-app    - Stop the app container"
	@echo "  make docker-restart-app - Restart the app container"
	@echo "  make logs               - Follow docker app logs"
	@echo "  make psql               - Run psql against the dev database"
	@echo "  make sqlc               - Generate sqlc code"
	@echo "  make docs               - Generate swagger documentation"
	@echo "  make swag-fmt           - format swag comments"
	@echo "  make db-migrate         - Run database migrations (goose up)"
	@echo "  make db-reset           - Reset database and reapply migrations (goose down-to 0 > up)"
	@echo "  make delete-envelopes   - Delete all envelopes from the database"
	@echo "  make test               - Run tests"
	@echo "  make fmt                - Format code"
	@echo "  make lint               - Run staticcheck"
	@echo "  make security           - Run gosec security analysis"
	@echo "  make vet                - Run go vet"
	@echo "  make check              - Run all pre-commit checks (recommended before committing)"
	@echo "  make clean              - Clean build artifacts"

check-env:
	@if [ ! -f .env ]; then \
		echo "Error: a .env file is needed running the app in dev mode"; \
		echo ""; \
		echo "Please create a .env file in the project root."; \
		echo "You can copy the example file:"; \
		echo ""; \
		echo "  cp .env.example .env"; \
		echo ""; \
		echo "See README.md for more details."; \
		exit 1; \
	fi

# Docker management
docker-up:
	@$(MAKE) check-env
	@echo "🐳 Starting Docker containers..."
	@echo "Using Go version: $(GO_VERSION)"
	@GO_VERSION=$(GO_VERSION) docker compose up

docker-down:
	@echo "🐳 Stopping Docker containers..."
	@docker compose down

docker-up-db:
	@echo "🐳 Starting database container (detached mode)..."
	@docker compose up db -d

docker-up-app:
	@echo "🐳 Starting app container (detached mode)..."
	@docker compose up app -d

docker-down-db:
	@echo "🐳 Stopping database container..."
	@docker compose down db

docker-down-app:
	@echo "🐳 Stopping app container..."
	@docker compose down app

docker-restart-app:
	@echo "🐳 Restart app container..."
	@docker compose restart app

docker-build:
	@echo "🐳 Building app container..."
	@echo "Using Go version: $(GO_VERSION)"
	@GO_VERSION=$(GO_VERSION) docker compose build app

# drop the db volume, restart the app container with latest dependencies, restart the containers
docker-reset:
	@$(MAKE) check-env
	@echo "🔄 Resetting database..."
	$(MAKE) docker-down
	@docker volume rm pint-demo_db-data-dev || true
	@echo "🐳 Rebuilding app container..."
	@echo "Using Go version: $(GO_VERSION)"
	@GO_VERSION=$(GO_VERSION) docker compose build app
	@GO_VERSION=$(GO_VERSION) docker compose up

restart:
	@echo "🐳 Restarting app container..."
	@docker compose restart app

logs:
	@echo "🐳 Following docker logs..."
	@docker compose logs -f app

# Database access
psql:
	@echo "🐘 Connecting to PostgreSQL..."
	@docker compose exec db psql -U $(DB_ACCOUNT) -d $(DB_NAME)

# Generate sqlc code
sqlc:
	@echo "🔄 Generating sqlc code..."
	@docker compose exec $(APP_SERVICE) sh -c "cd /pint-demo/app && sqlc generate"

# delete the envelopes from the database
delete-envelopes:
	@echo "🗑️ Deleting envelopes..."
	@docker compose exec $(APP_SERVICE) sh -c "cd /pint-demo/app && psql \$$DATABASE_URL -c 'DELETE FROM ENVELOPES CASCADE;'"

# Run database migrations
db-migrate:
	@echo "🔄 Running database migrations..."
	@docker compose exec $(APP_SERVICE) sh -c "cd /pint-demo/app && goose -dir sql/schema postgres \$$DATABASE_URL -env=none up"


# Reset database and reapply migrations
db-reset:
	@echo "🔄 Resetting database..."
	@docker compose exec $(APP_SERVICE) sh -c "cd /pint-demo/app && goose -dir sql/schema postgres \$$DATABASE_URL -env=none down-to 0"
	@$(MAKE) db-migrate

# Format code
fmt:
	@echo "🔄 Formatting code..."
	@docker compose exec $(APP_SERVICE) sh -c "cd /pint-demo/app && go fmt ./..."

# Run go vet
vet:
	@echo "🔍 Running go vet..."
	@docker compose exec $(APP_SERVICE) sh -c "cd /pint-demo/app && go vet ./..."

# Run staticcheck linter
lint:
	@echo "🔄 Running staticcheck..."
	@docker compose exec $(APP_SERVICE) sh -c "cd /pint-demo/app && staticcheck ./..."

# Format swag comments
swag-fmt:
	@echo "🔄 Formatting swag comments..."
	@docker compose exec $(APP_SERVICE) sh -c "cd /pint-demo/app && swag fmt"


# Generate swagger documentation
docs:
	@echo "🔄 Generating swagger documentation..."
	@docker compose exec $(APP_SERVICE) sh -c "cd /pint-demo/app && swag init --parseInternal -g ./cmd/pint-server/main.go  "

# Run security analysis
security:
	@echo "🔄 Running security analysis..."
	@docker compose exec $(APP_SERVICE) sh -c "cd /pint-demo/app && gosec -exclude-generated ./..."


# Run vulnerability scan
vuln:
	@echo "🔍 Running vulnerability scan..."
	@docker compose exec $(APP_SERVICE) sh -c "cd /pint-demo/app && govulncheck ./..."

# Run tests
test:
	@echo "🧪 Running tests (note tests require a local installation of go)..."
	@sh -c "cd app && go test ./..."

	@echo "🧪 Running integration tests"
	@sh -c "cd app && go test -v -count=1 -tags=integration ./test/integration/"


# Run all checks
check: generate fmt vet test lint security vuln
	@echo ""
	@echo "✅ All checks passed! Ready to commit."

# Generate all code and documentation
generate: docs sqlc swag-fmt 

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -rf app/bin/
	@rm -rf app/internal/database/
	@echo "Clean complete!"

