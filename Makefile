# Docker-based Makefile for pint-demo

.PHONY: help build run-receiver run-sender test clean migrate sqlc docker-up docker-down restart logs psql check fmt vet

# Docker compose service name
APP_SERVICE = app
DB_ACCOUNT = pint-dev
DB_NAME = pint_demo

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@echo "  make help            - Show this help message"
	@echo "  make docker-up       - Start Docker containers"
	@echo "  make docker-down     - Stop Docker containers"
	@echo "  make docker-reset    - Drop the database and restart the containers"
	@echo "  make restart         - Restart the app container"
	@echo "  make logs            - Follow docker logs"
	@echo "  make psql            - Run psql against the dev database"
	@echo "  make sqlc            - Generate sqlc code"
	@echo "  make docs            - Generate swagger documentation"
	@echo "  make swag-fmt        - format swag comments"
	@echo "  make migrate         - Run database migrations (up)"
	@echo "  make run-receiver    - Run receiver locally (expects docker db to be running)"
	@echo "  make run-sender      - Run sender CLI locally (expects docker db to be running)"
	@echo "  make test            - Run tests"
	@echo "  make fmt             - Format code"
	@echo "  make lint            - Run staticcheck"
	@echo "  make security        - Run gosec security analysis"
	@echo "  make vet             - Run go vet"
	@echo "  make check           - Run all pre-commit checks (recommended before committing)"
	@echo "  make clean           - Clean build artifacts"

# Docker management
docker-up:
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
	@echo "🐳 Starting Docker containers..."
	@docker compose up 

docker-down:
	@echo "🐳 Stopping Docker containers..."
	@docker compose down

# drop the db volume, restart the app container with latest dependencies, restart the containers
docker-reset:
	@echo "🔄 Resetting database..."
	$(MAKE) docker-down
	@docker volume rm pint-demo_db-data-dev || true
	@echo "🐳 Rebuilding app container..."
	@docker compose build app
	@docker compose up

restart:
	@echo "🐳 Restarting app container..."
	@docker compose restart app

logs:
	@echo "🐳 Following docker logs..."
	@docker compose logs -f

# Database access
psql:
	@echo "🐘 Connecting to PostgreSQL..."
	@docker compose exec db psql -U $(DB_ACCOUNT) -d $(DB_NAME)

# Generate sqlc code
sqlc:
	@echo "🔄 Generating sqlc code..."
	@docker compose exec $(APP_SERVICE) sh -c "cd /pint-demo/app && sqlc generate"

# Run database migrations
migrate:
	@echo "🔄 Running database migrations..."
	@docker compose exec $(APP_SERVICE) sh -c "cd /pint-demo/app && goose -dir sql/schema postgres \$$DATABASE_URL -env=none up"

# Run receiver locally (expects docker db to be running)
run-receiver:
	@echo "🚀 Running receiver locally..."
	@cd app && DATABASE_URL="postgres://pint-dev@localhost:15433/pint_demo?sslmode=disable" SECRET_KEY="dev-secret-key-12345" go run cmd/pint-server/main.go

# Run sender CLI locally (expects docker db to be running)
run-sender:
	@echo "🚀 Running sender CLI locally..."
	@cd app && DATABASE_URL="postgres://pint-dev@localhost:15433/pint_demo?sslmode=disable" SECRET_KEY="dev-secret-key-12345" go run cmd/pint-client/main.go

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

