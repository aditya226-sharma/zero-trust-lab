.PHONY: help test lint opa-test build up down logs clean create-vms \
       prod-up prod-down prod-logs dashboard logging-up logging-down

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

test: ## Run all tests (Python + OPA)
	pytest -v
	@echo "---"
	opa test gateway/opa/ -v

lint: ## Run flake8 linter
	flake8 .

build: ## Build all Docker images locally
	docker build -t ztlab-demo-app ./app
	docker build -t ztlab-authz-bridge ./gateway/authz-bridge
	docker build -t ztlab-mock-oidc ./gateway/mock-oidc

up: ## Start the gateway stack locally (detached)
	cd gateway && docker compose up -d

down: ## Stop the gateway stack
	cd gateway && docker compose down

logs: ## Tail gateway stack logs
	cd gateway && docker compose logs -f

prod-up: ## Start using pre-built GHCR images (detached)
	cd gateway && docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

prod-down: ## Stop production stack
	cd gateway && docker compose -f docker-compose.yml -f docker-compose.prod.yml down

prod-logs: ## Tail production stack logs
	cd gateway && docker compose -f docker-compose.yml -f docker-compose.prod.yml logs -f

dashboard: ## Open admin dashboard in browser (requires gateway up)
	@echo "Admin dashboard: http://localhost/admin"
	@echo "Grafana:          http://localhost:3000 (admin/ztlab-grafana)"
	@echo "Loki API:         http://localhost:3100/ready"

logging-up: ## Start the full stack with logging (Loki + Grafana)
	cd gateway && docker compose --profile logging up -d

logging-down: ## Stop the logging stack
	cd gateway && docker compose --profile logging down

clean: ## Remove Python caches and pytest caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true

create-vms: ## Create KVM/libvirt VMs (requires root)
	sudo bash scripts/create-vms.sh
