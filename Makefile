.PHONY: help test lint opa-test build up down clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

test: ## Run all tests (Python + OPA)
	pytest -v
	@echo "---"
	opa test gateway/opa/ -v

lint: ## Run flake8 linter
	flake8 .

build: ## Build all Docker images
	docker build -t ztlab-demo-app ./app
	docker build -t ztlab-authz-bridge ./gateway/authz-bridge
	docker build -t ztlab-mock-oidc ./gateway/mock-oidc

up: ## Start the gateway stack (detached)
	cd gateway && docker compose up -d

down: ## Stop the gateway stack
	cd gateway && docker compose down

logs: ## Tail gateway stack logs
	cd gateway && docker compose logs -f

clean: ## Remove Python caches and pytest caches
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true

create-vms: ## Create KVM/libvirt VMs (requires root)
	sudo bash scripts/create-vms.sh
