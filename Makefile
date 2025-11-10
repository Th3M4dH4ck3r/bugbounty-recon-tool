.PHONY: help install build test lint clean docker-build docker-up docker-down scan report

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(BLUE)Scout Security Scanner - Available Commands$(NC)"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2}'

install: ## Install dependencies
	@echo "$(BLUE)Installing dependencies...$(NC)"
	npm install
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

build: ## Build the project
	@echo "$(BLUE)Building project...$(NC)"
	npm run build
	@echo "$(GREEN)✓ Build complete$(NC)"

dev: ## Run in development mode
	@echo "$(BLUE)Starting in development mode...$(NC)"
	npm run dev

test: ## Run tests
	@echo "$(BLUE)Running tests...$(NC)"
	npm test

test-coverage: ## Run tests with coverage
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	npm run test:coverage

lint: ## Run linter
	@echo "$(BLUE)Running linter...$(NC)"
	npm run lint

lint-fix: ## Fix linting issues
	@echo "$(BLUE)Fixing linting issues...$(NC)"
	npm run lint:fix

clean: ## Clean build artifacts
	@echo "$(BLUE)Cleaning...$(NC)"
	rm -rf dist coverage reports/*.md reports/*.json pocs/*.js pocs/*.sol artifacts/* logs/*
	@echo "$(GREEN)✓ Cleaned$(NC)"

docker-build: ## Build Docker image
	@echo "$(BLUE)Building Docker image...$(NC)"
	docker-compose build
	@echo "$(GREEN)✓ Docker image built$(NC)"

docker-up: ## Start Docker containers
	@echo "$(BLUE)Starting Docker containers...$(NC)"
	docker-compose up -d
	@echo "$(GREEN)✓ Containers started$(NC)"

docker-down: ## Stop Docker containers
	@echo "$(BLUE)Stopping Docker containers...$(NC)"
	docker-compose down
	@echo "$(GREEN)✓ Containers stopped$(NC)"

docker-logs: ## View Docker logs
	docker-compose logs -f

scan: ## Run a quick scan on contracts directory
	@echo "$(BLUE)Running security scan...$(NC)"
	npm run dev -- scan --target ./contracts --output ./reports

analyze: ## Run static analysis only
	@echo "$(BLUE)Running static analysis...$(NC)"
	npm run dev -- analyze static --source ./contracts --output ./reports/findings.json

poc: ## Generate PoCs from findings
	@echo "$(BLUE)Generating PoCs...$(NC)"
	npm run dev -- poc --input ./reports/findings.json --output ./pocs

report: ## Generate report from findings
	@echo "$(BLUE)Generating report...$(NC)"
	npm run dev -- report --input ./reports/findings.json --output ./reports/report.md --format markdown
	@echo "$(GREEN)✓ Report generated at ./reports/report.md$(NC)"

server: ## Start API server
	@echo "$(BLUE)Starting API server...$(NC)"
	npm run dev -- server --port 3000

demo: build ## Run full demo workflow
	@echo "$(BLUE)Running demo workflow...$(NC)"
	@echo "1. Analyzing contracts..."
	npm run dev -- analyze static --source ./contracts --output ./reports/findings.json
	@echo "2. Generating PoCs..."
	npm run dev -- poc --input ./reports/findings.json --output ./pocs --type hardhat
	@echo "3. Creating report..."
	npm run dev -- report --input ./reports/findings.json --output ./reports/demo-report.md
	@echo "$(GREEN)✓ Demo complete! Check ./reports/demo-report.md$(NC)"

setup-env: ## Create .env file from example
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "$(GREEN)✓ Created .env file from .env.example$(NC)"; \
		echo "$(BLUE)Please edit .env and add your API keys$(NC)"; \
	else \
		echo "$(RED).env file already exists$(NC)"; \
	fi

deps-check: ## Check for outdated dependencies
	@echo "$(BLUE)Checking for outdated dependencies...$(NC)"
	npm outdated

.DEFAULT_GOAL := help
