# BreachReplay
SHELL := /bin/bash
PY ?= python3
VENV := .venv
VPY := $(VENV)/bin/python
COMPOSE := docker compose
SHOWCASE_COMPOSE := docker compose -f docker-compose.showcase.yml

.PHONY: help setup demo dev test test-backend test-frontend lint format build verify e2e showcase showcase-export fixtures down clean

help: ## Show targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup: ## Install backend (venv) and frontend dependencies, generate the demo capture
	$(PY) -m venv $(VENV)
	$(VPY) -m pip install -q --upgrade pip
	$(VPY) -m pip install -q -r backend/requirements-dev.txt
	cd frontend && npm ci --no-audit --no-fund
	$(PY) scripts/generate_demo_pcap.py

demo: ## Build + start the full stack and run the demo capture through Zeek + Suricata
	./scripts/demo.sh

dev: ## Analyzers + backend in Docker, Vite dev server with hot reload on :5173
	$(COMPOSE) up -d --build analyzer-zeek analyzer-suricata backend
	cd frontend && BREACHREPLAY_API=http://127.0.0.1:$${API_PORT:-8000} npm run dev

test: test-backend test-frontend ## Run backend and frontend unit tests

test-backend:
	cd backend && ../$(VPY) -m pytest -q

test-frontend:
	cd frontend && npm test

lint: ## Ruff lint + format check, TypeScript typecheck
	cd backend && ../$(VPY) -m ruff check . ../scripts && ../$(VPY) -m ruff format --check . ../scripts
	cd frontend && npm run typecheck

format: ## Format Python sources
	cd backend && ../$(VPY) -m ruff format . ../scripts && ../$(VPY) -m ruff check --fix . ../scripts

build: ## Build all Docker images
	$(COMPOSE) build

verify: ## End-to-end checks against the running stack
	./scripts/verify.sh

e2e: ## Playwright browser tests against the running production stack (:8080)
	cd frontend && E2E_BASE_URL=$${E2E_BASE_URL:-http://localhost:8080} npx playwright test

showcase: ## Run SHOWCASE mode (precomputed synthetic incident, no analyzers)
	$(COMPOSE) down --remove-orphans
	$(SHOWCASE_COMPOSE) up -d --build
	@echo "Showcase: http://localhost:$${WEB_PORT:-8080}"

showcase-export: ## Re-export showcase/showcase-incident.json from the running full stack
	$(PY) scripts/export_showcase.py --api http://localhost:$${API_PORT:-8000}

fixtures: ## Re-record backend test fixtures by running the analyzer images on the demo capture
	./scripts/record_fixtures.sh

down: ## Stop all containers
	-$(SHOWCASE_COMPOSE) down --remove-orphans
	$(COMPOSE) down --remove-orphans

clean: down ## Remove containers, volumes and local build output
	$(COMPOSE) down -v
	rm -rf frontend/dist frontend/playwright-report frontend/test-results
