.PHONY: install check test test-unit test-db-up test-db-down test-migration migrate

# Test Postgres knobs (disposable, localhost-only).
TEST_DB_HOST ?= localhost
TEST_DB_PORT ?= 5439
TEST_DB_NAME ?= vendor_cp_test
TEST_DB_ADMIN_USER ?= postgres
TEST_DB_ADMIN_PASSWORD ?= postgres
TEST_DB_MIGRATOR_USER ?= app_admin

install:  ## Install deps (kernel from Forgejo; set POETRY_HTTP_BASIC_FORGEJO_* from OpenBao)
	poetry install

check:  ## Lint + format-check + types
	poetry run ruff check .
	poetry run ruff format --check .
	poetry run mypy

test:  ## Boot, provisioning contract, D1–D5 deny cases, accounts (SQLite)
	poetry run pytest -q --ignore=tests/migration

test-unit: test  ## Alias for the fast (SQLite) suite

test-db-up:  ## Start disposable test Postgres and migrate (creates roles + schema)
	TEST_DB_PORT=$(TEST_DB_PORT) TEST_DB_NAME=$(TEST_DB_NAME) \
	TEST_DB_ADMIN_USER=$(TEST_DB_ADMIN_USER) TEST_DB_ADMIN_PASSWORD=$(TEST_DB_ADMIN_PASSWORD) \
	docker compose -f docker-compose.test.yml up -d --wait
	# The init script creates the permanent production-shaped migrator before
	# any kernel or module DDL. The cluster bootstrap role never runs migrations.
	MIGRATION_DATABASE_URL=postgresql+psycopg://$(TEST_DB_MIGRATOR_USER)@$(TEST_DB_HOST):$(TEST_DB_PORT)/$(TEST_DB_NAME) \
	poetry run dotmac-platform admin migrate

test-db-down:  ## Stop + remove the test Postgres
	TEST_DB_PORT=$(TEST_DB_PORT) docker compose -f docker-compose.test.yml down -v

test-migration:  ## Vendor migration rehearsals (needs test-db-up)
	TEST_DATABASE_URL=postgresql+psycopg://$(TEST_DB_ADMIN_USER):$(TEST_DB_ADMIN_PASSWORD)@$(TEST_DB_HOST):$(TEST_DB_PORT)/$(TEST_DB_NAME) \
	poetry run pytest tests/migration -q

migrate:  ## Apply migrations (uses MIGRATION_DATABASE_URL/DATABASE_URL from env)
	poetry run dotmac-platform admin migrate
