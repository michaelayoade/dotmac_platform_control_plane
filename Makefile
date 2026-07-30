.PHONY: install check test

install:  ## Install deps (kernel from Forgejo; set POETRY_HTTP_BASIC_FORGEJO_* from OpenBao)
	poetry install

check:  ## Lint + format-check + types
	poetry run ruff check .
	poetry run ruff format --check .
	poetry run mypy

test:  ## Boot, provisioning contract, D1–D5 deny cases
	poetry run pytest -q
