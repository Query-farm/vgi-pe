# vgi-pe — dev and test targets.
#
# Usage:
#   make test       # unit/integration (pytest) + end-to-end SQL (haybarn-unittest)
#   make test-unit  # pytest only
#   make test-sql   # DuckDB sqllogictest .test files via haybarn-unittest
#
# test-sql is self-contained: it points VGI_PE_WORKER at the worker run as a uv
# stdio subprocess (exactly how DuckDB drives it after ATTACH) and runs the
# files under test/sql/. haybarn-unittest is a uv tool:
#   uv tool install --prerelease allow 'haybarn-unittest>=2.0.0rc11,<2.1'   # ~/.local/bin/haybarn-unittest
# haybarn 2.0 is required: its community `vgi` extension is the one that speaks the
# worker's VGI protocol (vgi.v3 / 3.2). --keep-home lets the runner see the
# extensions installed under the real $HOME (haybarn-unittest 2.0 isolates it).

# Worker command DuckDB uses for ATTACH (overridable). Use the project venv's
# python directly (NOT `uv run pe_worker.py`): a PEP-723 `uv run` resolves the
# inline script deps into a separate cached env that can pin a stale vgi-python
# and emit the old catalog RPC schema; the venv python uses the locked SDK.
WORKER_STDIO    ?= .venv/bin/python pe_worker.py

# haybarn-unittest lives in the uv tools bin; keep it on PATH.
HAYBARN_BIN     ?= $(HOME)/.local/bin
TEST_DIR         = .
TEST_PATTERN     = test/sql/*

.PHONY: test test-unit test-sql lint fixtures

test: test-unit test-sql

test-unit:
	uv run pytest -q

test-sql:
	PATH="$(HAYBARN_BIN):$$PATH" \
		VGI_PE_WORKER="$(WORKER_STDIO)" \
		haybarn-unittest --keep-home --test-dir "$(TEST_DIR)" "$(TEST_PATTERN)"

# Regenerate the committed binary fixtures under test/sql/data/ (needs a C
# compiler, mingw, and zig — see tests/fixtures.py).
fixtures:
	uv run python tests/fixtures.py

lint:
	uv run ruff format --check .
	uv run ruff check .
	uv run mypy vgi_pe/
