# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.16.0",
#     "lief>=0.15",
#     "pyarrow",
# ]
# ///
"""Repo-root PEP-723 shim for the ``pe`` VGI worker.

The catalog, ``PeWorker`` class, and ``main()`` live in the wheel-importable
``vgi_pe.worker`` module (so a ``pip install``ed wheel and the container image
can import them). This thin shim re-exports them and keeps the original
``uv run pe_worker.py`` entry point working unchanged for the Makefile,
``ci/run-integration.sh``, DuckDB ``ATTACH``, and the test fixtures.

Usage:
    uv run pe_worker.py            # serve over stdio (DuckDB subprocess)

    INSTALL vgi FROM community; LOAD vgi;
    ATTACH 'pe' (TYPE vgi, LOCATION 'uv run pe_worker.py');
"""

from __future__ import annotations

from vgi_pe.worker import PeWorker, main

__all__ = ["PeWorker", "main"]


if __name__ == "__main__":
    main()
