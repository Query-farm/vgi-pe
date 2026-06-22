"""Static analysis of executable binaries (PE / ELF / Mach-O) as a VGI worker.

A defensive **malware-triage** tool: it parses an untrusted executable image and
reports static signals — format, architecture, entry point, signing, build
timestamp, sections + per-section entropy, imports, exports, and printable
strings — as DuckDB functions. It **never executes** the binary.

The implementation is split so each concern stays focused:

- ``core``    -- pure parse / extraction logic over ``lief``; no Arrow or VGI
  dependency, directly unit-testable. Total and crash-proof: hostile input
  yields ``None`` / empty results, never an exception.
- ``scalars`` -- per-row VGI scalar functions (positional-only; the binary
  argument is a VARCHAR path or a BLOB of bytes, exposed as arity overloads).
- ``tables``  -- set-returning extractors (``sections``, ``imports``,
  ``exports``, ``strings``).

``pe_worker.py`` at the repo root assembles these into the ``pe`` catalog and
runs the worker over stdio (or HTTP).
"""

from __future__ import annotations

__version__ = "0.1.0"
