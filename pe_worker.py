# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.9.0",
#     "lief>=0.15",
#     "pyarrow",
# ]
# ///
"""VGI worker exposing static analysis of executable binaries to SQL.

Assembles the functions in ``vgi_pe`` into a single ``pe`` catalog and runs the
worker over stdio (DuckDB subprocess) or HTTP. It does **static** triage of
PE / ELF / Mach-O images -- format, architecture, entry point, signing, build
timestamp, sections + per-section entropy, imports, exports, and printable
strings -- as DuckDB functions.

This is a **defensive malware-triage** tool. Every input is presumed to be an
untrusted, possibly-hostile sample: the worker only **reads and describes** the
bytes, it NEVER executes the binary and never resolves any external reference.
Malformed / truncated / non-binary input degrades to NULL (scalars) or no rows
(table functions) -- it never crashes or hangs the worker. Backed by ``lief``
(Apache-2.0), one permissive cross-format parser.

Usage:
    uv run pe_worker.py            # serve over stdio (DuckDB subprocess)

    INSTALL vgi FROM community; LOAD vgi;
    ATTACH 'pe' (TYPE vgi, LOCATION 'uv run pe_worker.py');

    SELECT pe.binary_format('sample.exe');            -- 'PE'
    SELECT pe.is_signed('sample.exe');                -- false
    SELECT pe.machine('sample.exe');                  -- 'X86_64'
    SELECT pe.imphash('sample.exe');                  -- import hash for clustering
    SELECT pe.overall_entropy('sample.exe');          -- packing signal (0-8)
    SELECT * FROM pe.sections('sample.exe') ORDER BY name;
    SELECT * FROM pe.imports('sample.exe');
    SELECT * FROM pe.exports('sample.so');
    SELECT * FROM pe.strings('sample.exe', min_len := 8);
"""

from __future__ import annotations

import json

from vgi import Worker
from vgi.catalog import Catalog, Schema

from vgi_pe.meta import keywords_array
from vgi_pe.scalars import SCALAR_FUNCTIONS
from vgi_pe.tables import TABLE_FUNCTIONS

_FUNCTIONS: list[type] = [
    *SCALAR_FUNCTIONS,
    *TABLE_FUNCTIONS,
]

# Catalog/schema discovery metadata (provenance, support, LLM/Markdown
# descriptions). The per-function descriptions/examples live on each function's
# Meta; this only adds the catalog- and schema-level tags consumers and LLMs
# read when listing/describing the worker.
_CATALOG_DESCRIPTION_LLM = (
    "Static, read-only triage of executable binaries (Windows PE, Linux ELF, macOS Mach-O) as SQL "
    "functions: detect the format and architecture, read the entry point, code-signing status, PE "
    "build timestamp and import hash (imphash) for clustering, compute whole-file and per-section "
    "Shannon entropy to spot packing/encryption, and list sections, imported/exported symbols, and "
    "printable strings. Each function takes a binary as either a VARCHAR filesystem path or a BLOB "
    "of raw bytes. The worker NEVER executes the binary and never resolves external references; "
    "malformed or hostile input degrades to NULL / no rows. Use for malware triage, build "
    "provenance, and binary-corpus analysis in SQL."
)
_CATALOG_DESCRIPTION_MD = (
    "# Executable Binary Analysis in SQL (PE / ELF / Mach-O)\n\n"
    "![LIEF logo](https://raw.githubusercontent.com/lief-project/LIEF/main/doc/sphinx/_static/logo_blue.png)\n\n"
    "**Static, read-only malware triage and binary forensics over Apache Arrow** — parse Windows "
    "PE, Linux ELF, and macOS Mach-O executables and query their format, architecture, entropy, "
    "imports, exports, sections, and strings directly from DuckDB SQL.\n\n"
    "The `pe` catalog turns static binary analysis into ordinary SQL. It is built for malware "
    "analysts, incident responders, threat hunters, reverse engineers, and anyone running "
    "build-provenance or binary-corpus checks at scale. Instead of shelling out to a pile of "
    "command-line tools and stitching their output together, you `ATTACH` this worker and `SELECT` "
    "the facts you need — across thousands of samples — with the full power of joins, filters, and "
    "aggregation. Every input is treated as untrusted and possibly hostile: the worker only **reads "
    "and describes** the bytes. It NEVER executes the sample and never resolves an external "
    "reference, and malformed, truncated, or non-binary input degrades cleanly to `NULL` (scalars) "
    "or no rows (table functions) rather than crashing or hanging.\n\n"
    "Cross-format parsing is powered by [LIEF](https://lief.re) (Library to Instrument Executable "
    "Formats), a permissive Apache-2.0 library that reads PE, ELF, and Mach-O through one consistent "
    "API. See the [LIEF source on GitHub](https://github.com/lief-project/LIEF) and the "
    "[LIEF documentation](https://lief.re/doc/stable/index.html) for format details. The worker "
    "wraps LIEF in total, crash-proof extractors and exposes them as Arrow-native DuckDB functions; "
    'bounds on input size, string counts, and row counts keep even adversarial "bomb" inputs from '
    "exhausting memory.\n\n"
    "The catalog exposes two shapes of query. **Per-binary facts** answer a single question about a "
    "sample — its container format and CPU architecture, its entry point, whether it is code-signed, "
    "its build timestamp and import-hash fingerprint, and its whole-file entropy — so they slot "
    "directly into a projection or a filter and scale across an entire corpus. **Set-returning "
    "functions** expand one binary into many rows — its per-section layout with entropy, its "
    "imported and exported symbols, and its printable strings — for row-level IOC hunting, "
    "filtering, and joining. Every function accepts the binary as either a filesystem path it opens "
    "or raw bytes passed inline, so you can analyze files on disk or blobs already living in a "
    "table, and each pairs its narrative with runnable, tested example queries. Discover the exact "
    "set of functions by listing the schema. Static analysis only — the binary is never executed."
)
_SCHEMA_DESCRIPTION_LLM = (
    "Static binary-analysis functions over PE/ELF/Mach-O images: format and architecture detection, "
    "entry point, code-signing status, PE build timestamp and imphash, whole-file and per-section "
    "entropy, and listings of sections, imports, exports, and printable strings. Input is a VARCHAR "
    "path or a BLOB; the binary is never executed."
)
_SCHEMA_DESCRIPTION_MD = (
    "## main\n\n"
    "Static analysis of PE/ELF/Mach-O binaries over Apache Arrow.\n\n"
    "This schema groups the worker's functions into navigation categories covering format and "
    "architecture detection, structural layout, entropy and packing signals, signing and build "
    "provenance, imported/exported symbols, and printable-string extraction. Per-binary scalar "
    "facts fold into projections and filters; set-returning functions expand a single sample into "
    "rows for hunting and joining. List the schema to discover the exact functions and their "
    "categories.\n\n"
    "Every function accepts a VARCHAR path or a BLOB and degrades to NULL / no rows on hostile "
    "input. Static (read-only) — the binary is never executed."
)
# Representative, catalog-qualified example queries for the schema (VGI506). They
# read committed fixtures by relative path so they run against an attached worker.
_SCHEMA_EXAMPLE_QUERIES = (
    "SELECT pe.main.binary_format('test/sql/data/hello.exe');\n"
    "SELECT pe.main.machine('test/sql/data/hello.exe');\n"
    "SELECT pe.main.overall_entropy('test/sql/data/hello.exe');\n"
    "SELECT pe.main.imphash('test/sql/data/hello.exe');\n"
    "SELECT name, entropy FROM pe.main.sections('test/sql/data/hello.exe') ORDER BY entropy DESC;\n"
    "SELECT * FROM pe.main.imports('test/sql/data/hello.exe') LIMIT 10;\n"
    "SELECT * FROM pe.main.strings('test/sql/data/hello.exe', min_len := 8) LIMIT 10;"
)
_CATALOG_KEYWORDS = (
    "pe, elf, mach-o, macho, binary analysis, malware triage, static analysis, reverse engineering, "
    "imphash, entropy, packing, sections, imports, exports, strings, code signing, lief, executable"
)
_SCHEMA_KEYWORDS = (
    "binary_format, machine, entry_point, is_signed, compile_timestamp, imphash, section_count, "
    "overall_entropy, sections, imports, exports, strings, malware triage, static analysis"
)

# VGI413/VGI408-412: the schema's ordered category registry. Every function
# carries a `vgi.category` (set via `meta.object_tags(category=...)`) naming one
# of these slugs; array order is the display order and each category has at least
# one member (VGI412). These are the navigation sections the worker groups its
# functions into.
_SCHEMA_CATEGORIES = json.dumps(
    [
        {
            "name": "format",
            "title": "Format & Architecture",
            "description": "Detect the container format (PE/ELF/Mach-O) and target CPU architecture.",
        },
        {
            "name": "structure",
            "title": "Structure & Layout",
            "description": "Entry point, section count, and per-section layout of the image.",
        },
        {
            "name": "entropy",
            "title": "Entropy & Packing",
            "description": "Whole-file Shannon entropy as a packing/encryption signal.",
        },
        {
            "name": "signing",
            "title": "Signing & Provenance",
            "description": "Code-signing status, PE build timestamp, and import-hash clustering.",
        },
        {
            "name": "symbols",
            "title": "Imports & Exports",
            "description": "Imported and exported symbol tables.",
        },
        {
            "name": "strings",
            "title": "Strings",
            "description": "Printable ASCII/UTF-16 string extraction and IOC hunting.",
        },
    ]
)

# VGI152/VGI407: a fixed, version-controlled agent-suitability suite. `vgi-lint
# simulate` / the --agent-check pass run an LLM analyst through each `prompt`
# (the only field it sees) against the attached worker; `reference_sql` is the
# grader-only canonical solution. Each task targets a committed fixture by
# relative path (worker cwd = repo root) so it runs deterministically.
# The scalar tasks return a single value whose auto-generated column name depends
# on exactly how the analyst spells the call, so they are graded by VALUE only
# (`ignore_column_names`); the deterministic reference below fixes the expected
# value. The one multi-column task pins explicit column names in the prompt.
_AGENT_TEST_TASKS = json.dumps(
    [
        {
            "name": "detect-format",
            "prompt": (
                "Using the attached 'pe' worker, return the single executable container-format "
                "value (PE, ELF, or Mach-O) of the file at path 'test/sql/data/hello.exe'."
            ),
            "reference_sql": "SELECT pe.main.binary_format('test/sql/data/hello.exe')",
            "ignore_column_names": True,
        },
        {
            "name": "target-architecture",
            "prompt": (
                "Using the attached 'pe' worker, return the single CPU-architecture value that the "
                "binary at path 'test/sql/data/hello.exe' targets."
            ),
            "reference_sql": "SELECT pe.main.machine('test/sql/data/hello.exe')",
            "ignore_column_names": True,
        },
        {
            "name": "whole-file-entropy",
            "prompt": (
                "Using the attached 'pe' worker, return the raw whole-file Shannon entropy value "
                "(bits per byte, do not round) of the file at path 'test/sql/data/hello.exe'."
            ),
            "reference_sql": "SELECT pe.main.overall_entropy('test/sql/data/hello.exe')",
            "ignore_column_names": True,
        },
        {
            "name": "highest-entropy-section",
            "prompt": (
                "Using the attached 'pe' worker, find the single section of "
                "'test/sql/data/hello.exe' with the highest per-section entropy. Return exactly "
                "two columns named `name` and `entropy` for that one section."
            ),
            "reference_sql": (
                "SELECT name, entropy FROM pe.main.sections('test/sql/data/hello.exe') ORDER BY entropy DESC LIMIT 1"
            ),
        },
        {
            "name": "count-imports",
            "prompt": (
                "Using the attached 'pe' worker, return the single count of imported symbols in "
                "the binary at path 'test/sql/data/hello.exe'."
            ),
            "reference_sql": "SELECT count(*) AS n FROM pe.main.imports('test/sql/data/hello.exe')",
            "ignore_column_names": True,
        },
        {
            "name": "count-long-strings",
            "prompt": (
                "Using the attached 'pe' worker, return the single count of printable strings of "
                "length 8 or more in the file at path 'test/sql/data/hello.exe'."
            ),
            "reference_sql": ("SELECT count(*) AS n FROM pe.main.strings('test/sql/data/hello.exe', min_len := 8)"),
            "ignore_column_names": True,
        },
    ]
)

_PE_CATALOG = Catalog(
    name="pe",
    default_schema="main",
    comment="Defensive malware-triage worker: static, read-only analysis of PE/ELF/Mach-O executables as SQL functions (the binary is never executed)",  # noqa: E501
    source_url="https://github.com/Query-farm/vgi-pe",
    tags={
        "vgi.title": "Executable Binary Triage (PE / ELF / Mach-O)",
        "vgi.keywords": keywords_array(_CATALOG_KEYWORDS),
        "vgi.doc_llm": _CATALOG_DESCRIPTION_LLM,
        "vgi.doc_md": _CATALOG_DESCRIPTION_MD,
        "vgi.author": "Query.Farm",
        "vgi.copyright": "Copyright 2026 Query Farm LLC - https://query.farm",
        "vgi.license": "MIT",
        "vgi.support_contact": "https://github.com/Query-farm/vgi-pe/issues",
        "vgi.support_policy_url": "https://github.com/Query-farm/vgi-pe/blob/main/README.md",
        # VGI152/VGI407: the fixed agent-suitability suite (catalog-only tag).
        "vgi.agent_test_tasks": _AGENT_TEST_TASKS,
    },
    schemas=[
        Schema(
            name="main",
            comment="Binary-analysis functions: format/architecture, entry point, signing, entropy, imphash, sections, imports, exports, and strings over PE/ELF/Mach-O input",  # noqa: E501
            tags={
                "vgi.title": "Binary Triage Functions",
                "vgi.keywords": keywords_array(_SCHEMA_KEYWORDS),
                "vgi.doc_llm": _SCHEMA_DESCRIPTION_LLM,
                "vgi.doc_md": _SCHEMA_DESCRIPTION_MD,
                # VGI139: vgi.source_url lives on the catalog only, not repeated
                # per-object (schema/function). The catalog carries source_url.
                "vgi.example_queries": _SCHEMA_EXAMPLE_QUERIES,
                # VGI413/VGI408-412: the schema's ordered category registry; each
                # function names one slug via its vgi.category tag.
                "vgi.categories": _SCHEMA_CATEGORIES,
                # VGI123 classifying tags use BARE keys (NOT vgi.-namespaced).
                "domain": "security",
                "topic": "malware-triage",
            },
            functions=list(_FUNCTIONS),
        ),
    ],
)


class PeWorker(Worker):
    """Worker process hosting the ``pe`` catalog."""

    catalog = _PE_CATALOG


def main() -> None:
    """Run the pe worker process (stdio or, via flags, HTTP)."""
    PeWorker.main()


if __name__ == "__main__":
    main()
