# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.16.0",
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
from vgi.catalog import Catalog, Schema, Table

from vgi_pe.meta import keywords_array
from vgi_pe.scalars import SCALAR_FUNCTIONS
from vgi_pe.tables import TABLE_FUNCTIONS, AnalysesFunction

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
    "printable strings. Each function takes a binary as either a `VARCHAR` filesystem path or a `BLOB` "
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
    "table, and each pairs its narrative with runnable, tested example queries. "
    "Static analysis only — the binary is never executed."
)
_SCHEMA_DESCRIPTION_LLM = (
    "Static binary-analysis functions over PE/ELF/Mach-O images: format and architecture detection, "
    "entry point, code-signing status, PE build timestamp and imphash, whole-file and per-section "
    "entropy, and listings of sections, imports, exports, and printable strings. Input is a `VARCHAR` "
    "path or a `BLOB`; the binary is never executed."
)
_SCHEMA_DESCRIPTION_MD = (
    "## main\n\n"
    "Static analysis of PE/ELF/Mach-O binaries over Apache Arrow.\n\n"
    "This schema groups the worker's functions into navigation categories covering format and "
    "architecture detection, structural layout, entropy and packing signals, signing and build "
    "provenance, imported/exported symbols, and printable-string extraction. Per-binary scalar "
    "facts fold into projections and filters; set-returning functions expand a single sample into "
    "rows for hunting and joining.\n\n"
    "Every function accepts a `VARCHAR` path or a `BLOB` and degrades to NULL / no rows on hostile "
    "input. Static (read-only) — the binary is never executed."
)
# Representative, catalog-qualified example queries for the schema (VGI506/VGI515).
# A described-example JSON list (each carries a human-readable description; the
# native duckdb_functions().examples carrier drops descriptions, so the strict
# linter reads them from this tag). They read committed fixtures by relative path
# so they run against an attached worker.
_SCHEMA_EXAMPLE_QUERIES = json.dumps(
    [
        {
            "description": "Browse the worker's analysis catalog before owning a binary.",
            "sql": "SELECT name, kind, formats FROM pe.main.analyses ORDER BY kind, name",
        },
        {
            "description": "Detect the executable container format of a sample.",
            "sql": "SELECT pe.main.binary_format('test/sql/data/hello.exe')",
        },
        {
            "description": "Read the target CPU architecture of a sample.",
            "sql": "SELECT pe.main.machine('test/sql/data/hello.exe')",
        },
        {
            "description": "Compute whole-file entropy as a packing/encryption signal.",
            "sql": "SELECT pe.main.overall_entropy('test/sql/data/hello.exe')",
        },
        {
            "description": "Fingerprint a PE by its import hash for clustering.",
            "sql": "SELECT pe.main.imphash('test/sql/data/hello.exe')",
        },
        {
            "description": "Rank a sample's sections by per-section entropy.",
            "sql": "SELECT name, entropy FROM pe.main.sections('test/sql/data/hello.exe') ORDER BY entropy DESC",
        },
        {
            "description": "List the first imported symbols of a sample.",
            "sql": "SELECT library, function FROM pe.main.imports('test/sql/data/hello.exe') LIMIT 10",
        },
        {
            "description": "Extract long printable strings for IOC hunting.",
            "sql": "SELECT seq, value FROM pe.main.strings('test/sql/data/hello.exe', min_len := 8) LIMIT 10",
        },
    ]
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
        {
            "name": "discovery",
            "title": "Discovery & Catalog",
            "description": "Browse the worker's analysis catalog without supplying a binary.",
        },
    ]
)

# VGI152/VGI407/VGI520/VGI920: a fixed, version-controlled agent-suitability
# suite. The --ai agent-simulation pass runs an LLM analyst through each `prompt`
# (the ONLY field it sees) against the attached worker and grades its answer
# against the grader-only `reference_sql`. Every function and the `analyses`
# discovery table is exercised by at least one task (VGI520), and each targets a
# committed fixture by relative path (worker cwd = repo root) so it runs
# deterministically.
#
# Grading discipline (VGI920): raw floats and raw row-counts are brittle to grade
# — the analyst rounds, renames, or the value shifts with a library version — so
# every quantitative task is framed as a yes/no THRESHOLD predicate returning a
# stable BOOLEAN. Only genuinely fixed strings (format, architecture, imphash of
# the byte-deterministic PE) are compared exactly. All tasks return a single
# value whose column label depends on how the analyst spells the call, so they
# grade by VALUE only (`ignore_column_names`). Every reference value below was
# verified by actually running the query against the committed fixtures.
_AGENT_TEST_TASKS = json.dumps(
    [
        # --- format & architecture (stable strings) ---
        {
            "name": "detect-format",
            "prompt": (
                "Using the attached 'pe' worker, return the executable container-format "
                "value (PE, ELF, or Mach-O) of the file at path 'test/sql/data/hello.exe'."
            ),
            "reference_sql": "SELECT pe.main.binary_format('test/sql/data/hello.exe')",
            "ignore_column_names": True,
        },
        {
            "name": "target-architecture",
            "prompt": (
                "Using the attached 'pe' worker, return the CPU-architecture value that the "
                "binary at path 'test/sql/data/hello.exe' targets."
            ),
            "reference_sql": "SELECT pe.main.machine('test/sql/data/hello.exe')",
            "ignore_column_names": True,
        },
        # --- structure (threshold predicates) ---
        {
            "name": "entry-point-high",
            "prompt": (
                "Using the attached 'pe' worker, is the entry-point virtual address of the file "
                "at path 'test/sql/data/hello.exe' greater than 1000000000? Return a boolean."
            ),
            "reference_sql": "SELECT pe.main.entry_point('test/sql/data/hello.exe') > 1000000000",
            "ignore_column_names": True,
        },
        {
            "name": "many-sections",
            "prompt": (
                "Using the attached 'pe' worker, does the file at path 'test/sql/data/hello.exe' "
                "have more than 10 sections? Return a boolean."
            ),
            "reference_sql": "SELECT pe.main.section_count('test/sql/data/hello.exe') > 10",
            "ignore_column_names": True,
        },
        # --- entropy (threshold predicate) ---
        {
            "name": "entropy-in-range",
            "prompt": (
                "Using the attached 'pe' worker, is the whole-file Shannon entropy (bits per byte) "
                "of the file at path 'test/sql/data/hello.exe' between 4 and 7 inclusive? Return a "
                "boolean."
            ),
            "reference_sql": "SELECT pe.main.overall_entropy('test/sql/data/hello.exe') BETWEEN 4 AND 7",
            "ignore_column_names": True,
        },
        # --- signing / provenance ---
        {
            "name": "macho-is-signed",
            "prompt": (
                "Using the attached 'pe' worker, is the file at path 'test/sql/data/hello_macho' "
                "code-signed (does it carry an embedded code signature)? Return the boolean."
            ),
            "reference_sql": "SELECT pe.main.is_signed('test/sql/data/hello_macho')",
            "ignore_column_names": True,
        },
        {
            "name": "build-year",
            "prompt": (
                "Using the attached 'pe' worker, was the PE at path 'test/sql/data/hello.exe' "
                "built in the year 2023 according to its build timestamp? Return a boolean."
            ),
            "reference_sql": "SELECT year(pe.main.compile_timestamp('test/sql/data/hello.exe')) = 2023",
            "ignore_column_names": True,
        },
        {
            "name": "import-hash",
            "prompt": (
                "Using the attached 'pe' worker, return the PE import hash (imphash) of the file "
                "at path 'test/sql/data/hello.exe'."
            ),
            "reference_sql": "SELECT pe.main.imphash('test/sql/data/hello.exe')",
            "ignore_column_names": True,
        },
        # --- set-returning tables (threshold predicates; literal args only) ---
        {
            "name": "top-section-entropy",
            "prompt": (
                "Using the attached 'pe' worker, across the sections of 'test/sql/data/hello.exe', "
                "is the highest per-section entropy greater than 5.0? Return a boolean."
            ),
            "reference_sql": "SELECT max(entropy) > 5.0 FROM pe.main.sections('test/sql/data/hello.exe')",
            "ignore_column_names": True,
        },
        {
            "name": "has-many-imports",
            "prompt": (
                "Using the attached 'pe' worker, does the binary at path 'test/sql/data/hello.exe' "
                "import more than 10 symbols? Return a boolean."
            ),
            "reference_sql": "SELECT count(*) > 10 FROM pe.main.imports('test/sql/data/hello.exe')",
            "ignore_column_names": True,
        },
        {
            "name": "macho-has-exports",
            "prompt": (
                "Using the attached 'pe' worker, does the file at path 'test/sql/data/hello_macho' "
                "export at least one symbol? Return a boolean."
            ),
            "reference_sql": "SELECT count(*) >= 1 FROM pe.main.exports('test/sql/data/hello_macho')",
            "ignore_column_names": True,
        },
        {
            "name": "many-long-strings",
            "prompt": (
                "Using the attached 'pe' worker, does the file at path 'test/sql/data/hello.exe' "
                "contain more than 100 printable strings of length 8 or more? Return a boolean."
            ),
            "reference_sql": ("SELECT count(*) > 100 FROM pe.main.strings('test/sql/data/hello.exe', min_len := 8)"),
            "ignore_column_names": True,
        },
        # --- discovery table ---
        {
            "name": "catalog-scalar-count",
            "prompt": (
                "Using the attached 'pe' worker's analysis catalog, are more than 5 analyses "
                "listed as scalar functions? Return a boolean."
            ),
            "reference_sql": "SELECT count(*) > 5 FROM pe.main.analyses WHERE kind = 'scalar'",
            "ignore_column_names": True,
        },
    ]
)

# VGI146: a browsable, argument-free discovery table so an agent can see what the
# worker offers before it owns a binary. Backed by the parameterless
# `AnalysesFunction` (a curated in-memory registry — no file, no network), so
# `SELECT ... FROM pe.main.analyses` scans credential-free. The object-level docs,
# example queries, and result schema live on the function's Meta.tags; the table
# adds its natural primary key and column comments.
_DISCOVERY_TABLES: list[Table] = [
    Table(
        name="analyses",
        function=AnalysesFunction,
        comment="Browsable registry of every analysis (scalar/table) this worker exposes (discovery table).",
        primary_key=(("name",),),
        not_null=("name", "kind", "category", "formats", "result"),
        column_comments={
            "name": "Function name to call (e.g. `imphash`, `sections`).",
            "kind": "`scalar` (one value per binary) or `table` (many rows per binary).",
            "category": "Navigation category slug (format/structure/entropy/signing/symbols/strings).",
            "formats": "Which container formats (PE / ELF / Mach-O) the analysis applies to.",
            "result": "What the analysis returns.",
        },
        tags=AnalysesFunction.Meta.tags,
    ),
]

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
            tables=list(_DISCOVERY_TABLES),
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
