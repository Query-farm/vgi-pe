# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.8.5",
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
    "bounds on input size, string counts, and row counts keep even adversarial \"bomb\" inputs from "
    "exhausting memory.\n\n"
    "Scalar functions answer one fact per binary: `binary_format` (PE/ELF/Mach-O detection), "
    "`machine` (abstract architecture), `entry_point`, `is_signed` (code-signing status), "
    "`compile_timestamp` (PE build time), `imphash` (the classic import hash for clustering related "
    "samples), `section_count`, and `overall_entropy` (whole-file Shannon entropy, a packing and "
    "encryption signal). Table functions return sets of rows: `sections` (name, size, and "
    "per-section entropy), `imports`, `exports`, and `strings` (printable strings with an optional "
    "`min_len :=` filter). Every function accepts the binary as either a `VARCHAR` filesystem path "
    "or a `BLOB` of raw bytes, so you can analyze files on disk or bytes already living in a table. "
    "For example: `SELECT pe.imphash('sample.exe')`, "
    "`SELECT name, entropy FROM pe.sections('sample.exe') ORDER BY entropy DESC`, or "
    "`SELECT * FROM pe.strings('sample.exe', min_len := 8)`. Static analysis only — the binary is "
    "never executed."
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
    "Scalars: `binary_format`, `machine`, `entry_point`, `is_signed`, `compile_timestamp`, "
    "`imphash`, `section_count`, `overall_entropy`. Table functions: `sections`, `imports`, "
    "`exports`, `strings`.\n\n"
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
                # VGI123 classifying tags use BARE keys (NOT vgi.-namespaced).
                "domain": "security",
                "category": "binary-analysis",
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
