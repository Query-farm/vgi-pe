# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.8.4",
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
    "# pe\n\n"
    "Static analysis of executable binaries (PE / ELF / Mach-O) over Apache Arrow — a defensive "
    "**malware-triage** worker backed by [`lief`](https://lief.re) (Apache-2.0).\n\n"
    "Scalars: `binary_format`, `machine`, `entry_point`, `is_signed`, `compile_timestamp`, "
    "`imphash`, `section_count`, `overall_entropy`. "
    "Table functions: `sections`, `imports`, `exports`, `strings`.\n\n"
    "Every function accepts either a VARCHAR path or a BLOB of raw bytes. Static analysis only — the "
    "binary is never executed."
)
_SCHEMA_DESCRIPTION_LLM = (
    "Static binary-analysis functions over PE/ELF/Mach-O images: format and architecture detection, "
    "entry point, code-signing status, PE build timestamp and imphash, whole-file and per-section "
    "entropy, and listings of sections, imports, exports, and printable strings. Input is a VARCHAR "
    "path or a BLOB; the binary is never executed."
)
_SCHEMA_DESCRIPTION_MD = (
    "Static analysis of PE/ELF/Mach-O binaries over Apache Arrow: format, sections, entropy, "
    "imports/exports, signing, and strings. Static (read-only) — the binary is never executed."
)

_PE_CATALOG = Catalog(
    name="pe",
    default_schema="main",
    comment="Defensive malware-triage worker: static, read-only analysis of PE/ELF/Mach-O executables as SQL functions (the binary is never executed)",  # noqa: E501
    source_url="https://github.com/Query-farm/vgi-pe",
    tags={
        "vgi.description_llm": _CATALOG_DESCRIPTION_LLM,
        "vgi.description_md": _CATALOG_DESCRIPTION_MD,
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
                "vgi.description_llm": _SCHEMA_DESCRIPTION_LLM,
                "vgi.description_md": _SCHEMA_DESCRIPTION_MD,
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
