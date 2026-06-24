# /// script
# requires-python = ">=3.13"
# dependencies = [
#     "vgi-python[http]>=0.8.3",
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

_PE_CATALOG = Catalog(
    name="pe",
    default_schema="main",
    schemas=[
        Schema(
            name="main",
            comment="Static analysis of PE/ELF/Mach-O binaries: format, sections, entropy, imports, signing, strings",  # noqa: E501
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
