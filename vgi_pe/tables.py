"""Set-returning binary-analysis table functions for DuckDB.

These expand to **many rows** per binary, so they are exposed as **table
functions** -- the form that accepts DuckDB ``name := value`` arguments (here,
``strings``' optional ``min_len``). The per-row, single-value functions are
*scalars* and live in :mod:`vgi_pe.scalars`.

    SELECT * FROM pe.sections('sample.exe') ORDER BY name;        -- per-section + entropy
    SELECT * FROM pe.imports('sample.exe');                       -- imported symbols
    SELECT * FROM pe.exports('sample.exe');                       -- exported symbols
    SELECT * FROM pe.strings('sample.exe', min_len := 8);         -- printable strings

Polymorphic ``binary`` input
----------------------------
The first positional argument is **either** a ``VARCHAR`` filesystem path the
worker opens **or** a ``BLOB`` of raw binary bytes. DuckDB dispatches on the
argument type, so each table function is registered twice -- a ``*PathFunction``
(``Arg`` typed ``pa.string()``) and a ``*BytesFunction`` (typed ``pa.binary()``)
-- sharing one ``Meta.name``.

Hostile input: an unparseable / truncated / non-binary input yields **no rows**
(never a worker crash, never an error, never a hang) -- hostile binaries are the
expected case for a triage tool. A NULL ``binary`` argument also yields no rows.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Annotated, ClassVar

import pyarrow as pa
from vgi.arguments import Arg
from vgi.metadata import FunctionExample
from vgi.table_function import (
    BindParams,
    ProcessParams,
    TableCardinality,
    TableFunctionGenerator,
    bind_fixed_schema,
    init_single_worker,
)
from vgi_rpc.rpc import OutputCollector

from . import core, meta
from .core import BinarySource
from .schema_utils import field

# Real, committed fixtures the worker can open by relative path (the worker's cwd
# is the repo root). Chosen per function so every example actually returns rows
# under the strict linter (it runs every example by default). hello.exe has
# sections/imports/strings; only the Mach-O fixture has exports.
_PE_FIXTURE = "test/sql/data/hello.exe"
_MACHO_FIXTURE = "test/sql/data/hello_macho"


# DuckDB cannot expose a table function's output schema for discovery, so each
# table function carries a ``vgi.result_columns_md`` tag: a Markdown table of the
# rows it returns. These mirror the ``pa.schema([...])`` definitions below.
_SECTIONS_COLUMNS_MD = (
    "| column | type | description |\n"
    "|---|---|---|\n"
    "| `name` | VARCHAR | Section name (e.g. `.text`, `.data`, `__TEXT`). |\n"
    "| `virtual_size` | BIGINT | Size in bytes when mapped into memory. |\n"
    "| `raw_size` | BIGINT | Size in bytes on disk. |\n"
    "| `entropy` | DOUBLE | Per-section Shannon entropy (0-8); high (>~7) suggests packing/encryption. |\n"
    "| `characteristics` | VARCHAR | Comma-joined section flags (PE only; empty for ELF/Mach-O). |"
)
_IMPORTS_COLUMNS_MD = (
    "| column | type | description |\n"
    "|---|---|---|\n"
    "| `library` | VARCHAR | Imported library/DLL name (empty for ELF/Mach-O). |\n"
    "| `function` | VARCHAR | Imported symbol name, or `ordinal#N` when imported by ordinal. |"
)
_EXPORTS_COLUMNS_MD = (
    "| column | type | description |\n"
    "|---|---|---|\n"
    "| `name` | VARCHAR | Exported symbol name. |\n"
    "| `address` | UBIGINT | Symbol address/value (0 when unavailable). |"
)
_STRINGS_COLUMNS_MD = (
    "| column | type | description |\n"
    "|---|---|---|\n"
    "| `seq` | BIGINT | 1-based ordinal of the string in file order. |\n"
    "| `value` | VARCHAR | Printable ASCII/UTF-16 string (length >= `min_len`). |"
)

# Optional minimum string length for ``strings``. Explicit ``arrow_type`` so a
# supplied INTEGER binds correctly (without it the default makes the SDK infer a
# NULL Arrow type).
_MIN_LEN = Arg[int | None](
    "min_len",
    default=core.DEFAULT_MIN_STRING_LEN,
    arrow_type=pa.int32(),
    doc="Minimum string length to report (default 5).",
)


# ---------------------------------------------------------------------------
# Per-object discovery/description tags (VGI112/113/124/126/128) plus the
# Markdown column docs (vgi.result_columns_md) and, for `sections`, a set of
# guaranteed-runnable executable examples (VGI509).
# ---------------------------------------------------------------------------

# Catalog-qualified, self-contained, guaranteed-runnable examples (VGI509). Each
# `sql` reads a committed fixture by relative path (the worker's cwd is the repo
# root) so it executes cleanly against an attached `pe` worker. `expected_result`
# is intentionally omitted — the linter only needs each query to run and return
# rows, and pinning exact bytes/offsets would be brittle across build hosts.
_SECTIONS_EXECUTABLE_EXAMPLES = json.dumps(
    [
        {
            "description": "List the sections of a PE with their per-section entropy.",
            "sql": f"SELECT name, entropy FROM pe.main.sections('{_PE_FIXTURE}') ORDER BY entropy DESC LIMIT 5",
        },
        {
            "description": "Flag high-entropy sections (a packing/encryption signal).",
            "sql": f"SELECT name, entropy FROM pe.main.sections('{_PE_FIXTURE}') WHERE entropy > 6",
        },
        {
            "description": "Count the imported symbols of a PE.",
            "sql": f"SELECT count(*) AS imports FROM pe.main.imports('{_PE_FIXTURE}')",
        },
        {
            "description": "List exported symbols of a Mach-O binary.",
            "sql": f"SELECT name, address FROM pe.main.exports('{_MACHO_FIXTURE}') ORDER BY name",
        },
        {
            "description": "Extract long printable strings from a binary.",
            "sql": f"SELECT seq, value FROM pe.main.strings('{_PE_FIXTURE}', min_len := 8) ORDER BY seq LIMIT 5",
        },
    ]
)

_SECTIONS_TAGS = {
    **meta.object_tags(
        title="Per-Section Layout & Entropy",
        doc_llm=(
            "Enumerate the **sections** of a binary, one row per section, with size and "
            "**per-section Shannon entropy** — the workhorse table for layout-level triage. "
            "Columns: `name`, `virtual_size`, `raw_size`, `entropy` (0–8), `characteristics` "
            "(PE flags; empty for ELF/Mach-O). Accepts a VARCHAR path or a BLOB; unparseable or "
            "non-binary input yields **no rows** (never an error).\n\n"
            "Use it to find *where* in a file suspicious data lives: a high-entropy (`> ~7`) "
            "`.text`/code section, an executable+writable section, or a section whose raw size "
            "dwarfs its virtual size all point to packing, embedded payloads, or self-modifying "
            "code. Cross-reference with `pe.entry_point(...)` to confirm the entry point lands in "
            "a sane section. Static read-only; the binary is never executed."
        ),
        doc_md=(
            "## sections\n\n"
            "One row per section of the binary, with sizes and per-section entropy.\n\n"
            "### Returns\n\n" + _SECTIONS_COLUMNS_MD + "\n\n### Notes\n\n"
            "`characteristics` is populated for PE only. High `entropy` (`> ~7`) localizes "
            "packing/encryption to a specific section; a large `raw_size`-vs-`virtual_size` gap "
            "or an entry point outside an executable section are further packing signals. "
            "Unparseable input returns no rows."
        ),
        keywords="sections, segments, layout, entropy, packing, .text, .data, characteristics, flags, structure",
        relative_path="vgi_pe/tables.py",
    ),
    "vgi.result_columns_md": _SECTIONS_COLUMNS_MD,
    "vgi.executable_examples": _SECTIONS_EXECUTABLE_EXAMPLES,
}

_IMPORTS_TAGS = {
    **meta.object_tags(
        title="Imported Symbols Table",
        doc_llm=(
            "Enumerate the **imported symbols** of a binary, one row per import, as "
            "`(library, function)`. For PE the `library` is the DLL (e.g. `KERNEL32.dll`) and "
            "`function` the imported API, or `ordinal#N` when imported by ordinal; for ELF/Mach-O "
            "`library` is empty and `function` is the symbol. Accepts a VARCHAR path or a BLOB; "
            "unparseable input yields no rows.\n\n"
            "The import table is one of the richest behavioral fingerprints of a binary: which "
            "APIs it pulls in (networking, crypto, process injection, registry, file I/O) sketches "
            "what it *can* do without running it, and the normalized import set underlies "
            "`pe.imphash(...)` clustering. Watch for tiny import tables (a packer that resolves "
            "APIs at runtime) and for suspicious API combinations. Static read-only."
        ),
        doc_md=(
            "## imports\n\n"
            "One row per imported symbol, as `(library, function)`.\n\n"
            "### Returns\n\n" + _IMPORTS_COLUMNS_MD + "\n\n### Notes\n\n"
            "PE rows carry the DLL in `library` (functions imported by ordinal appear as "
            "`ordinal#N`); ELF/Mach-O leave `library` empty. A suspiciously small import table "
            "often means runtime API resolution (a packing/evasion signal). Feeds "
            "`pe.imphash(...)`."
        ),
        keywords="imports, imported symbols, IAT, DLL, API, dependencies, dynamic symbols, capabilities, behavior",
        relative_path="vgi_pe/tables.py",
    ),
    "vgi.result_columns_md": _IMPORTS_COLUMNS_MD,
}

_EXPORTS_TAGS = {
    **meta.object_tags(
        title="Exported Symbols Table",
        doc_llm=(
            "Enumerate the **exported symbols** of a binary, one row per export, as "
            "`(name, address)` where `address` is the symbol's address/value (0 when "
            "unavailable). Exports are typical of shared libraries (DLLs, `.so`, `.dylib`) and "
            "plugin-style modules. Accepts a VARCHAR path or a BLOB; unparseable input or a binary "
            "with no exports yields no rows.\n\n"
            "Use it to understand a module's public API surface, to spot a DLL whose exports "
            "mimic a legitimate system library (a side-loading / proxying tactic), or to match "
            "named exports against known-bad indicators. Static read-only; the binary is never "
            "executed."
        ),
        doc_md=(
            "## exports\n\n"
            "One row per exported symbol, as `(name, address)`.\n\n"
            "### Returns\n\n" + _EXPORTS_COLUMNS_MD + "\n\n### Notes\n\n"
            "Most relevant for shared libraries / plugins; executables often export nothing (no "
            "rows). `address` is `0` when the value is unavailable. Exports that impersonate a "
            "known system library are a DLL side-loading signal."
        ),
        keywords="exports, exported symbols, EAT, DLL, shared library, dylib, so, public API, side-loading",
        relative_path="vgi_pe/tables.py",
    ),
    "vgi.result_columns_md": _EXPORTS_COLUMNS_MD,
}

_STRINGS_TAGS = {
    **meta.object_tags(
        title="Printable Strings Extractor",
        doc_llm=(
            "Extract **printable strings** from a binary, one row per string, as `(seq, value)` "
            "in file order. It recovers both ASCII and UTF-16LE runs at least `min_len` "
            "characters long (`min_len` defaults to 5 and is passed as the named argument "
            "`min_len :=`). Accepts a VARCHAR path or a BLOB; output is capped for safety against "
            "string-bomb input, and unparseable input yields no rows.\n\n"
            "Strings are the fastest way to surface human-readable indicators inside an opaque "
            "binary: URLs, IP addresses, file paths, registry keys, command lines, mutex names, "
            "embedded error messages, and crypto constants. Filter `value` with SQL `LIKE`/regex "
            "to hunt for IOCs across a corpus. Raise `min_len` to cut noise from packed samples. "
            "Static read-only; the binary is never executed."
        ),
        doc_md=(
            "## strings\n\n"
            "One row per printable string (ASCII + UTF-16LE) of length `>= min_len`.\n\n"
            "### Arguments\n\n"
            "- `binary` — a VARCHAR path or a BLOB.\n"
            "- `min_len` (named, default 5) — minimum string length to report.\n\n"
            "### Returns\n\n" + _STRINGS_COLUMNS_MD + "\n\n### Notes\n\n"
            "Output is bounded against string-bomb inputs. Use `WHERE value LIKE '%http%'` (and "
            "friends) to hunt URLs, paths, registry keys, and other IOCs; raise `min_len` to "
            "reduce noise on packed samples."
        ),
        keywords="strings, printable, ascii, utf-16, IOC, indicators, URLs, paths, extract, grep, hunting",
        relative_path="vgi_pe/tables.py",
    ),
    "vgi.result_columns_md": _STRINGS_COLUMNS_MD,
}


# ---------------------------------------------------------------------------
# sections(binary) -> (name, virtual_size, raw_size, entropy, characteristics)
# ---------------------------------------------------------------------------

_SECTIONS_SCHEMA = pa.schema(
    [
        field("name", pa.string(), "Section name.", nullable=False),
        field("virtual_size", pa.int64(), "Virtual size in bytes (in memory).", nullable=False),
        field("raw_size", pa.int64(), "Raw size in bytes (on disk).", nullable=False),
        field("entropy", pa.float64(), "Per-section Shannon entropy (0-8); high => packed.", nullable=False),
        field(
            "characteristics",
            pa.string(),
            "Comma-joined section flags (PE; empty for ELF/Mach-O).",
            nullable=False,
        ),
    ]
)


@dataclass(kw_only=True)
class _SectionsPathArgs:
    binary: Annotated[str | None, Arg(0, arrow_type=pa.string(), doc="Filesystem path to a binary.")]


@dataclass(kw_only=True)
class _SectionsBytesArgs:
    binary: Annotated[bytes | None, Arg(0, arrow_type=pa.binary(), doc="Raw binary bytes.")]


def _emit_sections(src: BinarySource, out: OutputCollector, schema: pa.Schema) -> None:
    rows = core.sections(src)
    out.emit(
        pa.RecordBatch.from_pydict(
            {
                "name": [r[0] for r in rows],
                "virtual_size": [r[1] for r in rows],
                "raw_size": [r[2] for r in rows],
                "entropy": [r[3] for r in rows],
                "characteristics": [r[4] for r in rows],
            },
            schema=schema,
        )
    )
    out.finish()


@init_single_worker
@bind_fixed_schema
class SectionsPathFunction(TableFunctionGenerator[_SectionsPathArgs]):
    """``sections(path)`` -- per-section rows for a binary at a path."""

    FIXED_SCHEMA: ClassVar[pa.Schema] = _SECTIONS_SCHEMA

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "sections"
        description = "Per-section (name, virtual_size, raw_size, entropy, flags) of a binary (VARCHAR path)"
        categories = ["pe", "structure"]
        tags = _SECTIONS_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT * FROM pe.sections('{_PE_FIXTURE}') ORDER BY name",
                description="Sections of a binary file with entropy",
            ),
        ]

    @classmethod
    def cardinality(cls, params: BindParams[_SectionsPathArgs]) -> TableCardinality:
        """Estimate the number of output rows for the optimizer."""
        return TableCardinality(estimate=10, max=None)

    @classmethod
    def process(cls, params: ProcessParams[_SectionsPathArgs], state: None, out: OutputCollector) -> None:
        """Emit the result rows for one input binary."""
        src = BinarySource.from_path(params.args.binary)
        if src is None:
            out.finish()
            return
        _emit_sections(src, out, params.output_schema)


@init_single_worker
@bind_fixed_schema
class SectionsBytesFunction(TableFunctionGenerator[_SectionsBytesArgs]):
    """``sections(blob)`` -- per-section rows for binary bytes."""

    FIXED_SCHEMA: ClassVar[pa.Schema] = _SECTIONS_SCHEMA

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "sections"
        description = "Per-section (name, virtual_size, raw_size, entropy, flags) of a binary (BLOB bytes)"
        categories = ["pe", "structure"]
        tags = _SECTIONS_TAGS
        # No `examples` on the BLOB overload: a VGI table function only accepts
        # *literal* parameters (not a subquery or a lateral column reference), so
        # a runnable BLOB-input example would have to inline the whole binary as a
        # hex literal. The VARCHAR-path overload (same `pe.main.sections` object)
        # already carries runnable, row-returning examples, and the BLOB path is
        # exercised end-to-end by the test suite.

    @classmethod
    def cardinality(cls, params: BindParams[_SectionsBytesArgs]) -> TableCardinality:
        """Estimate the number of output rows for the optimizer."""
        return TableCardinality(estimate=10, max=None)

    @classmethod
    def process(cls, params: ProcessParams[_SectionsBytesArgs], state: None, out: OutputCollector) -> None:
        """Emit the result rows for one input binary."""
        src = BinarySource.from_bytes(params.args.binary)
        if src is None:
            out.finish()
            return
        _emit_sections(src, out, params.output_schema)


# ---------------------------------------------------------------------------
# imports(binary) -> (library, function)
# ---------------------------------------------------------------------------

_IMPORTS_SCHEMA = pa.schema(
    [
        field("library", pa.string(), "Imported library/DLL (empty for ELF/Mach-O).", nullable=False),
        field("function", pa.string(), "Imported symbol name (or ordinal#N).", nullable=False),
    ]
)


@dataclass(kw_only=True)
class _ImportsPathArgs:
    binary: Annotated[str | None, Arg(0, arrow_type=pa.string(), doc="Filesystem path to a binary.")]


@dataclass(kw_only=True)
class _ImportsBytesArgs:
    binary: Annotated[bytes | None, Arg(0, arrow_type=pa.binary(), doc="Raw binary bytes.")]


def _emit_imports(src: BinarySource, out: OutputCollector, schema: pa.Schema) -> None:
    rows = core.imports(src)
    out.emit(
        pa.RecordBatch.from_pydict(
            {
                "library": [r[0] for r in rows],
                "function": [r[1] for r in rows],
            },
            schema=schema,
        )
    )
    out.finish()


@init_single_worker
@bind_fixed_schema
class ImportsPathFunction(TableFunctionGenerator[_ImportsPathArgs]):
    """``imports(path)`` -- imported symbols of a binary at a path."""

    FIXED_SCHEMA: ClassVar[pa.Schema] = _IMPORTS_SCHEMA

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "imports"
        description = "Imported symbols (library, function) of a binary (VARCHAR path)"
        categories = ["pe", "imports"]
        tags = _IMPORTS_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT * FROM pe.imports('{_PE_FIXTURE}') ORDER BY library, function",
                description="Imported symbols of a binary file",
            ),
        ]

    @classmethod
    def cardinality(cls, params: BindParams[_ImportsPathArgs]) -> TableCardinality:
        """Estimate the number of output rows for the optimizer."""
        return TableCardinality(estimate=100, max=None)

    @classmethod
    def process(cls, params: ProcessParams[_ImportsPathArgs], state: None, out: OutputCollector) -> None:
        """Emit the result rows for one input binary."""
        src = BinarySource.from_path(params.args.binary)
        if src is None:
            out.finish()
            return
        _emit_imports(src, out, params.output_schema)


@init_single_worker
@bind_fixed_schema
class ImportsBytesFunction(TableFunctionGenerator[_ImportsBytesArgs]):
    """``imports(blob)`` -- imported symbols of binary bytes."""

    FIXED_SCHEMA: ClassVar[pa.Schema] = _IMPORTS_SCHEMA

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "imports"
        description = "Imported symbols (library, function) of a binary (BLOB bytes)"
        categories = ["pe", "imports"]
        tags = _IMPORTS_TAGS
        # See SectionsBytesFunction: the VARCHAR-path overload of this same
        # `pe.main.imports` object carries the runnable examples; a table function
        # only accepts literal args so a BLOB example can't reference a file.

    @classmethod
    def cardinality(cls, params: BindParams[_ImportsBytesArgs]) -> TableCardinality:
        """Estimate the number of output rows for the optimizer."""
        return TableCardinality(estimate=100, max=None)

    @classmethod
    def process(cls, params: ProcessParams[_ImportsBytesArgs], state: None, out: OutputCollector) -> None:
        """Emit the result rows for one input binary."""
        src = BinarySource.from_bytes(params.args.binary)
        if src is None:
            out.finish()
            return
        _emit_imports(src, out, params.output_schema)


# ---------------------------------------------------------------------------
# exports(binary) -> (name, address)
# ---------------------------------------------------------------------------

_EXPORTS_SCHEMA = pa.schema(
    [
        field("name", pa.string(), "Exported symbol name.", nullable=False),
        field("address", pa.uint64(), "Symbol address/value (0 if unavailable).", nullable=False),
    ]
)


@dataclass(kw_only=True)
class _ExportsPathArgs:
    binary: Annotated[str | None, Arg(0, arrow_type=pa.string(), doc="Filesystem path to a binary.")]


@dataclass(kw_only=True)
class _ExportsBytesArgs:
    binary: Annotated[bytes | None, Arg(0, arrow_type=pa.binary(), doc="Raw binary bytes.")]


def _emit_exports(src: BinarySource, out: OutputCollector, schema: pa.Schema) -> None:
    rows = core.exports(src)
    out.emit(
        pa.RecordBatch.from_pydict(
            {
                "name": [r[0] for r in rows],
                "address": [r[1] for r in rows],
            },
            schema=schema,
        )
    )
    out.finish()


@init_single_worker
@bind_fixed_schema
class ExportsPathFunction(TableFunctionGenerator[_ExportsPathArgs]):
    """``exports(path)`` -- exported symbols of a binary at a path."""

    FIXED_SCHEMA: ClassVar[pa.Schema] = _EXPORTS_SCHEMA

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "exports"
        description = "Exported symbols (name, address) of a binary (VARCHAR path)"
        categories = ["pe", "exports"]
        tags = _EXPORTS_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT * FROM pe.exports('{_MACHO_FIXTURE}') ORDER BY name",
                description="Exported symbols of a binary file",
            ),
        ]

    @classmethod
    def cardinality(cls, params: BindParams[_ExportsPathArgs]) -> TableCardinality:
        """Estimate the number of output rows for the optimizer."""
        return TableCardinality(estimate=100, max=None)

    @classmethod
    def process(cls, params: ProcessParams[_ExportsPathArgs], state: None, out: OutputCollector) -> None:
        """Emit the result rows for one input binary."""
        src = BinarySource.from_path(params.args.binary)
        if src is None:
            out.finish()
            return
        _emit_exports(src, out, params.output_schema)


@init_single_worker
@bind_fixed_schema
class ExportsBytesFunction(TableFunctionGenerator[_ExportsBytesArgs]):
    """``exports(blob)`` -- exported symbols of binary bytes."""

    FIXED_SCHEMA: ClassVar[pa.Schema] = _EXPORTS_SCHEMA

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "exports"
        description = "Exported symbols (name, address) of a binary (BLOB bytes)"
        categories = ["pe", "exports"]
        tags = _EXPORTS_TAGS
        # See SectionsBytesFunction: the VARCHAR-path overload of this same
        # `pe.main.exports` object carries the runnable examples; a table function
        # only accepts literal args so a BLOB example can't reference a file.

    @classmethod
    def cardinality(cls, params: BindParams[_ExportsBytesArgs]) -> TableCardinality:
        """Estimate the number of output rows for the optimizer."""
        return TableCardinality(estimate=100, max=None)

    @classmethod
    def process(cls, params: ProcessParams[_ExportsBytesArgs], state: None, out: OutputCollector) -> None:
        """Emit the result rows for one input binary."""
        src = BinarySource.from_bytes(params.args.binary)
        if src is None:
            out.finish()
            return
        _emit_exports(src, out, params.output_schema)


# ---------------------------------------------------------------------------
# strings(binary, min_len := 5) -> (seq, value)
# ---------------------------------------------------------------------------

_STRINGS_SCHEMA = pa.schema(
    [
        field("seq", pa.int64(), "1-based ordinal of the string in file order.", nullable=False),
        field("value", pa.string(), "Printable ASCII/UTF-16 string.", nullable=False),
    ]
)


@dataclass(kw_only=True)
class _StringsPathArgs:
    binary: Annotated[str | None, Arg(0, arrow_type=pa.string(), doc="Filesystem path to a binary.")]
    min_len: Annotated[int | None, _MIN_LEN]


@dataclass(kw_only=True)
class _StringsBytesArgs:
    binary: Annotated[bytes | None, Arg(0, arrow_type=pa.binary(), doc="Raw binary bytes.")]
    min_len: Annotated[int | None, _MIN_LEN]


def _emit_strings(src: BinarySource, min_len: int | None, out: OutputCollector, schema: pa.Schema) -> None:
    rows = core.strings(src, min_len)
    out.emit(
        pa.RecordBatch.from_pydict(
            {
                "seq": [r[0] for r in rows],
                "value": [r[1] for r in rows],
            },
            schema=schema,
        )
    )
    out.finish()


@init_single_worker
@bind_fixed_schema
class StringsPathFunction(TableFunctionGenerator[_StringsPathArgs]):
    """``strings(path[, min_len := ...])`` -- printable strings of a file."""

    FIXED_SCHEMA: ClassVar[pa.Schema] = _STRINGS_SCHEMA

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "strings"
        description = "Printable ASCII/UTF-16 strings (seq, value) of a binary (VARCHAR path)"
        categories = ["pe", "strings"]
        tags = _STRINGS_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT * FROM pe.strings('{_PE_FIXTURE}') ORDER BY seq",
                description="Printable strings of a binary file",
            ),
            FunctionExample(
                sql=f"SELECT * FROM pe.strings('{_PE_FIXTURE}', min_len := 8) ORDER BY seq",
                description="Only strings at least 8 chars long",
            ),
        ]

    @classmethod
    def cardinality(cls, params: BindParams[_StringsPathArgs]) -> TableCardinality:
        """Estimate the number of output rows for the optimizer."""
        return TableCardinality(estimate=1000, max=core.MAX_STRINGS)

    @classmethod
    def process(cls, params: ProcessParams[_StringsPathArgs], state: None, out: OutputCollector) -> None:
        """Emit the result rows for one input binary."""
        src = BinarySource.from_path(params.args.binary)
        if src is None:
            out.finish()
            return
        _emit_strings(src, params.args.min_len, out, params.output_schema)


@init_single_worker
@bind_fixed_schema
class StringsBytesFunction(TableFunctionGenerator[_StringsBytesArgs]):
    """``strings(blob[, min_len := ...])`` -- printable strings of bytes."""

    FIXED_SCHEMA: ClassVar[pa.Schema] = _STRINGS_SCHEMA

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "strings"
        description = "Printable ASCII/UTF-16 strings (seq, value) of a binary (BLOB bytes)"
        categories = ["pe", "strings"]
        tags = _STRINGS_TAGS
        # See SectionsBytesFunction: the VARCHAR-path overload of this same
        # `pe.main.strings` object carries the runnable examples; a table function
        # only accepts literal args so a BLOB example can't reference a file.

    @classmethod
    def cardinality(cls, params: BindParams[_StringsBytesArgs]) -> TableCardinality:
        """Estimate the number of output rows for the optimizer."""
        return TableCardinality(estimate=1000, max=core.MAX_STRINGS)

    @classmethod
    def process(cls, params: ProcessParams[_StringsBytesArgs], state: None, out: OutputCollector) -> None:
        """Emit the result rows for one input binary."""
        src = BinarySource.from_bytes(params.args.binary)
        if src is None:
            out.finish()
            return
        _emit_strings(src, params.args.min_len, out, params.output_schema)


TABLE_FUNCTIONS: list[type] = [
    SectionsPathFunction,
    SectionsBytesFunction,
    ImportsPathFunction,
    ImportsBytesFunction,
    ExportsPathFunction,
    ExportsBytesFunction,
    StringsPathFunction,
    StringsBytesFunction,
]
