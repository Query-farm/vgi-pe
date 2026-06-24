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

from . import core
from .core import BinarySource
from .schema_utils import field

# DuckDB cannot expose a table function's output schema for discovery, so each
# table function carries a ``vgi.columns_md`` tag: a Markdown table of the rows
# it returns. These mirror the ``pa.schema([...])`` definitions below.
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
        tags = {"vgi.columns_md": _SECTIONS_COLUMNS_MD}
        examples = [
            FunctionExample(
                sql="SELECT * FROM pe.sections('sample.exe') ORDER BY name",
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
        tags = {"vgi.columns_md": _SECTIONS_COLUMNS_MD}
        examples = [
            FunctionExample(
                sql="SELECT * FROM pe.sections(blob) ORDER BY name",
                description="Sections of binary bytes with entropy",
            ),
        ]

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
        tags = {"vgi.columns_md": _IMPORTS_COLUMNS_MD}
        examples = [
            FunctionExample(
                sql="SELECT * FROM pe.imports('sample.exe') ORDER BY library, function",
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
        tags = {"vgi.columns_md": _IMPORTS_COLUMNS_MD}
        examples = [
            FunctionExample(
                sql="SELECT * FROM pe.imports(blob) ORDER BY library, function",
                description="Imported symbols of binary bytes",
            ),
        ]

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
        tags = {"vgi.columns_md": _EXPORTS_COLUMNS_MD}
        examples = [
            FunctionExample(
                sql="SELECT * FROM pe.exports('sample.so') ORDER BY name",
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
        tags = {"vgi.columns_md": _EXPORTS_COLUMNS_MD}
        examples = [
            FunctionExample(
                sql="SELECT * FROM pe.exports(blob) ORDER BY name",
                description="Exported symbols of binary bytes",
            ),
        ]

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
        tags = {"vgi.columns_md": _STRINGS_COLUMNS_MD}
        examples = [
            FunctionExample(
                sql="SELECT * FROM pe.strings('sample.exe') ORDER BY seq",
                description="Printable strings of a binary file",
            ),
            FunctionExample(
                sql="SELECT * FROM pe.strings('sample.exe', min_len := 8)",
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
        tags = {"vgi.columns_md": _STRINGS_COLUMNS_MD}
        examples = [
            FunctionExample(
                sql="SELECT * FROM pe.strings(blob) ORDER BY seq",
                description="Printable strings of binary bytes",
            ),
        ]

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
