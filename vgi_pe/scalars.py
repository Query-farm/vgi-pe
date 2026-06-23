"""Per-row scalar binary-analysis functions.

Every function here is a true DuckDB **scalar** -- one binary (per row) in, one
value out -- so it can be used inline in any projection or predicate:

    SELECT pe.binary_format(path)        FROM samples;
    SELECT pe.is_signed(blob)            FROM uploads;
    SELECT pe.imphash(path)              FROM samples;      -- cluster by import hash
    SELECT pe.overall_entropy(blob)      FROM uploads;      -- packing signal

Polymorphic input + argument syntax
------------------------------------
VGI / DuckDB *scalar* functions take **positional** arguments and resolve
overloads by the *types* of those arguments (the ``name := value`` named-argument
syntax is a property of table functions, not scalars). Each function therefore
accepts its binary argument as **either**:

- a ``VARCHAR`` filesystem path the worker opens, or
- a ``BLOB`` of the raw binary bytes (travelling over Arrow as binary).

These are two distinct DuckDB signatures, so each is its own ``ScalarFunction``
subclass sharing the ``Meta.name`` -- the same overload idiom the sibling
``vgi-pdf`` worker uses for path-vs-bytes input.

NULL / hostile semantics: a NULL input yields NULL output; a malformed,
truncated, or otherwise unparseable binary also yields NULL -- never a crash and
never a hang. (Static analysis only: the binary is never executed.)
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, Any

import pyarrow as pa
from vgi.arguments import Param, Returns
from vgi.metadata import FunctionExample
from vgi.scalar_function import ScalarFunction

from . import core
from .core import BinarySource

# ---------------------------------------------------------------------------
# Mapping helpers: apply a pure ``BinarySource -> X`` function across an input
# array of paths (strings) or bytes (binary), passing NULL straight through.
# ---------------------------------------------------------------------------


def _sources_from_paths(arr: pa.StringArray) -> list[BinarySource | None]:
    return [BinarySource.from_path(x) for x in arr.to_pylist()]


def _sources_from_bytes(arr: pa.BinaryArray) -> list[BinarySource | None]:
    return [BinarySource.from_bytes(x) for x in arr.to_pylist()]


def _map(
    srcs: list[BinarySource | None],
    fn: Callable[[BinarySource], Any],
    arrow_type: pa.DataType,
) -> pa.Array:
    out = [None if s is None else fn(s) for s in srcs]
    return pa.array(out, type=arrow_type)


# A small factory would be tidy, but a nested ``class Meta`` body cannot close
# over an enclosing-scope variable (the class body is not a closure), so each
# overload is written out explicitly. Verbose but boringly correct.


# ===========================================================================
# binary_format(binary) -> VARCHAR
# ===========================================================================


class BinaryFormatPathFunction(ScalarFunction):
    """``binary_format(path)`` -- 'PE'/'ELF'/'MachO' for a file at a path."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "binary_format"
        description = "Executable format ('PE'/'ELF'/'MachO') of a binary (VARCHAR path), or NULL"
        categories = ["pe", "format"]
        examples = [
            FunctionExample(
                sql="SELECT pe.binary_format('sample.exe')",
                description="Detect the executable format of a file",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.StringArray, Param(doc="Filesystem path to a binary.")]
    ) -> Annotated[pa.StringArray, Returns(arrow_type=pa.string())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_paths(binary), core.binary_format, pa.string())


class BinaryFormatBytesFunction(ScalarFunction):
    """``binary_format(blob)`` -- 'PE'/'ELF'/'MachO' for raw bytes."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "binary_format"
        description = "Executable format ('PE'/'ELF'/'MachO') of a binary (BLOB bytes), or NULL"
        categories = ["pe", "format"]
        examples = [
            FunctionExample(
                sql="SELECT pe.binary_format(blob) FROM uploads",
                description="Detect the executable format of bytes",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.BinaryArray, Param(doc="Raw binary bytes.", arrow_type=pa.binary())]
    ) -> Annotated[pa.StringArray, Returns(arrow_type=pa.string())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_bytes(binary), core.binary_format, pa.string())


# ===========================================================================
# is_signed(binary) -> BOOLEAN
# ===========================================================================


class IsSignedPathFunction(ScalarFunction):
    """``is_signed(path)`` -- True if the binary carries a code signature."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "is_signed"
        description = "True if a binary (VARCHAR path) carries a code signature (PE Authenticode / Mach-O)"
        categories = ["pe", "security"]
        examples = [
            FunctionExample(
                sql="SELECT pe.is_signed('sample.exe')",
                description="Whether a binary file is code-signed",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.StringArray, Param(doc="Filesystem path to a binary.")]
    ) -> Annotated[pa.BooleanArray, Returns(arrow_type=pa.bool_())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_paths(binary), core.is_signed, pa.bool_())


class IsSignedBytesFunction(ScalarFunction):
    """``is_signed(blob)`` -- True if binary bytes carry a code signature."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "is_signed"
        description = "True if a binary (BLOB bytes) carries a code signature (PE Authenticode / Mach-O)"
        categories = ["pe", "security"]
        examples = [
            FunctionExample(
                sql="SELECT pe.is_signed(blob) FROM uploads",
                description="Whether binary bytes are code-signed",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.BinaryArray, Param(doc="Raw binary bytes.", arrow_type=pa.binary())]
    ) -> Annotated[pa.BooleanArray, Returns(arrow_type=pa.bool_())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_bytes(binary), core.is_signed, pa.bool_())


# ===========================================================================
# entry_point(binary) -> UBIGINT
# ===========================================================================


class EntryPointPathFunction(ScalarFunction):
    """``entry_point(path)`` -- entry-point virtual address of a file."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "entry_point"
        description = "Entry-point virtual address of a binary (VARCHAR path), or NULL"
        categories = ["pe", "structure"]
        examples = [
            FunctionExample(
                sql="SELECT pe.entry_point('sample.exe')",
                description="Entry-point address of a binary file",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.StringArray, Param(doc="Filesystem path to a binary.")]
    ) -> Annotated[pa.UInt64Array, Returns(arrow_type=pa.uint64())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_paths(binary), core.entry_point, pa.uint64())


class EntryPointBytesFunction(ScalarFunction):
    """``entry_point(blob)`` -- entry-point virtual address of bytes."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "entry_point"
        description = "Entry-point virtual address of a binary (BLOB bytes), or NULL"
        categories = ["pe", "structure"]
        examples = [
            FunctionExample(
                sql="SELECT pe.entry_point(blob) FROM uploads",
                description="Entry-point address of binary bytes",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.BinaryArray, Param(doc="Raw binary bytes.", arrow_type=pa.binary())]
    ) -> Annotated[pa.UInt64Array, Returns(arrow_type=pa.uint64())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_bytes(binary), core.entry_point, pa.uint64())


# ===========================================================================
# machine(binary) -> VARCHAR
# ===========================================================================


class MachinePathFunction(ScalarFunction):
    """``machine(path)`` -- architecture name of a file."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "machine"
        description = "Architecture of a binary (VARCHAR path), e.g. 'X86_64'/'ARM64', or NULL"
        categories = ["pe", "structure"]
        examples = [
            FunctionExample(
                sql="SELECT pe.machine('sample.exe')",
                description="Architecture of a binary file",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.StringArray, Param(doc="Filesystem path to a binary.")]
    ) -> Annotated[pa.StringArray, Returns(arrow_type=pa.string())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_paths(binary), core.machine, pa.string())


class MachineBytesFunction(ScalarFunction):
    """``machine(blob)`` -- architecture name of bytes."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "machine"
        description = "Architecture of a binary (BLOB bytes), e.g. 'X86_64'/'ARM64', or NULL"
        categories = ["pe", "structure"]
        examples = [
            FunctionExample(
                sql="SELECT pe.machine(blob) FROM uploads",
                description="Architecture of binary bytes",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.BinaryArray, Param(doc="Raw binary bytes.", arrow_type=pa.binary())]
    ) -> Annotated[pa.StringArray, Returns(arrow_type=pa.string())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_bytes(binary), core.machine, pa.string())


# ===========================================================================
# compile_timestamp(binary) -> TIMESTAMP  (PE only; NULL otherwise)
# ===========================================================================

# PE TimeDateStamp is a Unix epoch (seconds). DuckDB maps an Arrow timestamp
# (microsecond, no tz) to TIMESTAMP, so we scale seconds -> microseconds.
_TS_TYPE = pa.timestamp("us")


def _timestamps(srcs: list[BinarySource | None]) -> pa.Array:
    out: list[int | None] = []
    for s in srcs:
        if s is None:
            out.append(None)
            continue
        epoch = core.compile_timestamp(s)
        out.append(None if epoch is None else epoch * 1_000_000)
    return pa.array(out, type=_TS_TYPE)


class CompileTimestampPathFunction(ScalarFunction):
    """``compile_timestamp(path)`` -- PE TimeDateStamp of a file, or NULL."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "compile_timestamp"
        description = "PE build timestamp (TimeDateStamp) of a binary (VARCHAR path); NULL for ELF/Mach-O"
        categories = ["pe", "metadata"]
        examples = [
            FunctionExample(
                sql="SELECT pe.compile_timestamp('sample.exe')",
                description="PE compile timestamp of a binary file",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.StringArray, Param(doc="Filesystem path to a binary.")]
    ) -> Annotated[pa.Array, Returns(arrow_type=_TS_TYPE)]:
        """Compute the per-row result array for the input batch."""
        return _timestamps(_sources_from_paths(binary))


class CompileTimestampBytesFunction(ScalarFunction):
    """``compile_timestamp(blob)`` -- PE TimeDateStamp of bytes, or NULL."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "compile_timestamp"
        description = "PE build timestamp (TimeDateStamp) of a binary (BLOB bytes); NULL for ELF/Mach-O"
        categories = ["pe", "metadata"]
        examples = [
            FunctionExample(
                sql="SELECT pe.compile_timestamp(blob) FROM uploads",
                description="PE compile timestamp of binary bytes",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.BinaryArray, Param(doc="Raw binary bytes.", arrow_type=pa.binary())]
    ) -> Annotated[pa.Array, Returns(arrow_type=_TS_TYPE)]:
        """Compute the per-row result array for the input batch."""
        return _timestamps(_sources_from_bytes(binary))


# ===========================================================================
# section_count(binary) -> INT
# ===========================================================================


class SectionCountPathFunction(ScalarFunction):
    """``section_count(path)`` -- number of sections in a file."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "section_count"
        description = "Number of sections in a binary (VARCHAR path), or NULL"
        categories = ["pe", "structure"]
        examples = [
            FunctionExample(
                sql="SELECT pe.section_count('sample.exe')",
                description="Section count of a binary file",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.StringArray, Param(doc="Filesystem path to a binary.")]
    ) -> Annotated[pa.Int32Array, Returns(arrow_type=pa.int32())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_paths(binary), core.section_count, pa.int32())


class SectionCountBytesFunction(ScalarFunction):
    """``section_count(blob)`` -- number of sections in bytes."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "section_count"
        description = "Number of sections in a binary (BLOB bytes), or NULL"
        categories = ["pe", "structure"]
        examples = [
            FunctionExample(
                sql="SELECT pe.section_count(blob) FROM uploads",
                description="Section count of binary bytes",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.BinaryArray, Param(doc="Raw binary bytes.", arrow_type=pa.binary())]
    ) -> Annotated[pa.Int32Array, Returns(arrow_type=pa.int32())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_bytes(binary), core.section_count, pa.int32())


# ===========================================================================
# overall_entropy(binary) -> DOUBLE
# ===========================================================================


class OverallEntropyPathFunction(ScalarFunction):
    """``overall_entropy(path)`` -- Shannon entropy of a whole file."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "overall_entropy"
        description = "Shannon entropy (bits/byte, 0-8) of a binary (VARCHAR path); high => packed/encrypted"
        categories = ["pe", "entropy"]
        examples = [
            FunctionExample(
                sql="SELECT pe.overall_entropy('sample.exe')",
                description="Overall entropy of a binary file",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.StringArray, Param(doc="Filesystem path to a binary.")]
    ) -> Annotated[pa.DoubleArray, Returns(arrow_type=pa.float64())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_paths(binary), core.overall_entropy, pa.float64())


class OverallEntropyBytesFunction(ScalarFunction):
    """``overall_entropy(blob)`` -- Shannon entropy of bytes."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "overall_entropy"
        description = "Shannon entropy (bits/byte, 0-8) of a binary (BLOB bytes); high => packed/encrypted"
        categories = ["pe", "entropy"]
        examples = [
            FunctionExample(
                sql="SELECT pe.overall_entropy(blob) FROM uploads",
                description="Overall entropy of binary bytes",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.BinaryArray, Param(doc="Raw binary bytes.", arrow_type=pa.binary())]
    ) -> Annotated[pa.DoubleArray, Returns(arrow_type=pa.float64())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_bytes(binary), core.overall_entropy, pa.float64())


# ===========================================================================
# imphash(binary) -> VARCHAR  (PE only; NULL otherwise)
# ===========================================================================


class ImphashPathFunction(ScalarFunction):
    """``imphash(path)`` -- PE import hash of a file, or NULL."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "imphash"
        description = "PE import hash (for clustering) of a binary (VARCHAR path); NULL for ELF/Mach-O"
        categories = ["pe", "clustering"]
        examples = [
            FunctionExample(
                sql="SELECT pe.imphash('sample.exe')",
                description="Import hash of a PE file",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.StringArray, Param(doc="Filesystem path to a binary.")]
    ) -> Annotated[pa.StringArray, Returns(arrow_type=pa.string())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_paths(binary), core.imphash, pa.string())


class ImphashBytesFunction(ScalarFunction):
    """``imphash(blob)`` -- PE import hash of bytes, or NULL."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "imphash"
        description = "PE import hash (for clustering) of a binary (BLOB bytes); NULL for ELF/Mach-O"
        categories = ["pe", "clustering"]
        examples = [
            FunctionExample(
                sql="SELECT pe.imphash(blob) FROM uploads",
                description="Import hash of PE bytes",
            ),
        ]

    @classmethod
    def compute(
        cls, binary: Annotated[pa.BinaryArray, Param(doc="Raw binary bytes.", arrow_type=pa.binary())]
    ) -> Annotated[pa.StringArray, Returns(arrow_type=pa.string())]:
        """Compute the per-row result array for the input batch."""
        return _map(_sources_from_bytes(binary), core.imphash, pa.string())


SCALAR_FUNCTIONS: list[type] = [
    BinaryFormatPathFunction,
    BinaryFormatBytesFunction,
    IsSignedPathFunction,
    IsSignedBytesFunction,
    EntryPointPathFunction,
    EntryPointBytesFunction,
    MachinePathFunction,
    MachineBytesFunction,
    CompileTimestampPathFunction,
    CompileTimestampBytesFunction,
    SectionCountPathFunction,
    SectionCountBytesFunction,
    OverallEntropyPathFunction,
    OverallEntropyBytesFunction,
    ImphashPathFunction,
    ImphashBytesFunction,
]
