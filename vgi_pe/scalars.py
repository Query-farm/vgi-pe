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

from . import core, meta
from .core import BinarySource

# A real, committed PE fixture the worker can open by relative path (the worker's
# cwd is the repo root). Used so per-function examples actually EXECUTE and
# return data under the strict linter (it runs every example by default).
_PE_FIXTURE = "test/sql/data/hello.exe"
_ELF_FIXTURE = "test/sql/data/hello_elf"

# Build a BLOB of the same fixture inline so the BLOB-overload examples are
# self-contained and runnable (DuckDB's `read_blob` returns the file bytes).
_PE_BLOB = f"(SELECT content FROM read_blob('{_PE_FIXTURE}'))"

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

_BINARY_FORMAT_TAGS = meta.object_tags(
    title="Detect Executable Format",
    doc_llm=(
        "Detect the **container format** of an executable image and return it as a short string: "
        "`PE` (Windows portable executable), `ELF` (Linux/Unix), or `MachO` (macOS). Pass the "
        "binary as either a VARCHAR filesystem path the worker opens or a BLOB of raw bytes. "
        "Returns `NULL` when the input is NULL, empty, truncated, or not a recognizable "
        "executable, so it is safe to run across a mixed corpus.\n\n"
        "Use this first when triaging an unknown sample: the format decides which downstream "
        "signals are meaningful (e.g. `imphash` and `compile_timestamp` are PE-only). The binary "
        "is parsed statically and **never executed**."
    ),
    doc_md=(
        "## binary_format\n\n"
        "Returns the executable container format of a binary as `PE`, `ELF`, or `MachO`.\n\n"
        "### Usage\n\n"
        "```sql\n"
        "SELECT pe.binary_format('malware.bin');   -- 'PE'\n"
        "SELECT pe.binary_format(content) FROM read_blob('s.elf');\n"
        "```\n\n"
        "Accepts a VARCHAR path or a BLOB. Returns `NULL` for NULL, empty, or unrecognizable "
        "input — never an error. Typically the first step in a triage pipeline because the format "
        "gates which other functions apply."
    ),
    keywords="format, file type, magic, PE, ELF, Mach-O, MachO, executable, container, detect, identify, binary type",
    relative_path="vgi_pe/scalars.py",
)


class BinaryFormatPathFunction(ScalarFunction):
    """``binary_format(path)`` -- 'PE'/'ELF'/'MachO' for a file at a path."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "binary_format"
        description = "Executable format ('PE'/'ELF'/'MachO') of a binary (VARCHAR path), or NULL"
        categories = ["pe", "format"]
        tags = _BINARY_FORMAT_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.binary_format('{_PE_FIXTURE}')",
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
        tags = _BINARY_FORMAT_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.binary_format({_PE_BLOB})",
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

_IS_SIGNED_TAGS = meta.object_tags(
    title="Binary Is Code-Signed",
    doc_llm=(
        "Return whether a binary carries an embedded **code signature**: `true`/`false`, or "
        "`NULL` for unparseable input. The check is format-aware — PE Authenticode signatures, "
        "Mach-O embedded code signatures — and ELF, which has no native embedded-signature "
        "concept, always reports `false`. A `false` result is a *successful* answer (the file "
        "simply isn't signed), not a parse failure.\n\n"
        "Use it as a quick trust signal during triage: unsigned system-looking binaries, or "
        "binaries that masquerade as signed vendors but report `false`, are worth a closer look. "
        "Note: this reports the *presence* of a signature, not whether the signature is valid or "
        "trusted. Static read-only check; the binary is never executed."
    ),
    doc_md=(
        "## is_signed\n\n"
        "Boolean: does the binary carry an embedded code signature?\n\n"
        "### Behavior by format\n\n"
        "| format | meaning |\n"
        "|---|---|\n"
        "| PE | has an Authenticode signature |\n"
        "| Mach-O | has an embedded code signature |\n"
        "| ELF | always `false` (no native embedded signature) |\n\n"
        "Returns `NULL` only for input that cannot be parsed. This reports *presence*, not "
        "cryptographic *validity* — verify the chain separately if trust matters."
    ),
    keywords="signed, signature, code signing, authenticode, codesign, trust, certificate, PE, Mach-O, security",
    relative_path="vgi_pe/scalars.py",
)


class IsSignedPathFunction(ScalarFunction):
    """``is_signed(path)`` -- True if the binary carries a code signature."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "is_signed"
        description = "True if a binary (VARCHAR path) carries a code signature (PE Authenticode / Mach-O)"
        categories = ["pe", "security"]
        tags = _IS_SIGNED_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.is_signed('{_PE_FIXTURE}')",
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
        tags = _IS_SIGNED_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.is_signed({_PE_BLOB})",
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

_ENTRY_POINT_TAGS = meta.object_tags(
    title="Entry-Point Address",
    doc_llm=(
        "Return the **entry-point address** of an executable as an unsigned 64-bit integer — the "
        "virtual address at which execution would begin (the PE `AddressOfEntryPoint` rebased to "
        "the image base, the ELF/Mach-O entry address). Returns `NULL` for unparseable input. "
        "The worker only reports the address; it never transfers control there.\n\n"
        "Use it to fingerprint a build, to spot an entry point that lands outside the expected "
        "code section (a classic packer/injection tell when correlated with `sections` and "
        "`overall_entropy`), or as a join key when clustering related samples."
    ),
    doc_md=(
        "## entry_point\n\n"
        "The virtual address where execution begins, as a `UBIGINT`.\n\n"
        "### Usage\n\n"
        "```sql\n"
        "SELECT pe.entry_point('sample.exe');   -- e.g. 5392\n"
        "```\n\n"
        "Returns `NULL` when the binary cannot be parsed. Compare against the address ranges from "
        "`pe.sections(...)` to check that the entry point falls inside an executable section — an "
        "entry point in a high-entropy or writable section is a common packing/injection signal."
    ),
    keywords="entry point, entrypoint, AddressOfEntryPoint, start address, OEP, virtual address, structure",
    relative_path="vgi_pe/scalars.py",
)


class EntryPointPathFunction(ScalarFunction):
    """``entry_point(path)`` -- entry-point virtual address of a file."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "entry_point"
        description = "Entry-point virtual address of a binary (VARCHAR path), or NULL"
        categories = ["pe", "structure"]
        tags = _ENTRY_POINT_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.entry_point('{_PE_FIXTURE}')",
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
        tags = _ENTRY_POINT_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.entry_point({_PE_BLOB})",
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

_MACHINE_TAGS = meta.object_tags(
    title="Target Architecture",
    doc_llm=(
        "Return the **target CPU architecture** of a binary as a normalized string, e.g. "
        "`X86_64`, `I386`, `ARM64`, `ARM`. It reads LIEF's *abstract* architecture so the answer "
        "is comparable across PE, ELF, and Mach-O rather than each format's raw machine code. "
        "Returns `NULL` for unparseable input.\n\n"
        "Use it to filter or partition a corpus by architecture (e.g. find all ARM64 samples), to "
        "sanity-check that a sample matches the platform it claims, or to route a sample to the "
        "right disassembler. Static read-only; the binary is never executed."
    ),
    doc_md=(
        "## machine\n\n"
        "The target CPU architecture as a normalized string (`X86_64`, `I386`, `ARM64`, `ARM`, "
        "…).\n\n"
        "### Usage\n\n"
        "```sql\n"
        "SELECT pe.machine('sample.exe');   -- 'X86_64'\n"
        "```\n\n"
        "Uses LIEF's abstract architecture so PE / ELF / Mach-O report on a common scale. Returns "
        "`NULL` for input that cannot be parsed."
    ),
    keywords="machine, architecture, arch, cpu, x86, x86_64, amd64, i386, arm, arm64, aarch64, ISA, structure",
    relative_path="vgi_pe/scalars.py",
)


class MachinePathFunction(ScalarFunction):
    """``machine(path)`` -- architecture name of a file."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "machine"
        description = "Architecture of a binary (VARCHAR path), e.g. 'X86_64'/'ARM64', or NULL"
        categories = ["pe", "structure"]
        tags = _MACHINE_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.machine('{_PE_FIXTURE}')",
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
        tags = _MACHINE_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.machine({_PE_BLOB})",
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


_COMPILE_TIMESTAMP_TAGS = meta.object_tags(
    title="PE Build Timestamp",
    doc_llm=(
        "Return the PE **build timestamp** (the COFF header `TimeDateStamp`) as a `TIMESTAMP`. "
        "This is **PE-only**: ELF and Mach-O have no equivalent header field and return `NULL`, "
        "as does any unparseable input. The raw field is a Unix epoch in seconds; the worker "
        "scales it to microsecond-precision Arrow timestamp.\n\n"
        "Use it for build-provenance and timeline analysis — bucketing samples by build date, "
        "spotting implausible values (the field is attacker-controllable, so a zero, far-future, "
        "or suspiciously round timestamp is itself a signal), and correlating related builds. "
        "Treat the value as a *claim*, not ground truth."
    ),
    doc_md=(
        "## compile_timestamp\n\n"
        "The PE COFF `TimeDateStamp` as a `TIMESTAMP` (PE only).\n\n"
        "### Usage\n\n"
        "```sql\n"
        "SELECT pe.compile_timestamp('sample.exe');\n"
        "```\n\n"
        "Returns `NULL` for ELF, Mach-O, and unparseable input. The field is stored as a Unix "
        "epoch (seconds) and is **attacker-controllable** — implausible values (zero, far future, "
        "round numbers) are a triage signal, not an error."
    ),
    keywords="compile timestamp, build time, TimeDateStamp, PE header, provenance, timeline, metadata, epoch",
    relative_path="vgi_pe/scalars.py",
)


class CompileTimestampPathFunction(ScalarFunction):
    """``compile_timestamp(path)`` -- PE TimeDateStamp of a file, or NULL."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "compile_timestamp"
        description = "PE build timestamp (TimeDateStamp) of a binary (VARCHAR path); NULL for ELF/Mach-O"
        categories = ["pe", "metadata"]
        tags = _COMPILE_TIMESTAMP_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.compile_timestamp('{_PE_FIXTURE}')",
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
        tags = _COMPILE_TIMESTAMP_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.compile_timestamp({_PE_BLOB})",
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


_SECTION_COUNT_TAGS = meta.object_tags(
    title="Number of Sections",
    doc_llm=(
        "Return the **number of sections** in a binary as an integer (PE sections, ELF sections, "
        "Mach-O sections across segments). Returns `NULL` for unparseable input.\n\n"
        "A scalar summary of what `pe.sections(...)` enumerates row-by-row. Use it as a cheap "
        "anomaly signal: an unusually low count (e.g. a single giant section) or an unusually high "
        "one can indicate packing, a manually crafted file, or an unusual toolchain. Pair it with "
        "`overall_entropy` for a quick packed-vs-clean heuristic. Static read-only; the binary is "
        "never executed."
    ),
    doc_md=(
        "## section_count\n\n"
        "The number of sections in the binary, as an integer.\n\n"
        "### Usage\n\n"
        "```sql\n"
        "SELECT pe.section_count('sample.exe');\n"
        "```\n\n"
        "Returns `NULL` for input that cannot be parsed. This is the scalar summary of "
        "`pe.sections(...)`; very low or very high counts are mild packing/obfuscation signals."
    ),
    keywords="section count, sections, number of sections, segments, layout, structure, count",
    relative_path="vgi_pe/scalars.py",
)


class SectionCountPathFunction(ScalarFunction):
    """``section_count(path)`` -- number of sections in a file."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "section_count"
        description = "Number of sections in a binary (VARCHAR path), or NULL"
        categories = ["pe", "structure"]
        tags = _SECTION_COUNT_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.section_count('{_PE_FIXTURE}')",
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
        tags = _SECTION_COUNT_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.section_count({_PE_BLOB})",
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


_OVERALL_ENTROPY_TAGS = meta.object_tags(
    title="Whole-File Shannon Entropy",
    doc_llm=(
        "Return the **Shannon entropy** of the entire file as a `DOUBLE` in bits-per-byte on a "
        "`0.0`–`8.0` scale. It is computed over the raw file bytes (independent of the section "
        "layout), so it works even when LIEF can't fully resolve the structure — but it still "
        "returns `NULL` for NULL or non-binary input so a random text blob isn't given a "
        "misleading number.\n\n"
        "High whole-file entropy (typically `> ~7.0`) is the single strongest cheap signal of "
        "**packing, compression, or encryption**: most native code sits around `5.5`–`6.5`, while "
        "packed/encrypted payloads push toward `8.0`. Use it as a first-pass triage filter, then "
        "drill into per-section entropy via `pe.sections(...)`. Static read-only."
    ),
    doc_md=(
        "## overall_entropy\n\n"
        "Whole-file Shannon entropy as a `DOUBLE`, in bits/byte on a `0`–`8` scale.\n\n"
        "### Interpreting the value\n\n"
        "| range | typical meaning |\n"
        "|---|---|\n"
        "| ~5.5–6.5 | ordinary native code/data |\n"
        "| > ~7.0 | likely packed, compressed, or encrypted |\n\n"
        "Computed over raw bytes (independent of section layout). Returns `NULL` for non-binary "
        "input. For where the high entropy lives, see per-section entropy in `pe.sections(...)`."
    ),
    keywords="entropy, shannon, packing, packed, compressed, encrypted, obfuscation, randomness, triage",
    relative_path="vgi_pe/scalars.py",
)


class OverallEntropyPathFunction(ScalarFunction):
    """``overall_entropy(path)`` -- Shannon entropy of a whole file."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "overall_entropy"
        description = "Shannon entropy (bits/byte, 0-8) of a binary (VARCHAR path); high => packed/encrypted"
        categories = ["pe", "entropy"]
        tags = _OVERALL_ENTROPY_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.overall_entropy('{_PE_FIXTURE}')",
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
        tags = _OVERALL_ENTROPY_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.overall_entropy({_PE_BLOB})",
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


_IMPHASH_TAGS = meta.object_tags(
    title="PE Import Hash (imphash)",
    doc_llm=(
        "Return the **imphash** (import hash) of a PE: the MD5 over the normalized, ordered list "
        "of imported library/function names. It is **PE-only** — ELF and Mach-O, and any "
        "unparseable input, return `NULL`. Two PEs built from the same source/toolchain with the "
        "same import table share an imphash even if their bytes differ, which makes it a classic "
        "**clustering / family-attribution** key for malware triage.\n\n"
        "Use it to `GROUP BY` related samples, to pivot from one known-bad sample to others, or to "
        "match against threat-intel imphash blocklists. Caveat: packers and import obfuscation can "
        "collapse or mangle the import table, so an imphash is a strong-but-not-definitive link. "
        "Static read-only; the binary is never executed."
    ),
    doc_md=(
        "## imphash\n\n"
        "The PE import hash — MD5 of the normalized import table — as a hex string (PE only).\n\n"
        "### Usage\n\n"
        "```sql\n"
        "SELECT pe.imphash(path) AS h, count(*) FROM samples GROUP BY h ORDER BY 2 DESC;\n"
        "```\n\n"
        "Returns `NULL` for ELF, Mach-O, and unparseable input. Samples sharing an imphash are "
        "likely the same family/build; packing or import obfuscation weakens the signal, so treat "
        "it as a strong hint rather than proof."
    ),
    keywords="imphash, import hash, pehash, clustering, family, attribution, malware, fingerprint, MD5, imports",
    relative_path="vgi_pe/scalars.py",
)


class ImphashPathFunction(ScalarFunction):
    """``imphash(path)`` -- PE import hash of a file, or NULL."""

    class Meta:
        """SDK function metadata (name, description, examples)."""

        name = "imphash"
        description = "PE import hash (for clustering) of a binary (VARCHAR path); NULL for ELF/Mach-O"
        categories = ["pe", "clustering"]
        tags = _IMPHASH_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.imphash('{_PE_FIXTURE}')",
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
        tags = _IMPHASH_TAGS
        examples = [
            FunctionExample(
                sql=f"SELECT pe.imphash({_PE_BLOB})",
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
