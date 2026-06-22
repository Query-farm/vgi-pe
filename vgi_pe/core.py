"""Pure executable-binary static-analysis logic — no Arrow, no VGI, unit-testable.

This module is the heart of the worker: it parses an executable binary (a PE,
ELF, or Mach-O image) from a filesystem *path* or raw *bytes* and extracts
**static** triage signals — format, architecture, entry point, signing, build
timestamp, sections + per-section entropy, imports, exports, and printable
strings. It is a **defensive malware-triage** tool: it reads and describes a
binary, it **never executes it** and never resolves any external reference
(no loading of imported libraries, no following of anything but the bytes it
was handed).

Library choice: ``lief`` (the LIEF project, Apache-2.0) — one permissive,
cross-format parser for PE / ELF / Mach-O. Imported once, at module load, and
reused for the whole (long-lived) worker process. Do NOT import it per-row.

Hostile input is the *default*: every sample is presumed to be untrusted, quite
possibly malware, and quite possibly truncated/corrupt/adversarial. **Every**
parse is wrapped so a malformed, truncated, or hostile file can never crash or
hang the worker: scalar callers get ``None`` (→ SQL NULL) and table callers get
empty results (→ no rows). Nothing here ever raises out to the caller.

Bounds (defence against resource exhaustion / "bomb" inputs):

- ``MAX_INPUT_BYTES`` — refuse to even parse an absurdly large blob.
- ``MAX_STRINGS`` / ``MAX_STRING_LEN`` — cap the strings extractor's output.
- ``MAX_ROWS`` — cap rows from sections / imports / exports.
"""

from __future__ import annotations

import contextlib
import math
import os
from typing import Any

# Heavy library imported once, at module load, and reused for the whole process
# lifetime (worker processes are long-lived). Do NOT import this per-row.
import lief

# LIEF logs parser warnings on hostile input to stderr; silence them so a flood
# of warnings from a malformed sample can't spam the worker's logs.
with contextlib.suppress(Exception):
    lief.logging.disable()

__all__ = [
    "MAX_INPUT_BYTES",
    "MAX_ROWS",
    "MAX_STRINGS",
    "MAX_STRING_LEN",
    "BinarySource",
    "binary_format",
    "compile_timestamp",
    "entry_point",
    "exports",
    "imphash",
    "imports",
    "is_signed",
    "machine",
    "overall_entropy",
    "parse",
    "section_count",
    "sections",
    "strings",
]

# ---------------------------------------------------------------------------
# Bounds (resource caps for hostile / "bomb" inputs).
# ---------------------------------------------------------------------------
# 512 MiB: comfortably larger than any real triage sample, small enough that a
# pathological blob can't exhaust memory just being read into the process.
MAX_INPUT_BYTES = 512 * 1024 * 1024
# Caps for the strings extractor.
MAX_STRINGS = 100_000
MAX_STRING_LEN = 1024
# Cap for set-returning extractors (sections / imports / exports).
MAX_ROWS = 1_000_000
# Default minimum length for the strings extractor.
DEFAULT_MIN_STRING_LEN = 5


# ---------------------------------------------------------------------------
# Polymorphic input: a VARCHAR filesystem path OR a BLOB of binary bytes.
# ---------------------------------------------------------------------------


class BinarySource:
    """A binary to read: either a filesystem ``path`` or in-memory ``data`` bytes.

    Exactly one of ``path`` / ``data`` is set. ``read_bytes()`` returns the raw
    bytes regardless of which it is, reading the file lazily and refusing an
    over-large input. Only the bytes we were given (or the local file path we
    were given) are ever touched — never a URL or any embedded reference.
    """

    __slots__ = ("data", "path")

    def __init__(self, *, path: str | None = None, data: bytes | None = None) -> None:
        self.path = path
        self.data = data

    @classmethod
    def from_path(cls, path: str | None) -> BinarySource | None:
        """Build a source from a VARCHAR path, or ``None`` for a NULL path."""
        if path is None:
            return None
        return cls(path=path)

    @classmethod
    def from_bytes(cls, data: bytes | None) -> BinarySource | None:
        """Build a source from BLOB bytes, or ``None`` for NULL bytes."""
        if data is None:
            return None
        return cls(data=data)

    def read_bytes(self) -> bytes | None:
        """Return the raw bytes, or ``None`` if unreadable / too large.

        Never raises: a missing file, a permission error, or an over-large input
        all degrade to ``None`` so the caller can map cleanly to NULL / no rows.
        """
        try:
            if self.data is not None:
                if len(self.data) > MAX_INPUT_BYTES:
                    return None
                return self.data
            assert self.path is not None
            if not os.path.isfile(self.path):
                return None
            if os.path.getsize(self.path) > MAX_INPUT_BYTES:
                return None
            with open(self.path, "rb") as fh:
                return fh.read()
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Parsing. ``parse`` is total: it returns a LIEF binary or ``None`` and never
# raises, no matter how hostile the bytes are.
# ---------------------------------------------------------------------------


def parse(src: BinarySource) -> Any | None:
    """Parse a binary into a LIEF object, or ``None`` if it isn't a known format.

    Total and crash-proof: truncated, corrupt, empty, or non-binary input all
    yield ``None``. LIEF parses PE / ELF / Mach-O; a fat Mach-O yields the first
    contained slice (LIEF's default behaviour), which is fine for triage.
    """
    data = src.read_bytes()
    if not data:
        return None
    try:
        binary = lief.parse(data)
    except Exception:
        return None
    return binary


# ---------------------------------------------------------------------------
# Scalars (one binary in, one value out). These NEVER raise: any failure on a
# hostile binary becomes ``None`` so the per-row scalar yields SQL NULL.
# ---------------------------------------------------------------------------


_FORMAT_NAMES = {
    "PE": "PE",
    "ELF": "ELF",
    "MACHO": "MachO",
}


def binary_format(src: BinarySource) -> str | None:
    """``'PE'`` / ``'ELF'`` / ``'MachO'``, or ``None`` if not a known binary."""
    binary = parse(src)
    if binary is None:
        return None
    try:
        name = binary.format.name
    except Exception:
        return None
    return _FORMAT_NAMES.get(name)


def machine(src: BinarySource) -> str | None:
    """Architecture name (e.g. ``'X86_64'``, ``'ARM64'``), or ``None``.

    Uses LIEF's format-agnostic abstract architecture so PE / ELF / Mach-O all
    report a comparable value.
    """
    binary = parse(src)
    if binary is None:
        return None
    try:
        arch = binary.abstract.header.architecture
        name = arch.name if hasattr(arch, "name") else str(arch)
        return name or None
    except Exception:
        return None


def entry_point(src: BinarySource) -> int | None:
    """Entry-point virtual address, or ``None`` if unavailable.

    Returned as an unsigned value; a negative/garbage entry point degrades to
    ``None`` rather than a confusing wrapped number.
    """
    binary = parse(src)
    if binary is None:
        return None
    try:
        ep = int(binary.entrypoint)
    except Exception:
        return None
    if ep < 0:
        return None
    return ep


def is_signed(src: BinarySource) -> bool | None:
    """``True`` if the binary carries a code signature, else ``False``; ``None``
    if it isn't a parseable binary.

    Covers PE Authenticode signatures and Mach-O code-signature load commands.
    ELF has no standard embedded code signature, so a valid ELF reports
    ``False`` (the absence of a signature is a *successful* answer, not a
    failure).
    """
    binary = parse(src)
    if binary is None:
        return None
    try:
        fmt = binary.format.name
        if fmt == "PE":
            return bool(binary.has_signatures)
        if fmt == "MACHO":
            return bool(binary.has_code_signature)
        # ELF (and anything else): no embedded code signature.
        return False
    except Exception:
        return None


def compile_timestamp(src: BinarySource) -> int | None:
    """PE ``TimeDateStamp`` as a Unix epoch (seconds), or ``None`` if n/a.

    Only PE images carry a compile timestamp in their COFF header; ELF and
    Mach-O return ``None``. A zero stamp (common in reproducible builds) is
    treated as "not present" → ``None``.
    """
    binary = parse(src)
    if binary is None:
        return None
    try:
        if binary.format.name != "PE":
            return None
        stamp = int(binary.header.time_date_stamps)
    except Exception:
        return None
    if stamp <= 0:
        return None
    return stamp


def imphash(src: BinarySource) -> str | None:
    """PE import hash (for clustering related samples), or ``None`` if n/a.

    The imphash is a hash over the ordered import-table library/function names —
    a classic malware-clustering signal. Only meaningful for PE; ELF / Mach-O
    return ``None``. A PE with no imports yields an empty imphash, which we also
    map to ``None``.
    """
    binary = parse(src)
    if binary is None:
        return None
    try:
        if binary.format.name != "PE":
            return None
        value = lief.PE.get_imphash(binary)
    except Exception:
        return None
    return value or None


def section_count(src: BinarySource) -> int | None:
    """Number of sections, or ``None`` if not a parseable binary."""
    binary = parse(src)
    if binary is None:
        return None
    try:
        return len(list(binary.sections))
    except Exception:
        return None


def _shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte over ``data`` (0.0 for empty)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def overall_entropy(src: BinarySource) -> float | None:
    """Shannon entropy (bits/byte, in ``[0, 8]``) of the whole file, or ``None``.

    A high overall entropy (≈7.5–8.0) is a packing / encryption signal. Computed
    over the raw bytes, so it is independent of how LIEF lays out sections.
    """
    data = src.read_bytes()
    if not data:
        return None
    # Confirm it is at least a recognizable binary before reporting entropy, so
    # plain text / random non-binary blobs are NULL (not a misleading number).
    if parse(src) is None:
        return None
    try:
        return _shannon_entropy(data)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Table-shaped extractors. Each returns a list of plain tuples and NEVER raises:
# a hostile binary yields an empty list (→ no rows). A per-row parse failure on
# one section/import is skipped rather than aborting the whole call.
# ---------------------------------------------------------------------------


# Common interesting PE section characteristics, in a stable order, rendered as
# a comma-joined flag string. Packers often produce writable+executable sections
# or oddly-named/high-entropy sections, so surfacing these helps triage.
_PE_FLAG_ORDER = ("CNT_CODE", "MEM_EXECUTE", "MEM_READ", "MEM_WRITE", "MEM_DISCARDABLE")


def _pe_characteristics(section: Any) -> str:
    """Render a PE section's interesting characteristics as a flag string."""
    flags: list[str] = []
    try:
        for name in _PE_FLAG_ORDER:
            characteristic = getattr(lief.PE.Section.CHARACTERISTICS, name, None)
            if characteristic is not None and section.has_characteristic(characteristic):
                flags.append(name)
    except Exception:
        return ""
    return ",".join(flags)


def sections(src: BinarySource) -> list[tuple[str, int, int, float, str]]:
    """Per-section rows ``(name, virtual_size, raw_size, entropy, characteristics)``.

    ``entropy`` is the per-section Shannon entropy (bits/byte) — a high value
    flags a likely-packed/compressed section. ``characteristics`` is a
    comma-joined flag string for PE (e.g. ``CNT_CODE,MEM_EXECUTE,MEM_READ``) and
    empty for ELF / Mach-O (whose section attributes differ). Returns ``[]`` for
    a binary that can't be parsed.
    """
    binary = parse(src)
    if binary is None:
        return []
    is_pe = False
    try:
        is_pe = binary.format.name == "PE"
    except Exception:
        is_pe = False
    rows: list[tuple[str, int, int, float, str]] = []
    try:
        for section in binary.sections:
            if len(rows) >= MAX_ROWS:
                break
            try:
                name = str(section.name)
                virtual_size = int(getattr(section, "virtual_size", 0) or 0)
                raw_size = int(getattr(section, "size", 0) or 0)
                try:
                    entropy = float(section.entropy)
                except Exception:
                    entropy = 0.0
                characteristics = _pe_characteristics(section) if is_pe else ""
            except Exception:
                continue
            rows.append((name, virtual_size, raw_size, entropy, characteristics))
    except Exception:
        return rows
    return rows


def imports(src: BinarySource) -> list[tuple[str, str]]:
    """Imported symbols as ``(library, function)`` rows.

    For PE, ``library`` is the DLL name (e.g. ``KERNEL32.dll``) and ``function``
    is the imported symbol (or ``ordinal#N`` for an ordinal import). For ELF /
    Mach-O, which don't bind imports to a per-library table the same way,
    ``library`` is the empty string and ``function`` is each imported symbol
    name. Returns ``[]`` for an unparseable binary.
    """
    binary = parse(src)
    if binary is None:
        return []
    rows: list[tuple[str, str]] = []
    is_pe = False
    try:
        is_pe = binary.format.name == "PE"
    except Exception:
        is_pe = False

    if is_pe:
        try:
            for imp in binary.imports:
                library = ""
                try:
                    library = str(imp.name or "")
                except Exception:
                    library = ""
                for entry in imp.entries:
                    if len(rows) >= MAX_ROWS:
                        return rows
                    try:
                        if entry.is_ordinal:
                            function = f"ordinal#{int(entry.ordinal)}"
                        else:
                            function = str(entry.name or "")
                    except Exception:
                        continue
                    rows.append((library, function))
        except Exception:
            return rows
        return rows

    # ELF / Mach-O: use the format-agnostic abstract imported-function list.
    try:
        for func in binary.abstract.imported_functions:
            if len(rows) >= MAX_ROWS:
                break
            try:
                name = str(getattr(func, "name", func) or "")
            except Exception:
                continue
            if name:
                rows.append(("", name))
    except Exception:
        return rows
    return rows


def exports(src: BinarySource) -> list[tuple[str, int]]:
    """Exported symbols as ``(name, address)`` rows.

    ``address`` is the symbol's value/address as an unsigned integer (0 when
    unavailable). Returns ``[]`` for an unparseable binary or one with no
    exports.
    """
    binary = parse(src)
    if binary is None:
        return []
    rows: list[tuple[str, int]] = []
    try:
        for func in binary.abstract.exported_functions:
            if len(rows) >= MAX_ROWS:
                break
            try:
                name = str(getattr(func, "name", func) or "")
                address = int(getattr(func, "address", 0) or 0)
                if address < 0:
                    address = 0
            except Exception:
                continue
            if name:
                rows.append((name, address))
    except Exception:
        return rows
    return rows


def _printable_ascii(data: bytes, min_len: int) -> list[str]:
    """Extract printable ASCII runs of at least ``min_len`` chars."""
    out: list[str] = []
    current: list[int] = []
    for byte in data:
        if 0x20 <= byte <= 0x7E:
            current.append(byte)
            if len(current) > MAX_STRING_LEN:
                # Flush an over-long run at the cap and keep scanning.
                out.append(bytes(current[:MAX_STRING_LEN]).decode("ascii"))
                current = []
                if len(out) >= MAX_STRINGS:
                    return out
        else:
            if len(current) >= min_len:
                out.append(bytes(current).decode("ascii"))
                if len(out) >= MAX_STRINGS:
                    return out
            current = []
    if len(current) >= min_len and len(out) < MAX_STRINGS:
        out.append(bytes(current).decode("ascii"))
    return out


def _printable_utf16le(data: bytes, min_len: int) -> list[str]:
    """Extract printable UTF-16LE runs (ASCII char followed by a NUL) ≥ ``min_len``.

    Catches the wide (UTF-16) strings common in Windows binaries without a full
    Unicode decode: a run of ``<ascii> 0x00`` pairs.
    """
    out: list[str] = []
    current: list[int] = []
    i = 0
    n = len(data)
    while i + 1 < n:
        lo = data[i]
        hi = data[i + 1]
        if 0x20 <= lo <= 0x7E and hi == 0x00:
            current.append(lo)
            i += 2
            if len(current) > MAX_STRING_LEN:
                out.append(bytes(current[:MAX_STRING_LEN]).decode("ascii"))
                current = []
                if len(out) >= MAX_STRINGS:
                    return out
            continue
        if len(current) >= min_len:
            out.append(bytes(current).decode("ascii"))
            if len(out) >= MAX_STRINGS:
                return out
        current = []
        i += 1
    if len(current) >= min_len and len(out) < MAX_STRINGS:
        out.append(bytes(current).decode("ascii"))
    return out


def strings(src: BinarySource, min_len: int | None = None) -> list[tuple[int, str]]:
    """Printable strings as ``(seq, value)`` rows (1-based ``seq``).

    Extracts both printable-ASCII and printable-UTF-16LE runs of at least
    ``min_len`` characters (default :data:`DEFAULT_MIN_STRING_LEN`). Output is
    bounded by :data:`MAX_STRINGS` and each value by :data:`MAX_STRING_LEN`, so a
    high-entropy / huge file can't produce unbounded output. Operates on the raw
    bytes (so it works even on a binary LIEF can't fully parse, as long as the
    bytes are readable); returns ``[]`` only when the input is unreadable.
    """
    data = src.read_bytes()
    if not data:
        return []
    effective_min = DEFAULT_MIN_STRING_LEN if min_len is None else int(min_len)
    if effective_min < 1:
        effective_min = 1
    try:
        ascii_runs = _printable_ascii(data, effective_min)
        remaining = MAX_STRINGS - len(ascii_runs)
        wide_runs = _printable_utf16le(data, effective_min) if remaining > 0 else []
        combined = ascii_runs + wide_runs[:remaining]
    except Exception:
        return []
    return [(i, value) for i, value in enumerate(combined, start=1)]
