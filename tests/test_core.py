"""Unit tests for the pure ``vgi_pe.core`` static-analysis logic.

These call the pure functions directly (no Arrow, no VGI) over the committed
real binaries (a PE, an ELF, a Mach-O) plus the hostile garbage blob. They cover
the happy paths AND the hostile-input contract: garbage / empty / truncated
bytes -> None / empty, non-binary text -> None, never a crash.
"""

from __future__ import annotations

import pytest

from vgi_pe import core
from vgi_pe.core import BinarySource

from . import fixtures as fx


def _bytes(data: bytes) -> BinarySource:
    src = BinarySource.from_bytes(data)
    assert src is not None
    return src


def _pe() -> BinarySource:
    return _bytes(fx.load(fx.PE_NAME))


def _elf() -> BinarySource:
    return _bytes(fx.load(fx.ELF_NAME))


def _macho() -> BinarySource:
    return _bytes(fx.load(fx.MACHO_NAME))


# --------------------------------------------------------------------------- #
# binary_format — detects each format.
# --------------------------------------------------------------------------- #


def test_format_pe() -> None:
    assert core.binary_format(_pe()) == "PE"


def test_format_elf() -> None:
    assert core.binary_format(_elf()) == "ELF"


def test_format_macho() -> None:
    assert core.binary_format(_macho()) == "MachO"


# --------------------------------------------------------------------------- #
# machine / entry_point.
# --------------------------------------------------------------------------- #


def test_machine() -> None:
    assert core.machine(_pe()) == "X86_64"
    assert core.machine(_elf()) == "X86_64"
    assert core.machine(_macho()) == "ARM64"


def test_entry_point_positive() -> None:
    for src in (_pe(), _elf(), _macho()):
        ep = core.entry_point(src)
        assert ep is not None and ep > 0


# --------------------------------------------------------------------------- #
# is_signed — PE/ELF unsigned here, Mach-O signed (native cc auto-signs arm64).
# --------------------------------------------------------------------------- #


def test_is_signed() -> None:
    assert core.is_signed(_pe()) is False
    assert core.is_signed(_elf()) is False  # ELF has no embedded code signature
    assert core.is_signed(_macho()) is True


# --------------------------------------------------------------------------- #
# compile_timestamp — PE only, and byte-deterministic in our fixture.
# --------------------------------------------------------------------------- #


def test_compile_timestamp_pe_fixed() -> None:
    assert core.compile_timestamp(_pe()) == fx.PE_FIXED_EPOCH


def test_compile_timestamp_none_for_non_pe() -> None:
    assert core.compile_timestamp(_elf()) is None
    assert core.compile_timestamp(_macho()) is None


# --------------------------------------------------------------------------- #
# imphash — PE only.
# --------------------------------------------------------------------------- #


def test_imphash_pe() -> None:
    value = core.imphash(_pe())
    assert isinstance(value, str) and len(value) == 32  # md5 hex


def test_imphash_none_for_non_pe() -> None:
    assert core.imphash(_elf()) is None
    assert core.imphash(_macho()) is None


# --------------------------------------------------------------------------- #
# section_count / overall_entropy.
# --------------------------------------------------------------------------- #


def test_section_count_positive() -> None:
    for src in (_pe(), _elf(), _macho()):
        n = core.section_count(src)
        assert n is not None and n > 0


def test_overall_entropy_in_range() -> None:
    for src in (_pe(), _elf(), _macho()):
        ent = core.overall_entropy(src)
        assert ent is not None
        assert 0.0 <= ent <= 8.0


def test_entropy_high_on_random_section() -> None:
    # Random bytes should have entropy close to 8 (the packing signal).
    import os

    random_blob = os.urandom(64 * 1024)
    assert core._shannon_entropy(random_blob) > 7.5
    # A run of identical bytes has ~0 entropy.
    assert core._shannon_entropy(b"\x00" * 10_000) < 0.1


# --------------------------------------------------------------------------- #
# sections — rows, entropy bounds, PE flags.
# --------------------------------------------------------------------------- #


def test_sections_rows() -> None:
    rows = core.sections(_pe())
    assert len(rows) > 0
    for _name, vsize, raw, entropy, _flags in rows:
        assert vsize >= 0
        assert raw >= 0
        assert 0.0 <= entropy <= 8.0


def test_sections_pe_has_text_with_code_flag() -> None:
    rows = core.sections(_pe())
    text = next((r for r in rows if r[0] == ".text"), None)
    assert text is not None
    assert "CNT_CODE" in text[4]
    assert "MEM_EXECUTE" in text[4]


def test_sections_non_pe_empty_flags() -> None:
    for src in (_elf(), _macho()):
        rows = core.sections(src)
        assert all(r[4] == "" for r in rows)


# --------------------------------------------------------------------------- #
# imports / exports.
# --------------------------------------------------------------------------- #


def test_imports_pe_grouped_by_dll() -> None:
    rows = core.imports(_pe())
    assert len(rows) > 0
    libs = {r[0] for r in rows}
    assert any(lib.upper().startswith("KERNEL32") for lib in libs)
    # Every PE import row names a library and a function.
    for library, function in rows:
        assert library
        assert function


def test_exports_macho_has_main() -> None:
    rows = core.exports(_macho())
    names = {r[0] for r in rows}
    assert "_main" in names
    for _name, address in rows:
        assert address >= 0


# --------------------------------------------------------------------------- #
# strings — known content, min_len, bounds.
# --------------------------------------------------------------------------- #


def test_strings_finds_known_content() -> None:
    for src in (_pe(), _elf(), _macho()):
        values = [v for _, v in core.strings(src, 5)]
        assert any(fx.KNOWN_STRING in v for v in values)


def test_strings_min_len_respected() -> None:
    rows = core.strings(_pe(), 12)
    assert all(len(v) >= 12 for _, v in rows)
    # Lower threshold yields at least as many strings.
    assert len(core.strings(_pe(), 5)) >= len(rows)


def test_strings_seq_is_1_based_and_dense() -> None:
    rows = core.strings(_pe(), 5)
    assert [r[0] for r in rows] == list(range(1, len(rows) + 1))


def test_strings_bounded() -> None:
    # A huge highly-repetitive blob can't produce unbounded output.
    blob = b"ABCDEFGHIJ" * 5_000_000  # one giant printable run
    rows = core.strings(_bytes(blob), 5)
    assert len(rows) <= core.MAX_STRINGS
    assert all(len(v) <= core.MAX_STRING_LEN for _, v in rows)


# --------------------------------------------------------------------------- #
# hostile / garbage / empty / truncated / non-binary — survive, never crash.
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "data",
    [
        fx.make_garbage_bytes(),
        b"",
        b"MZ\x00\x00 truncated pe",
        b"\x7fELF broken and truncated",
        b"this is just plain text, not a binary at all, nope",
    ],
)
def test_garbage_scalars_return_none(data: bytes) -> None:
    src = _bytes(data)
    assert core.binary_format(src) is None
    assert core.machine(src) is None
    assert core.entry_point(src) is None
    assert core.is_signed(src) is None
    assert core.compile_timestamp(src) is None
    assert core.imphash(src) is None
    assert core.section_count(src) is None
    assert core.overall_entropy(src) is None


@pytest.mark.parametrize(
    "data",
    [fx.make_garbage_bytes(), b"", b"MZ broken", b"\x7fELF broken"],
)
def test_garbage_tables_empty(data: bytes) -> None:
    src = _bytes(data)
    assert core.sections(src) == []
    assert core.imports(src) == []
    assert core.exports(src) == []


def test_garbage_beside_good_binary() -> None:
    # The headline robustness case: a garbage blob is processed (→ None/empty)
    # and a good binary right after it still parses fine.
    bad = _bytes(fx.make_garbage_bytes())
    good = _pe()
    assert core.binary_format(bad) is None
    assert core.binary_format(good) == "PE"
    assert core.section_count(good) is not None


def test_null_source_is_none() -> None:
    assert BinarySource.from_path(None) is None
    assert BinarySource.from_bytes(None) is None


def test_missing_file_path_degrades_to_none() -> None:
    src = BinarySource.from_path("/no/such/binary/here.exe")
    assert src is not None
    assert core.binary_format(src) is None
    assert core.sections(src) == []


def test_oversized_input_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    # A blob above MAX_INPUT_BYTES is refused at read time → read_bytes None.
    # Lower the cap rather than allocate gigabytes.
    monkeypatch.setattr(core, "MAX_INPUT_BYTES", 4)
    src = _bytes(b"way more than four bytes")
    assert src.read_bytes() is None
    assert core.binary_format(src) is None
    assert core.sections(src) == []
