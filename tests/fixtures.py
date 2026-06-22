"""Binary fixtures for the vgi-pe suite.

The unit and SQL suites run against a handful of tiny **real** executables that
are committed under ``test/sql/data/`` — one of each format plus a hostile
garbage blob:

    hello.exe      a real PE32+ (built with mingw, x86-64)
    hello_elf      a real ELF   (built with `zig cc`, x86-64, static)
    hello_macho    a real Mach-O (built with the native `cc`)
    garbage.bin    NOT a binary at all — the hostile-input survival case

The test code reads these committed files (so the suite needs no compiler), via
``load(name)``. The committed fixtures are *produced* by ``regenerate(...)``,
which compiles each format from a tiny C program and -- crucially -- patches the
PE ``TimeDateStamp`` to a fixed epoch and rebuilds with LIEF so the committed PE
is **byte-deterministic** (mingw otherwise embeds the wall-clock build time).
Regeneration needs ``cc``, ``x86_64-w64-mingw32-gcc``, and ``zig``; run
``make fixtures`` (or ``python tests/fixtures.py``) on a machine that has them.
"""

from __future__ import annotations

import pathlib
import subprocess
import tempfile

_DATA_DIR = pathlib.Path(__file__).resolve().parent.parent / "test" / "sql" / "data"

# Fixed epoch baked into the deterministic PE (2023-11-14T22:13:20Z).
PE_FIXED_EPOCH = 1700000000

# A tiny program that links against the C runtime so the PE has a real import
# table (KERNEL32 + the CRT shims) and an imphash worth clustering on.
_HELLO_C = """\
#include <stdio.h>
int main(void) {
    printf("hello from vgi-pe static-analysis fixture\\n");
    return 0;
}
"""

PE_NAME = "hello.exe"
ELF_NAME = "hello_elf"
MACHO_NAME = "hello_macho"
GARBAGE_NAME = "garbage.bin"

# Known content the string extractor should find inside every compiled fixture.
KNOWN_STRING = "hello from vgi-pe static-analysis fixture"


def load(name: str) -> bytes:
    """Read a committed fixture's raw bytes from ``test/sql/data/``."""
    return (_DATA_DIR / name).read_bytes()


def make_garbage_bytes() -> bytes:
    """Not an executable at all — the hostile-input survival case."""
    return b"this is definitely not an executable \x00\x01\x02 %%%% garbage" * 4


# --------------------------------------------------------------------------- #
# Regeneration (compile-time; needs the toolchains). Not run by the test suite.
# --------------------------------------------------------------------------- #


def _compile(args: list[str], *, src: pathlib.Path, out: pathlib.Path) -> bytes:
    subprocess.run([*args, "-o", str(out), str(src)], check=True, capture_output=True)
    return out.read_bytes()


def _build_pe_deterministic(src: pathlib.Path, tmp: pathlib.Path) -> bytes:
    """Build a PE with mingw, then patch TimeDateStamp + rebuild for determinism."""
    import lief

    raw_out = tmp / "hello_raw.exe"
    _compile(["x86_64-w64-mingw32-gcc", "-Os"], src=src, out=raw_out)
    binary = lief.parse(str(raw_out))
    binary.header.time_date_stamps = PE_FIXED_EPOCH
    builder = lief.PE.Builder(binary, lief.PE.Builder.config_t())
    builder.build()
    patched = tmp / "hello_patched.exe"
    builder.write(str(patched))
    return patched.read_bytes()


def regenerate(data_dir: pathlib.Path | None = None) -> None:
    """Compile + write the committed binary fixtures into ``data_dir``.

    Needs ``cc`` (native Mach-O), ``x86_64-w64-mingw32-gcc`` (PE), and ``zig``
    (ELF via ``zig cc``). The PE is made byte-deterministic by patching its
    TimeDateStamp and rebuilding with LIEF.
    """
    out_dir = data_dir or _DATA_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        tmp = pathlib.Path(td)
        src = tmp / "hello.c"
        src.write_text(_HELLO_C)

        macho = _compile(["cc", "-Os"], src=src, out=tmp / "hello_macho")
        elf = _compile(["zig", "cc", "-target", "x86_64-linux-musl", "-Os"], src=src, out=tmp / "hello_elf")
        pe = _build_pe_deterministic(src, tmp)

        (out_dir / MACHO_NAME).write_bytes(macho)
        (out_dir / ELF_NAME).write_bytes(elf)
        (out_dir / PE_NAME).write_bytes(pe)
        (out_dir / GARBAGE_NAME).write_bytes(make_garbage_bytes())


if __name__ == "__main__":
    regenerate()
    print(f"wrote binary fixtures to {_DATA_DIR}")
