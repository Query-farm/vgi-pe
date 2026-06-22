"""End-to-end tests for the per-row scalar pe functions.

These spawn ``pe_worker.py`` as a subprocess via ``vgi.client.Client`` and call
each scalar exactly as DuckDB would after ``ATTACH``, exercising the polymorphic
``binary`` input (a VARCHAR path or a BLOB of bytes). This is the authoritative
wire-level check that complements the SQL suite.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pyarrow as pa
import pytest
from vgi import Arguments
from vgi.client import Client

from . import fixtures as fx

_WORKER = str(Path(__file__).resolve().parent.parent / "pe_worker.py")
_DATA = Path(__file__).resolve().parent.parent / "test" / "sql" / "data"


@pytest.fixture(scope="module")
def client() -> Iterator[Client]:
    # worker_limit=1 so output order matches input order for deterministic
    # per-row assertions.
    with Client(f"{sys.executable} {_WORKER}", worker_limit=1) as c:
        yield c


def _scalar_bytes(client: Client, name: str, blobs: list[bytes | None]) -> list:
    batch = pa.RecordBatch.from_pydict({"binary": pa.array(blobs, type=pa.binary())})
    results = list(
        client.scalar_function(
            function_name=name,
            input=iter([batch]),
            arguments=Arguments(positional=[]),
        )
    )
    return results[0]["result"].to_pylist()


def _scalar_paths(client: Client, name: str, paths: list[str | None]) -> list:
    batch = pa.RecordBatch.from_pydict({"binary": pa.array(paths, type=pa.string())})
    results = list(
        client.scalar_function(
            function_name=name,
            input=iter([batch]),
            arguments=Arguments(positional=[]),
        )
    )
    return results[0]["result"].to_pylist()


class TestBinaryFormat:
    def test_bytes(self, client: Client) -> None:
        blobs = [
            fx.load(fx.PE_NAME),
            fx.load(fx.ELF_NAME),
            fx.load(fx.MACHO_NAME),
            None,
            fx.make_garbage_bytes(),
        ]
        out = _scalar_bytes(client, "binary_format", blobs)
        assert out == ["PE", "ELF", "MachO", None, None]


class TestIsSigned:
    def test_bytes(self, client: Client) -> None:
        out = _scalar_bytes(
            client,
            "is_signed",
            [fx.load(fx.PE_NAME), fx.load(fx.MACHO_NAME), None, fx.make_garbage_bytes()],
        )
        assert out == [False, True, None, None]


class TestMachine:
    def test_bytes(self, client: Client) -> None:
        out = _scalar_bytes(client, "machine", [fx.load(fx.PE_NAME), fx.load(fx.MACHO_NAME)])
        assert out == ["X86_64", "ARM64"]


class TestEntryPoint:
    def test_bytes(self, client: Client) -> None:
        out = _scalar_bytes(client, "entry_point", [fx.load(fx.PE_NAME), None])
        assert out[0] is not None and out[0] > 0
        assert out[1] is None


class TestImphash:
    def test_bytes(self, client: Client) -> None:
        out = _scalar_bytes(client, "imphash", [fx.load(fx.PE_NAME), fx.load(fx.ELF_NAME), None])
        assert isinstance(out[0], str) and len(out[0]) == 32
        assert out[1] is None  # ELF has no imphash
        assert out[2] is None


class TestCompileTimestamp:
    def test_bytes(self, client: Client) -> None:
        import datetime

        out = _scalar_bytes(client, "compile_timestamp", [fx.load(fx.PE_NAME), fx.load(fx.ELF_NAME)])
        assert isinstance(out[0], datetime.datetime)
        assert int(out[0].replace(tzinfo=datetime.UTC).timestamp()) == fx.PE_FIXED_EPOCH
        assert out[1] is None  # ELF has no compile timestamp


class TestSectionCount:
    def test_bytes(self, client: Client) -> None:
        out = _scalar_bytes(client, "section_count", [fx.load(fx.PE_NAME), None, fx.make_garbage_bytes()])
        assert out[0] is not None and out[0] > 0
        assert out[1] is None
        assert out[2] is None


class TestOverallEntropy:
    def test_bytes(self, client: Client) -> None:
        out = _scalar_bytes(client, "overall_entropy", [fx.load(fx.PE_NAME), fx.make_garbage_bytes()])
        assert out[0] is not None and 0.0 <= out[0] <= 8.0
        assert out[1] is None  # garbage is not a binary → NULL


class TestPathInput:
    """The VARCHAR-path overload, over the committed fixtures on disk."""

    def test_format_path(self, client: Client) -> None:
        out = _scalar_paths(
            client,
            "binary_format",
            [str(_DATA / fx.PE_NAME), str(_DATA / fx.ELF_NAME), str(_DATA / "does_not_exist")],
        )
        assert out == ["PE", "ELF", None]
