"""In-process tests for the pe table functions (sections, imports, exports, strings).

Drives each table function through the real bind -> init -> process lifecycle
in-process (no worker subprocess), passing the polymorphic ``binary`` argument
as BLOB bytes and exercising the optional ``min_len`` named filter on ``strings``.
"""

from __future__ import annotations

import pyarrow as pa

from vgi_pe.tables import (
    ExportsBytesFunction,
    ImportsBytesFunction,
    SectionsBytesFunction,
    StringsBytesFunction,
)

from . import fixtures as fx
from .harness import invoke_table_function


def _blob(data: bytes) -> pa.Scalar:
    return pa.scalar(data, type=pa.binary())


class TestSections:
    def test_columns_and_rows(self) -> None:
        table = invoke_table_function(SectionsBytesFunction, positional=(_blob(fx.load(fx.PE_NAME)),))
        assert table.column_names == ["name", "virtual_size", "raw_size", "entropy", "characteristics"]
        assert table.num_rows > 0

    def test_entropy_in_range(self) -> None:
        table = invoke_table_function(SectionsBytesFunction, positional=(_blob(fx.load(fx.PE_NAME)),))
        for ent in table.column("entropy").to_pylist():
            assert 0.0 <= ent <= 8.0

    def test_pe_text_has_code_flag(self) -> None:
        table = invoke_table_function(SectionsBytesFunction, positional=(_blob(fx.load(fx.PE_NAME)),))
        rows = {r["name"]: r["characteristics"] for r in table.to_pylist()}
        assert "CNT_CODE" in rows[".text"]

    def test_null_no_rows(self) -> None:
        table = invoke_table_function(SectionsBytesFunction, positional=(pa.scalar(None, type=pa.binary()),))
        assert table.num_rows == 0

    def test_garbage_no_rows(self) -> None:
        table = invoke_table_function(SectionsBytesFunction, positional=(_blob(fx.make_garbage_bytes()),))
        assert table.num_rows == 0


class TestImports:
    def test_pe_imports(self) -> None:
        table = invoke_table_function(ImportsBytesFunction, positional=(_blob(fx.load(fx.PE_NAME)),))
        assert table.column_names == ["library", "function"]
        libs = set(table.column("library").to_pylist())
        assert any(lib.upper().startswith("KERNEL32") for lib in libs)

    def test_garbage_no_rows(self) -> None:
        table = invoke_table_function(ImportsBytesFunction, positional=(_blob(fx.make_garbage_bytes()),))
        assert table.num_rows == 0


class TestExports:
    def test_macho_exports(self) -> None:
        table = invoke_table_function(ExportsBytesFunction, positional=(_blob(fx.load(fx.MACHO_NAME)),))
        assert table.column_names == ["name", "address"]
        assert "_main" in table.column("name").to_pylist()


class TestStrings:
    def test_finds_known_string(self) -> None:
        table = invoke_table_function(StringsBytesFunction, positional=(_blob(fx.load(fx.PE_NAME)),))
        assert table.column_names == ["seq", "value"]
        values = table.column("value").to_pylist()
        assert any(fx.KNOWN_STRING in v for v in values)

    def test_min_len_named_arg(self) -> None:
        table = invoke_table_function(
            StringsBytesFunction,
            positional=(_blob(fx.load(fx.PE_NAME)),),
            named={"min_len": pa.scalar(20, type=pa.int32())},
        )
        assert all(len(v) >= 20 for v in table.column("value").to_pylist())

    def test_null_no_rows(self) -> None:
        table = invoke_table_function(StringsBytesFunction, positional=(pa.scalar(None, type=pa.binary()),))
        assert table.num_rows == 0
