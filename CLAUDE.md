# CLAUDE.md — vgi-pe

Contributor/agent notes. User-facing docs live in `README.md`; this is the
"how it's built and where the sharp edges are" companion.

## What this is

A [VGI](https://query.farm) worker doing **static analysis of executable
binaries** (PE / ELF / Mach-O) as DuckDB functions — a defensive
**malware-triage** tool. Backed by `lief` (Apache-2.0), one cross-format parser.
`pe_worker.py` assembles every function into one `pe` catalog (single `main`
schema) over stdio. Sibling style/tooling to `vgi-pdf` (the other binary-input,
path-or-bytes worker) and `vgi-conform`.

## Layout

```
pe_worker.py           repo-root stdio entry point; PEP 723 inline deps; main()
vgi_pe/
  core.py              pure parse/extraction logic over lief; no Arrow/VGI; total + crash-proof
  scalars.py           per-row scalars (path/bytes overloads): binary_format, is_signed, ...
  tables.py            table functions (path/bytes overloads): sections, imports, exports, strings
  schema_utils.py      pa.Field comment / column-doc helper
tests/                 pytest: test_core (pure), test_tables (in-proc), test_scalars (Client RPC)
  fixtures.py          loads committed real binaries; regenerate() compiles them
test/sql/*.test        haybarn-unittest sqllogictest — authoritative E2E
test/sql/data/         committed tiny real binaries (PE/ELF/Mach-O) + garbage.bin
Makefile               test / test-unit / test-sql / lint / fixtures
```

To add a function: implement it in `core.py` (pure, total — never raises;
returns `None` / `[]` for "can't"), wrap it as a scalar (`scalars.py`) or table
function (`tables.py`) with a **path** and a **bytes** overload sharing one
`Meta.name`, then register both in the module's `*_FUNCTIONS` list.

## Scalars vs table functions — THE core convention (read first)

The VGI SDK makes **scalar functions positional-only**: `name := value` named
args are rejected for scalars and only work on table functions.

- **Per-row functions are scalars.** Each takes its binary argument as *either*
  a `VARCHAR` path or a `BLOB` of bytes — two distinct DuckDB signatures, so each
  is its own `ScalarFunction` subclass sharing the `Meta.name` (a `*PathFunction`
  typed `pa.string()` and a `*BytesFunction` typed `pa.binary()`). Same path/bytes
  overload split that `vgi-pdf` uses.
- **Set-returning functions are table functions** (`sections`, `imports`,
  `exports`, `strings`) — same path/bytes overload, and `strings` additionally
  takes the optional `min_len :=` named arg (a table-function-only feature).

Don't build the overload classes from a factory: a nested `class Meta:` body
cannot reference an enclosing-scope variable (the class body is not a closure),
so each overload is written out explicitly. Verbose but boringly correct.

## STRUCT/MAP/LIST returns need an explicit arrow_type

Any non-primitive return (and, here, even the primitives, for clarity) declares
`Returns(arrow_type=...)`; the SDK raises otherwise. `compile_timestamp` returns
`pa.timestamp("us")` (PE TimeDateStamp is seconds → scaled to microseconds);
`entry_point` and `exports.address` are `pa.uint64()` (UBIGINT). Table schemas
are built once as module-level `pa.schema([...])` with `field(...)` comments.

## Sharp edges (learned the hard way)

1. **`haybarn-unittest` skips `require vgi`.** Under haybarn the extension is not
   autoloaded for `require`, so a `.test` using `require vgi` is silently
   SKIPPED. Use an explicit `statement ok` / `LOAD vgi;` instead (every `.test`
   here does).
2. **Hostile input must never crash the worker.** Binaries are untrusted malware
   samples *by definition*. `core.parse` is total: it returns a LIEF object or
   `None` and never raises. Every extractor wraps its work in `try/except` →
   `None` (scalars → NULL) / `[]` (tables → no rows). A garbage blob beside a
   good one must leave the worker alive — `test/sql/hostile.test` asserts exactly
   that (garbage → NULL/no rows, then a good binary still answers). We also
   `lief.logging.disable()` so a malformed sample can't spam stderr.
3. **Static analysis only.** We **never execute** the binary and never resolve an
   external reference. Only the bytes handed in (or the local path handed in) are
   read.
4. **Bounds.** `MAX_INPUT_BYTES` (512 MiB) refuses absurd blobs before parsing;
   `strings` caps `MAX_STRINGS` and `MAX_STRING_LEN`; table extractors cap
   `MAX_ROWS`. A "bomb" input can't exhaust memory or run unbounded.
5. **Format-specific vs abstract.** `machine` uses LIEF's *abstract*
   architecture so all three formats report comparably. `imphash` /
   `compile_timestamp` are PE-only (NULL otherwise). `is_signed` is PE
   `has_signatures` / Mach-O `has_code_signature` / ELF `false` (absence is a
   *successful* answer, not a failure). `overall_entropy` is computed over the
   raw file bytes (independent of LIEF's section layout), but still returns NULL
   for non-binary input so a random text blob isn't given a misleading number.
6. **The unit suite can pass while the RPC path is broken.** `test_core.py` calls
   pure functions directly; only `test_scalars.py` (real `vgi.client.Client`
   subprocess) and `test/sql/*.test` (real `ATTACH`+`SELECT`) exercise the wire.
   **Run the SQL suite** — it's authoritative.

## Fixtures (real binaries, byte-deterministic PE)

`tests/fixtures.py` `load(name)` reads tiny **real** executables committed under
`test/sql/data/`: `hello.exe` (PE32+, mingw), `hello_elf` (ELF, `zig cc`),
`hello_macho` (Mach-O, native `cc`), `garbage.bin`. `regenerate()` (`make
fixtures`) compiles each from one tiny C program and patches the PE
`TimeDateStamp` to `PE_FIXED_EPOCH` + rebuilds with LIEF so the committed PE is
**byte-deterministic** (mingw otherwise bakes in the wall-clock build time). The
test code only *reads* the committed files, so the suite needs no compiler.
Determinism caveat: the Mach-O is whatever the build host emits (entropy/section
assertions use ranges/tolerance, not exact bytes).

## LIEF is Apache-2.0 (licensing note)

`lief` is **Apache-2.0** — permissive, no copyleft. Used as an ordinary,
unmodified, separately pip-installed dependency. **vgi-pe's own code stays MIT**
and is fine for commercial use.

## Testing

```sh
uv run pytest -q              # unit: pure core + in-proc tables + Client RPC scalars
make test-sql                 # E2E: haybarn-unittest over test/sql/*  (authoritative)
make test                     # both
uv run ruff check . && uv run mypy vgi_pe/
```

Everything is pure/offline (no network, no execution), so the suite is fast and
hermetic.
