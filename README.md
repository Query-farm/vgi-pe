# vgi-pe

Static analysis of executable binaries — **PE, ELF, and Mach-O** — as DuckDB SQL
functions, served by a [VGI](https://query.farm) worker. A defensive
**malware-triage** tool: it parses an untrusted executable image and reports
static signals (format, architecture, entry point, code signing, build
timestamp, sections + per-section entropy, imports, exports, printable strings)
without ever executing the binary.

Backed by [LIEF](https://lief.re) (Apache-2.0), one permissive cross-format
parser for PE / ELF / Mach-O.

```sql
INSTALL vgi FROM community; LOAD vgi;
ATTACH 'pe' (TYPE vgi, LOCATION 'uv run pe_worker.py');

SELECT pe.binary_format('sample.exe');            -- 'PE' | 'ELF' | 'MachO' | NULL
SELECT pe.machine('sample.exe');                  -- 'X86_64', 'ARM64', ...
SELECT pe.is_signed('sample.exe');                -- Authenticode / Mach-O code signature
SELECT pe.imphash('sample.exe');                  -- PE import hash (clustering)
SELECT pe.overall_entropy('sample.exe');          -- 0-8; high => packed/encrypted

SELECT * FROM pe.sections('sample.exe') ORDER BY name;   -- per-section entropy + flags
SELECT * FROM pe.imports('sample.exe');                  -- imported symbols
SELECT * FROM pe.exports('sample.so');                   -- exported symbols
SELECT * FROM pe.strings('sample.exe', min_len := 8);    -- printable strings
```

## Function surface

Every function accepts its binary argument as **either** a `VARCHAR` filesystem
path the worker opens **or** a `BLOB` of the raw bytes.

### Scalars (one binary in, one value out)

| Function | Returns | Notes |
|---|---|---|
| `binary_format(binary)` | `VARCHAR` | `'PE'` / `'ELF'` / `'MachO'`, else NULL |
| `is_signed(binary)` | `BOOLEAN` | PE Authenticode / Mach-O code signature present (ELF → `false`) |
| `entry_point(binary)` | `UBIGINT` | entry-point virtual address |
| `machine(binary)` | `VARCHAR` | architecture, e.g. `'X86_64'`, `'ARM64'` |
| `compile_timestamp(binary)` | `TIMESTAMP` | PE `TimeDateStamp`; NULL for ELF/Mach-O |
| `section_count(binary)` | `INT` | number of sections |
| `overall_entropy(binary)` | `DOUBLE` | whole-file Shannon entropy in `[0, 8]` |
| `imphash(binary)` | `VARCHAR` | PE import hash for clustering; NULL otherwise |

### Table functions (one binary in, many rows out)

| Function | Columns |
|---|---|
| `sections(binary)` | `name, virtual_size, raw_size, entropy, characteristics` |
| `imports(binary)` | `library, function` |
| `exports(binary)` | `name, address` |
| `strings(binary, min_len := 5)` | `seq, value` |

`characteristics` is a comma-joined PE section-flag string (e.g.
`CNT_CODE,MEM_EXECUTE,MEM_READ`) and is empty for ELF / Mach-O. For ELF / Mach-O
`imports`, `library` is empty and `function` is each imported symbol name; for
PE, `library` is the DLL and `function` is the symbol (or `ordinal#N`).

## Untrusted input — the whole point

Every sample is presumed to be untrusted, possibly hostile, possibly malware.
The worker **only reads and describes** the bytes; it **never executes** the
binary and never resolves any external reference (no loading imported libraries,
no following anything but the bytes handed to it).

Robustness contract:

- A **malformed / truncated / non-binary** input degrades to **NULL** (scalars)
  or **no rows** (table functions) — never a crash, never an error, never a
  hang. Hostile input is the expected case, not an exceptional one.
- **NULL** input → NULL / no rows.
- Work is **bounded**: inputs above `MAX_INPUT_BYTES` (512 MiB) are refused, and
  the `strings` extractor caps both the number of strings and each string's
  length.

## Fixtures

The suite runs against a few tiny **real** executables committed under
`test/sql/data/` — `hello.exe` (PE32+, mingw), `hello_elf` (ELF, `zig cc`),
`hello_macho` (Mach-O, native `cc`), and `garbage.bin` (the hostile case). They
are produced by `tests/fixtures.py` (`make fixtures`), which compiles a tiny C
program for each target and patches the PE `TimeDateStamp` to a fixed epoch +
rebuilds with LIEF so the committed PE is byte-deterministic. The test code only
*reads* the committed files, so running the suite needs no compiler.

## Development

```sh
uv sync --extra dev
uv run pytest -q          # unit: pure core + Client RPC scalars + in-proc tables
make test-sql             # E2E: haybarn-unittest over test/sql/*  (authoritative)
make test                 # both
uv run ruff check . && uv run mypy vgi_pe/
```

## Licensing

`vgi-pe`'s own code is **MIT**. It depends on **LIEF** (the `lief` PyPI wheel),
which is **Apache-2.0** — a permissive license with no copyleft obligation, used
as an ordinary, unmodified, separately-installed dependency. Everything is pure
and offline (no network), so the suite is fast and hermetic.
