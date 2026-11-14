# Executable Binary Triage example

[01 · Read static evidence without turning it into a verdict](01_read_static_evidence_without_a_verdict.ipynb) preserves the comparison of benign PE, ELF and Mach-O bytes, distinguishes file/section entropy and varies printable-string extraction while retaining empty and missing inputs. [Open in Colab](https://colab.research.google.com/github/Query-farm/vgi-pe/blob/main/notebooks/01_read_static_evidence_without_a_verdict.ipynb).

Choose **Runtime → Run all** in Colab. The base-package bootstrap preserves compatible
preloaded libraries and retrieves immutable SHA256-verified companions. Locally,
install [uv](https://docs.astral.sh/uv/) and Git, then run inside `notebooks/`:

```sh
uv sync --locked
uv run --locked vgi-notebooks
uv run --locked vgi-notebooks 01_read_static_evidence_without_a_verdict.ipynb --parameters '{"MIN_STRING_LENGTH":16}' --output-dir artifacts/longer-strings
```

For Jupyter select `.venv/bin/python`. The `[runner]` extra and lock are for local
publication. Overrides require a separate destination; unknown parameters fail and
a failed run cannot replace the last successful default. If old setup replaced
kernel libraries, open the current notebook in a fresh runtime.

## Portable released worker

```sql
INSTALL vgi FROM community;
LOAD vgi;
ATTACH 'pe' (TYPE vgi, LOCATION 'uvx --python 3.13 --from git+https://github.com/Query-farm/vgi-pe@v0.4.0 vgi-pe-worker');
```

The published Python v0.4.0 tag owns its dependencies. This short command was
verified through Haybarn 2.0.0rc11 without the older notebook's transitive overrides.
Validation resolved vgi-python 0.51.1, vgi-rpc 0.53.1, PyArrow 26.0.1 and LIEF 1.0.0.
The worker runs in its own cached Python 3.13 environment; notebook libraries remain
separate. Initial package/Git/extension/companion retrieval needs internet and
compatible LIEF/PyArrow wheels. No local worker checkout, compiler, credentials,
remote data service or binary execution is required. The tested platform is macOS
arm64; other platforms were not executed. Upgrade the tag only after rechecking
catalogs, defaults and the experiment.

The [shared v0.3.23 standard](https://github.com/Query-farm/vgi-example-notebooks/blob/v0.3.23/docs/standard.md)
provides catalog title/subtitle, branding, isolated SQL secrets, SVG presentation
and runner protections. Keep `charts/` beside the saved notebook for GitHub image
links; interactive runs retain native SVG. PNG review artifacts, logs and experiment
copies remain ignored. Hosted Colab was not manually operated; validation uses a
fresh compatible kernel with eight libraries imported before the visible bootstrap.

## Scope and coverage

The complete actual catalogs contain **13 public named surfaces**: eight scalars,
four table functions and the `analyses` reference table. Path and BLOB overloads
count once. This focused story meaningfully covers **9/13**, exceeding the required
7: `binary_format`, `machine`, `is_signed`, `compile_timestamp`, `imphash`,
`overall_entropy`, `section_count`, `sections` and `strings`.

`entry_point`, `imports`, `exports` and `analyses` remain uncovered. Listing the
reference table for discovery does not count as meaningful coverage. Full argument
and table-return schemas, release/current snapshots, reviewed mappings and execution
receipts are bound in `coverage.json` and `coverage/`.

The notebook executes v0.4.0. Current public source has matching interfaces but
normalizes section entropy from `-0.0` to `+0.0`, alongside metadata/example changes.
Those values are numerically equal, but formatted output need not be identical.
Current-compatible mappings do not claim a separately executed current-main notebook.
Existing green [source CI](https://github.com/Query-farm/vgi-pe/actions/runs/43581576906)
is reused; worker source/root dependencies are unchanged by this update. No rebuild,
full-suite repetition, source/container CI dispatch or new worker release is required.

## Unchanged benign inputs

Four fixture files are unchanged copies of [test/sql/data at f8fa94d](https://github.com/Query-farm/vgi-pe/tree/f8fa94d52c8aba2020cd2f631425fd07d16f0a17/test/sql/data).
Their original generator compiles a tiny C hello-world program as PE, ELF and Mach-O
and authors a text/garbage input. The PE header timestamp is deliberately fixed.
Compiler/toolchain variations can change binaries, so the committed byte images
and hashes are the reproducible inputs. `empty.bin` is an authored zero-byte file;
SQL adds a missing record. The original `fixtures/manifest.json` is unchanged and
setup verifies every SHA256. The MIT worker license is bundled.

No sample is executed, loaded as a library or used to resolve an import. These
benign examples are not malware samples, an incident collection or a detection
benchmark. Hash verification identifies fixture bytes; it does not establish a
forensic chain of custody.

## Interpreting the experiment

File entropy and section entropy use different byte populations. Headers, padding
and layout affect file entropy; the highest section entropy is neither a file
average nor a malware score. The worker reports NULL file entropy for unrecognized
text, although that text has a mathematically computable byte entropy. The notebook
independently recomputes whole-file Shannon entropy for all three recognized binaries.

`is_signed` reports signature presence, not cryptographic validation or trusted
signer status. ELF returns false under this worker's embedded-signature convention.
The PE timestamp is header metadata, not proof of actual build time. The PE import
hash is distinct from the SHA256 of complete file bytes. PE section characteristics
are not a cross-format permission inventory. Missing and empty inputs remain distinct.

`strings` extracts printable ASCII and UTF-16LE runs without requiring recognized
binary format. Its `seq` is a one-based result index, not a byte offset or a stable
identifier across minimum lengths. Rows may repeat strings; encoding and source
offset are not returned. A string does not prove execution, network contact or use
by code.

The fixed eight-character baseline is compared with the selected extraction using
multiset equality, preserving duplicate counts. These fixtures stay below the
release caps of 100,000 runs and 1,024 characters per run; the equivalence is not
promised for capped inputs. The chart uses a symmetric-log count axis with a linear
region from zero to one, retaining all six input records.

At minimum **8→16**, total selected runs change **2,122→932**: PE 2,087→921,
ELF 18→3, Mach-O 12→4, unrecognized text 5→4, empty/missing 0→0. Original bytes,
file/section evidence and known hello-world text remain unchanged. A smaller output
is an extraction choice, not evidence that a binary became safer.

Validation includes the default and detached minimum-16 run, two default SVGs and
both experiment figures, 12 SQL checks, printable-run reconciliation, three independent
entropy calculations, runner preservation guards and one fresh preloaded bootstrap.
