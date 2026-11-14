# VGI PE notebooks

[01 · Read static evidence without turning it into a verdict](01_read_static_evidence_without_a_verdict.ipynb) compares file/section entropy across benign PE, ELF and Mach-O fixtures, preserves unknown and missing inputs, and demonstrates how printable-string minimum length changes extraction while the original bytes stay fixed.

## Run

Install [uv](https://docs.astral.sh/uv/) and Git. From the repository root:

```sh
uv sync --project notebooks --frozen
uv run --project notebooks --frozen python notebooks/execute.py
```

The full `notebooks/` directory also runs independently:

```sh
cd notebooks
uv sync --frozen
uv run --frozen python execute.py
```

Initial setup downloads Python packages, the VGI community extension and a pinned public Git worker. Compatible Python 3.14 LIEF/PyArrow wheels are needed. The tested platform is macOS Apple silicon. No compiler, local worker source/build, credentials or remote data service is required. All subsequent analysis reads committed fixture bytes; no sample is executed, loaded as a library or used to resolve an import.

In VS Code select `notebooks/.venv/bin/python` and use `notebooks/` as the working directory. Other Jupyter editors can register it:

```sh
uv run --project notebooks --frozen python -m ipykernel install --user --name vgi-pe-notebooks --display-name 'Python (vgi-pe notebooks)'
```

Restart and run all after changing the parameter. Visible SQL includes the complete connection, BLOB scalar calls and constant-path table-function calls. Imports, plotting, generated interpretation, assertions and cleanup source are folded; both embedded charts remain visible.

## Experiment

```sh
uv run --project notebooks --frozen python notebooks/execute.py \
  --parameters '{"MIN_STRING_LENGTH":16}' \
  --output-dir notebooks/validation/longer-strings
```

The default is 8. Raising it to 16 reduces the selected printable runs from 2,122 to 932, while file/section evidence stays fixed. The three executables still contain the known hello-world string; the unrecognized text fixture still yields printable runs. Reset to 8 for the saved default. Integers from 8 through 64 are supported.

Overrides require a separate destination. The runner rejects unknown parameter names and writes only after a successful complete execution, preserving previous saved outputs on failure. Experiment copies include relative assets, fixtures, helpers, documentation and environment files. Logs, chart review files and experimental copies are ignored by Git.

## Portable worker and inputs

The literal visible `ATTACH` runs:

```text
uvx --python 3.14 --with vgi-python==0.51.0 --with vgi-rpc==0.53.1 --with pyarrow==26.0.1 --with lief==1.0.0 --from git+https://github.com/Query-farm/vgi-pe@473ecf09bded3b87ee672aab3bf36903d635563d vgi-pe-worker
```

That immutable public revision is v0.4.0. The worker runs in its own cached uv environment; the notebook separately pins Haybarn 2.0.0rc11 and presentation packages. Upgrading means changing the explicit revision/dependency pins and rerunning both settings. The published release can display a constant section's entropy as `-0.0`; numerically it is zero. Later source normalization does not alter this pinned worker.

Four fixture files are unchanged copies from [test/sql/data at f8fa94d](https://github.com/Query-farm/vgi-pe/tree/f8fa94d52c8aba2020cd2f631425fd07d16f0a17/test/sql/data). Their [original generator](https://github.com/Query-farm/vgi-pe/blob/f8fa94d52c8aba2020cd2f631425fd07d16f0a17/tests/fixtures.py) compiles a tiny C hello-world program as PE, ELF and Mach-O and authors the text/garbage input. The PE header timestamp is deliberately fixed. Compiler/toolchain variations can change generated binaries, so the committed bytes and hashes are the reproducible inputs here. `empty.bin` is an authored zero-byte file; SQL adds a missing row. `fixtures/manifest.json` records provenance and SHA-256 hashes. There are no malware samples or private data.

## Interpretation

The file entropy and section entropy populations differ. Headers, padding and layout affect the file metric; a section maximum is neither a file average nor a malware score. The worker reports NULL file entropy when it does not recognize a binary, even though readable non-binary text has a mathematically computable entropy. The notebook independently recomputes whole-file entropy for all three recognized binaries.

`is_signed` reports signature presence, not signature validation or trusted signer status. For ELF it returns false under this worker's embedded-signature convention. A PE timestamp is file metadata, not proof of build time; the import hash is distinct from the SHA-256 of complete file bytes. PE section flags are not a cross-format permissions inventory.

Printable ASCII and UTF-16LE runs can be extracted without successful binary parsing. `seq` is a one-based output index, not a source byte offset or a stable ID across minimum lengths. Returned rows can contain duplicate strings, and the table does not expose encoding or source offset. Presence of a string does not prove execution, network contact or use of that string by code.

The fixed eight-character baseline is compared with the actual worker's chosen-minimum extraction using a multiset equality check, preserving duplicate counts. These small fixtures remain below the pinned source's caps of 100,000 runs and 1,024 characters per run; inputs hitting the caps may not retain that equivalence. The count chart uses a symmetric-log scale with a linear region from zero to one so all six input records remain visible.

Selected counts at 8→16 are: PE 2,087→921; ELF 18→3; Mach-O 12→4; unrecognized text 5→4; empty and missing 0→0. The smaller result is an extraction choice, not evidence that the binaries became safer or changed.

## Validation

The default completed in 19.1 seconds; the detached minimum-16 run completed in 42.1 seconds. Both passed 12 SQL checks, printable-run reconciliation and independent whole-file entropy calculations for the three recognized binaries. Four charts and three runner preservation guards were reviewed. File/section displays and the entropy chart are identical across settings; all five fixture hashes match the manifest, and the original four fixture files match repository source.

Source validation passed 56 pytest tests, 47 stdio / 53 HTTP / 47 Unix SQL assertions (three cases each), Ruff/format/mypy and the repository CI’s isolated `uvx pydoclint` check. Executed metadata/AI validation passed at 94/100 L3 with zero findings. Notebook Ruff and structural review passed. Original source, tests, committed binaries, root project manifest and lockfile remain unchanged.

Official Query.Farm Strata Sun and VGI artwork is unchanged, with linked Query.Farm branding at the top and final bottom.
