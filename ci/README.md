# CI: the vgi-pe worker integration suite

[`.github/workflows/ci.yml`](../.github/workflows/ci.yml) runs the unit tests
and this repo's sqllogictest suite (`test/sql/*.test`) against the vgi-pe
VGI worker through the **real DuckDB `vgi` extension** on every push / PR.

## How it works (no C++ build)

Rather than building the vgi DuckDB extension from source, CI drives a
**prebuilt** standalone `haybarn-unittest` (the DuckDB/Haybarn sqllogictest
runner, published in Haybarn's releases) and installs the **signed** `vgi`
extension from the Haybarn community channel:

1. **Install the worker** — `uv sync --frozen` into a venv. `pe_worker.py`
   is a self-contained PEP 723 stdio worker the extension can spawn via
   `uv run pe_worker.py`.
2. **Download the runner** — the matching `haybarn_unittest-*` asset per
   platform from the latest Haybarn release.
3. **Preprocess** — the standalone runner links none of the extensions the
   tests gate on, so [`preprocess-require.awk`](preprocess-require.awk) rewrites
   each `require <ext>` into an explicit signed `INSTALL <ext> FROM
   {community,core}; LOAD <ext>;`. These tests skip `require vgi` (haybarn
   silently SKIPs it) and `LOAD vgi;` directly, so the awk also injects an
   `INSTALL vgi FROM community;` right before each bare `LOAD vgi;`. `require-env`
   and everything else pass through untouched.
4. **Run** — [`run-integration.sh`](run-integration.sh) stages the preprocessed
   tree (and the committed `test/sql/data/` fixtures), resolves
   `VGI_PE_WORKER` per transport, warms the extension cache once, then runs the
   suite in a single `haybarn-unittest` invocation. Any failed assertion exits
   non-zero and fails the job.

## Three transports

The same suite runs over every VGI transport, selected by the `TRANSPORT` env
var (the vgi extension picks the transport from the ATTACH `LOCATION` string):

| `TRANSPORT`  | `VGI_PE_WORKER` (LOCATION)   | How the worker is reached                         |
| ------------ | --------------------------- | ------------------------------------------------- |
| `subprocess` | `uv run pe_worker.py`       | extension spawns it over stdin/stdout (default)   |
| `http`       | `http://127.0.0.1:<port>`   | script boots `… --http --port 0 --port-file <f>`  |
| `unix`       | `unix://<sock>`             | script boots `… --unix <sock>`                    |

For `http`/`unix` the script boots the worker out-of-band with `cwd` = the stage
dir so the relative `test/sql/data/*` fixture paths resolve, polls for the
port-file / socket (bailing if the process dies), and trap-kills it on exit.

Two transport-specific notes baked into the script:

- **`http` needs `httpfs`.** The vgi HTTP transport rides DuckDB's httpfs, so the
  script injects `INSTALL httpfs FROM core; LOAD httpfs;` after each `LOAD vgi;`
  for the http leg only. Without it `ATTACH 'http://…'` throws "VGI HTTP
  transport requires the httpfs extension".
- **Silent-skip guard.** The sqllogictest runner SKIPS (exit 0!) any test whose
  error contains "HTTP"/"Unable to connect", so a broken http/unix setup would
  fake-pass as "All tests were skipped". The run step captures the log and fails
  the leg if nothing actually ran.

The `http` transport needs the `http` extra (waitress): the main dependency pins
`vgi-python[http]` (so `uv run` resolves it from the PEP 723 header) and CI
installs it explicitly with `uv sync --frozen --extra http`.

## Run it locally

```bash
uv sync --python 3.13 --extra http          # install the worker + deps (+ waitress)
# point HAYBARN_UNITTEST at a haybarn-unittest binary (or a local DuckDB
# `unittest` built with the vgi extension); pick a transport (default subprocess):
HAYBARN_UNITTEST=/path/to/haybarn-unittest \
WORKER_CMD="uv run --no-sync --python 3.13 $PWD/pe_worker.py" \
TRANSPORT=http \
  ci/run-integration.sh
```

Or use the Makefile target `make test-sql`, which installs `haybarn-unittest`
as a uv tool and points the worker at `uv run --python 3.13 pe_worker.py`
(subprocess transport).
