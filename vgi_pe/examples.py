"""Composed example queries shared across object- and schema-level metadata.

Each example combines two or more of the worker's own functions in one query a
triage analyst would actually write (a folder-wide scalar pass, a table function
filtered by a scalar baseline, a corpus clustered by one scalar and summarized by
another). Every SQL string is defined once here and referenced from the driving
object's ``vgi.example_queries`` / ``Meta.examples`` and from the schema-level
``vgi.example_queries`` list, so the copies can never drift apart.

All of them read the committed fixtures under ``test/sql/data/`` by relative path
(DuckDB's and the worker's cwd is the repo root), are offline, and are
deterministic.
"""

from __future__ import annotations

_PE_FIXTURE = "test/sql/data/hello.exe"
_FIXTURE_GLOB = "test/sql/data/*"

# binary_format + machine + is_signed + section_count + overall_entropy over every
# file of a folder (BLOB overloads fed by DuckDB's read_blob).
CORPUS_TRIAGE: dict[str, str] = {
    "description": (
        "Triage every file in a folder in one pass: container format, CPU architecture, "
        "code-signing, section count and whole-file entropy per file (a non-executable such as "
        "garbage.bin comes back all-NULL instead of failing the query)."
    ),
    "sql": (
        "SELECT filename, pe.main.binary_format(content) AS container, pe.main.machine(content) AS arch, "
        "pe.main.is_signed(content) AS signed, pe.main.section_count(content) AS n_sections, "
        "round(pe.main.overall_entropy(content), 2) AS file_entropy "
        f"FROM read_blob('{_FIXTURE_GLOB}') ORDER BY filename"
    ),
}

# sections (table) filtered against overall_entropy (scalar) of the same file.
SECTIONS_ABOVE_FILE_ENTROPY: dict[str, str] = {
    "description": (
        "Localize the densest content of a sample: the sections whose entropy exceeds the file's "
        "own whole-file entropy (for hello.exe, `.text` and the `/19` debug section at ~5.9-6.0 "
        "bits/byte against a 5.44 baseline)."
    ),
    "sql": (
        f"WITH baseline AS (SELECT pe.main.overall_entropy('{_PE_FIXTURE}') AS file_entropy) "
        "SELECT s.name, round(s.entropy, 3) AS entropy, round(b.file_entropy, 3) AS file_entropy "
        f"FROM pe.main.sections('{_PE_FIXTURE}') AS s, baseline AS b "
        "WHERE s.entropy > b.file_entropy ORDER BY s.entropy DESC"
    ),
}

# imphash (cluster key) + compile_timestamp (build-time span) over a folder.
IMPHASH_CLUSTERS: dict[str, str] = {
    "description": (
        "Cluster a folder of PE samples by import hash and show each cluster's size, build-time "
        "span and member files (non-PE files have no imphash and are skipped; the fixture folder "
        "holds a single PE, so it yields one cluster)."
    ),
    "sql": (
        "SELECT pe.main.imphash(content) AS imphash, count(*) AS samples, "
        "min(pe.main.compile_timestamp(content)) AS first_built, "
        "max(pe.main.compile_timestamp(content)) AS last_built, "
        "list(filename ORDER BY filename) AS files "
        f"FROM read_blob('{_FIXTURE_GLOB}') WHERE pe.main.imphash(content) IS NOT NULL "
        "GROUP BY 1 ORDER BY samples DESC, imphash"
    ),
}
