"""Composed example queries shared across object- and schema-level metadata.

Each example combines two or more of the worker's own functions in one query a
triage analyst would actually write (a folder-wide scalar pass, a table function
filtered by a scalar baseline, a corpus clustered by one scalar and summarized by
another). Every SQL string is defined once here and referenced from the driving
object's ``vgi.example_queries`` / ``Meta.examples`` and from the schema-level
``vgi.example_queries`` list, so the copies can never drift apart.

All of them read the committed fixtures under ``test/sql/data/`` over HTTPS from a
pinned release tag (``FIXTURES_URL``, never ``main``, so the URL is immutable),
fetched DuckDB-side with ``read_blob`` and handed to the worker's BLOB overloads.
They therefore run for anyone with an attached worker, from any directory, with
no repo checkout; the worker itself still never fetches anything. Table functions
take their binary as a constant (DuckDB forbids a subquery argument), so their
examples are two-statement lists that load the bytes into the session variable
``bin`` first (see ``fixture_set``).
"""

from __future__ import annotations

# The committed SQL fixtures, served from a release tag at which they all exist.
FIXTURES_URL = "https://raw.githubusercontent.com/Query-farm/vgi-pe/v0.4.0/test/sql/data"
PE_URL = f"{FIXTURES_URL}/hello.exe"  # PE32+ x86-64 (mingw): sections, imports, imphash
ELF_URL = f"{FIXTURES_URL}/hello_elf"  # ELF x86-64 (zig cc)
MACHO_URL = f"{FIXTURES_URL}/hello_macho"  # Mach-O arm64, ad-hoc signed, has exports
GARBAGE_URL = f"{FIXTURES_URL}/garbage.bin"  # not an executable


def fixture_blob(url: str) -> str:
    """SQL scalar subquery yielding a fixture's bytes (``read_blob`` over HTTPS)."""
    return f"(SELECT content FROM read_blob('{url}'))"


def fixture_set(url: str) -> str:
    """SQL statement loading a fixture's bytes into the session variable ``bin``.

    A table function's binary argument must be a constant, so its examples load
    the bytes first and pass ``getvariable('bin')``.
    """
    return f"SET VARIABLE bin = {fixture_blob(url)}"


PE_BLOB = fixture_blob(PE_URL)
ELF_BLOB = fixture_blob(ELF_URL)
MACHO_BLOB = fixture_blob(MACHO_URL)
# DuckDB's read_blob takes a list of files: the whole fixture "folder".
_FIXTURE_LIST = "[" + ", ".join(f"'{u}'" for u in (PE_URL, ELF_URL, MACHO_URL, GARBAGE_URL)) + "]"

# binary_format + machine + is_signed + section_count + overall_entropy over every
# file of a folder (BLOB overloads fed by DuckDB's read_blob).
CORPUS_TRIAGE: dict[str, str] = {
    "description": (
        "Triage a set of files in one pass (read_blob also takes a folder glob such as 'samples/*'): "
        "container format, CPU architecture, "
        "code-signing, section count and whole-file entropy per file (a non-executable such as "
        "garbage.bin comes back all-NULL instead of failing the query)."
    ),
    "sql": (
        "SELECT filename, pe.main.binary_format(content) AS container, pe.main.machine(content) AS arch, "
        "pe.main.is_signed(content) AS signed, pe.main.section_count(content) AS n_sections, "
        "round(pe.main.overall_entropy(content), 2) AS file_entropy "
        f"FROM read_blob({_FIXTURE_LIST}) ORDER BY filename"
    ),
}

# sections (table) filtered against overall_entropy (scalar) of the same file.
SECTIONS_ABOVE_FILE_ENTROPY: dict[str, object] = {
    "description": (
        "Localize the densest content of a sample: the sections whose entropy exceeds the file's "
        "own whole-file entropy (for hello.exe, `.text` and the `/19` debug section at ~5.9-6.0 "
        "bits/byte against a 5.44 baseline)."
    ),
    "sql": [
        fixture_set(PE_URL),
        "WITH baseline AS (SELECT pe.main.overall_entropy(getvariable('bin')) AS file_entropy) "
        "SELECT s.name, round(s.entropy, 3) AS entropy, round(b.file_entropy, 3) AS file_entropy "
        "FROM pe.main.sections(getvariable('bin')) AS s, baseline AS b "
        "WHERE s.entropy > b.file_entropy ORDER BY s.entropy DESC",
    ],
}


def as_script(example: dict[str, object]) -> dict[str, str]:
    """Render a statement-list example as one ``;``-joined script string.

    The single-string form the schema-level ``vgi.example_queries`` list carries
    (run the statements in order on one connection).
    """
    sql = example["sql"]
    script = ";\n".join(sql) if isinstance(sql, list) else str(sql)
    return {"description": str(example["description"]), "sql": script}


# imphash (cluster key) + compile_timestamp (build-time span) over a folder.
IMPHASH_CLUSTERS: dict[str, str] = {
    "description": (
        "Cluster a folder of PE samples by import hash and show each cluster's size, build-time "
        "span and member files (non-PE files have no imphash and are skipped; the sample set "
        "holds a single PE, so it yields one cluster)."
    ),
    "sql": (
        "SELECT pe.main.imphash(content) AS imphash, count(*) AS samples, "
        "min(pe.main.compile_timestamp(content)) AS first_built, "
        "max(pe.main.compile_timestamp(content)) AS last_built, "
        "list(filename ORDER BY filename) AS files "
        f"FROM read_blob({_FIXTURE_LIST}) WHERE pe.main.imphash(content) IS NOT NULL "
        "GROUP BY 1 ORDER BY samples DESC, imphash"
    ),
}
