"""Shared helpers for per-object discovery/description metadata (strict profile).

The ``vgi-lint`` strict profile expects these tags on **every** function and
table. Each function/table surfaces them in its ``Meta.tags``:

- ``vgi.title`` (VGI124)         — human-friendly display name (must NOT
  normalize-equal the machine name, or VGI125 fires).
- ``vgi.doc_llm`` (VGI112)       — a Markdown narrative aimed at an LLM/agent.
- ``vgi.doc_md`` (VGI113)        — a Markdown narrative aimed at human docs
  (must be DISTINCT content from ``vgi.doc_llm``).
- ``vgi.keywords`` (VGI126/VGI138) — search terms/synonyms, serialized as a
  **JSON array of strings** (VGI138 rejects a bare comma-separated string).

``vgi.source_url`` is intentionally NOT set per-object: VGI139 requires the
provenance link to live on the **catalog** only, not be repeated on every
object. ``keywords_array`` converts a comma-separated keyword string into the
JSON-array form the linter requires.
"""

from __future__ import annotations

import json


def keywords_array(keywords: str) -> str:
    """Serialize comma-separated keywords into a JSON array of strings (VGI138).

    Args:
        keywords: Comma-separated search terms/synonyms, e.g. ``"pe, elf"``.

    Returns:
        A JSON array string of the trimmed, de-duplicated terms, e.g.
        ``'["pe", "elf"]'`` — the form ``vgi.keywords`` must take.
    """
    seen: dict[str, None] = {}
    for term in keywords.split(","):
        cleaned = term.strip()
        if cleaned and cleaned not in seen:
            seen[cleaned] = None
    return json.dumps(list(seen), ensure_ascii=False)


def object_tags(
    *,
    title: str,
    doc_llm: str,
    doc_md: str,
    keywords: str,
    relative_path: str,
) -> dict[str, str]:
    """Build the standard per-object discovery/description tags.

    Args:
        title: Human-friendly display name (VGI124).
        doc_llm: Markdown narrative aimed at LLMs/agents (VGI112).
        doc_md: Markdown narrative aimed at human docs (VGI113); must differ from
            ``doc_llm``.
        keywords: Comma-separated search terms/synonyms (VGI126); serialized into
            a JSON array of strings for ``vgi.keywords`` (VGI138).
        relative_path: Implementing source file relative to the repo root.
            Accepted for documentation/consistency but NOT emitted as a per-object
            ``vgi.source_url`` — VGI139 keeps that link on the catalog only.

    Returns:
        A tag dict suitable for spreading into a function's ``Meta.tags``.
    """
    del relative_path  # source_url is catalog-only (VGI139); see module docstring.
    return {
        "vgi.title": title,
        "vgi.doc_llm": doc_llm,
        "vgi.doc_md": doc_md,
        "vgi.keywords": keywords_array(keywords),
    }
