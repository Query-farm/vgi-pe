"""Shared helpers for per-object discovery/description metadata (strict profile).

The ``vgi-lint`` strict profile (0.26.0) expects these tags on **every** function
and table. Each function/table surfaces them in its ``Meta.tags``:

- ``vgi.title`` (VGI124)         — human-friendly display name (must NOT
  normalize-equal the machine name, or VGI125 fires).
- ``vgi.doc_llm`` (VGI112)       — a Markdown narrative aimed at an LLM/agent.
- ``vgi.doc_md`` (VGI113)        — a Markdown narrative aimed at human docs
  (must be DISTINCT content from ``vgi.doc_llm``).
- ``vgi.keywords`` (VGI126)      — comma-separated search terms/synonyms.
- ``vgi.source_url`` (VGI128)    — link to the implementing source file.

``source_url(file)`` builds the canonical GitHub blob URL so every object points
at exactly where it is implemented.
"""

from __future__ import annotations

# Base GitHub blob URL for source files in this repo (pinned to ``main``).
_SOURCE_BASE = "https://github.com/Query-farm/vgi-pe/blob/main"


def source_url(relative_path: str) -> str:
    """Build the implementation ``vgi.source_url`` for a file in the repo.

    Args:
        relative_path: Path of the implementing file relative to the repo root,
            e.g. ``vgi_pe/scalars.py``.

    Returns:
        The canonical GitHub blob URL for that file on ``main``.
    """
    return f"{_SOURCE_BASE}/{relative_path}"


def object_tags(
    *,
    title: str,
    doc_llm: str,
    doc_md: str,
    keywords: str,
    relative_path: str,
) -> dict[str, str]:
    """Build the five standard per-object discovery/description tags.

    Args:
        title: Human-friendly display name (VGI124).
        doc_llm: Markdown narrative aimed at LLMs/agents (VGI112).
        doc_md: Markdown narrative aimed at human docs (VGI113); must differ from
            ``doc_llm``.
        keywords: Comma-separated search terms/synonyms (VGI126).
        relative_path: Implementing source file relative to the repo root
            (VGI128).

    Returns:
        A tag dict suitable for spreading into a function's ``Meta.tags``.
    """
    return {
        "vgi.title": title,
        "vgi.doc_llm": doc_llm,
        "vgi.doc_md": doc_md,
        "vgi.keywords": keywords,
        "vgi.source_url": source_url(relative_path),
    }
