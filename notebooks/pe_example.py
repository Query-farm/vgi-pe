"""Presentation and byte-provenance checks for benign executable fixtures."""

import hashlib
import json
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
from vgi_notebooks import finish

SOURCE = "Source: committed benign hello-world fixtures · VGI PE v0.4.0 · static byte reads only"


def verify_fixtures():
    manifest = json.loads(Path("fixtures/manifest.json").read_text())
    for name, digest in manifest["sha256"].items():
        if hashlib.sha256((Path("fixtures") / name).read_bytes()).hexdigest() != digest:
            raise ValueError(f"Fixture differs from its recorded provenance: {name}")


def validate_minimum(value):
    if type(value) is not int or not 8 <= value <= 64:
        raise ValueError("MIN_STRING_LENGTH must be an integer from 8 to 64.")


def entropy_comparison(evidence):
    fig, ax = plt.subplots(figsize=(12, 7))
    for y, row in enumerate(evidence.itertuples()):
        if pd.isna(row.file_entropy):
            ax.text(0.15, y, "No reported entropy", va="center", color="#6c7971", fontsize=11)
        else:
            ax.scatter(row.file_entropy, y - 0.12, s=90, color="#267358", marker="o")
            ax.scatter(row.highest_section_entropy, y + 0.12, s=90, color="#456fba", marker="D")
    ax.scatter([], [], color="#267358", s=75, marker="o", label="Whole file")
    ax.scatter([], [], color="#456fba", s=75, marker="D", label="Highest section")
    ax.set_yticks(range(len(evidence)), evidence.sample_id.tolist())
    ax.set_ylim(len(evidence) - 0.5, -0.5)
    ax.set_xlim(0, 8)
    ax.set_xlabel("Shannon entropy · bits per byte · different byte populations")
    ax.grid(axis="y", visible=False)
    fig.legend(loc="upper left", bbox_to_anchor=(0.08, 0.80), ncol=2, frameon=False)
    finish(
        fig,
        "File and section entropy describe different bytes",
        "Three benign executable fixtures · no risk score or classification",
        SOURCE,
        name="01-static-entropy",
    )


def string_retention(retention, minimum):
    fig, ax = plt.subplots(figsize=(12, 7.3))
    y = list(range(len(retention)))
    ax.barh(
        [v - 0.17 for v in y],
        retention.baseline_runs,
        height=0.28,
        color="#cfd8d2",
        label="Fixed minimum 8",
    )
    ax.barh(
        [v + 0.17 for v in y],
        retention.selected_runs,
        height=0.28,
        color="#267358",
        label=f"Chosen minimum {minimum}",
    )
    for i, row in enumerate(retention.itertuples()):
        ax.text(
            max(row.baseline_runs, row.selected_runs) * 1.2 + 0.12,
            i,
            f"{row.selected_runs} / {row.baseline_runs}",
            va="center",
            fontsize=11,
        )
    ax.set_yticks(y, retention.sample_id.tolist())
    ax.invert_yaxis()
    ax.set_xscale("symlog", linthresh=1)
    ax.set_xlim(0, 7000)
    ax.set_xticks([0, 1, 10, 100, 1000], [0, 1, 10, 100, 1000])
    ax.grid(axis="y", visible=False)
    ax.set_xlabel("Printable runs · symmetric-log count scale · labels = chosen / baseline")
    fig.legend(loc="upper left", bbox_to_anchor=(0.08, 0.80), ncol=2, frameon=False)
    finish(
        fig,
        "A longer minimum changes what is visible",
        "Counts include repeated strings · unrecognized text remains in the analysis",
        SOURCE,
        name="02-string-retention",
    )
