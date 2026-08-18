"""
JSON report generation.
"""

import json
from dataclasses import asdict, is_dataclass
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any


def make_json_safe(value: Any) -> Any:
    """
    Convert scanner objects to JSON-safe values.
    """

    if value is None:
        return None

    if is_dataclass(value):
        return make_json_safe(
            asdict(value)
        )

    if isinstance(value, dict):
        return {
            str(key): make_json_safe(item)
            for key, item in value.items()
        }

    if isinstance(
        value,
        (list, tuple, set),
    ):
        return [
            make_json_safe(item)
            for item in value
        ]

    if isinstance(value, Path):
        return str(value)

    if isinstance(
        value,
        (datetime, date),
    ):
        return value.isoformat()

    if isinstance(
        value,
        (str, int, float, bool),
    ):
        return value

    if hasattr(value, "__dict__"):
        return make_json_safe(
            vars(value)
        )

    return str(value)


def build_report_data(
    target,
    phase_results: dict,
    findings,
) -> dict:
    """
    Build the complete report structure.
    """

    phase_7 = phase_results.get(
        "phase_7"
    ) or {}

    if isinstance(findings, list):
        finding_data = findings
    else:
        finding_data = []

    severity_counts = (
        phase_7.get(
            "counts",
            {},
        )
        if isinstance(phase_7, dict)
        else {}
    )

    report_data = {
        "scanner": {
            "name": "Web Recon Scanner",
            "version": "1.0",
            "generated_at": datetime.now(
                timezone.utc
            ).isoformat(),
        },

        "target": phase_results.get(
            "target",
            {},
        ),

        "phases": {
            "phase_1": {
                "target": phase_results.get(
                    "target"
                ),
            },

            "phase_2": phase_results.get(
                "http"
            ),

            "phase_3": phase_results.get(
                "phase_3"
            ),

            "phase_4": phase_results.get(
                "phase_4"
            ),

            "phase_5": phase_results.get(
                "phase_5"
            ),

            "phase_6": phase_results.get(
                "phase_6"
            ),

            "phase_7": phase_results.get(
                "phase_7"
            ),
        },

        "findings": finding_data,

        "finding_summary": {
            "total": len(finding_data),

            "critical": severity_counts.get(
                "Critical",
                0,
            ),

            "high": severity_counts.get(
                "High",
                0,
            ),

            "medium": severity_counts.get(
                "Medium",
                0,
            ),

            "low": severity_counts.get(
                "Low",
                0,
            ),

            "informational": severity_counts.get(
                "Informational",
                0,
            ),
        },
    }

    return make_json_safe(
        report_data
    )


def generate_json_report(
    target,
    phase_results: dict,
    findings,
    output_dir: Path,
) -> Path:
    """
    Generate report.json.
    """

    output_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_data = build_report_data(
        target,
        phase_results,
        findings,
    )

    report_file = (
        output_dir / "report.json"
    )

    report_file.write_text(
        json.dumps(
            report_data,
            indent=4,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    return report_file