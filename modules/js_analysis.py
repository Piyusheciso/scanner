"""
JavaScript pattern analysis.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


PATTERNS = {
    "innerHTML": "innerHTML",
    "eval()": r"\beval\s*\(",
    "location.href": r"\blocation\s*\.\s*href\b",
    "localStorage": r"\blocalStorage\b",
    "sessionStorage": r"\bsessionStorage\b",
    "document.cookie": r"\bdocument\s*\.\s*cookie\b",
}


@dataclass
class JSFileAnalysis:
    file: str
    patterns: Dict[str, int]
    total_matches: int
    error: str | None = None


@dataclass
class JSAnalysisResult:
    files: List[JSFileAnalysis]
    totals: Dict[str, int]
    files_analyzed: int
    files_failed: int


def _count_pattern(
    content: str,
    pattern: str,
) -> int:
    """
    Count pattern occurrences.
    """

    import re

    return len(
        re.findall(
            pattern,
            content,
            re.IGNORECASE,
        )
    )


def analyze_js_file(
    file_path: Path,
) -> JSFileAnalysis:
    """
    Analyze one JavaScript file.
    """

    try:

        content = file_path.read_text(
            encoding="utf-8",
            errors="replace",
        )

        counts = {}

        for name, pattern in PATTERNS.items():

            counts[name] = _count_pattern(
                content,
                pattern,
            )

        total_matches = sum(
            counts.values()
        )

        return JSFileAnalysis(
            file=str(file_path),
            patterns=counts,
            total_matches=total_matches,
            error=None,
        )

    except OSError as exc:

        return JSFileAnalysis(
            file=str(file_path),
            patterns={
                name: 0
                for name in PATTERNS
            },
            total_matches=0,
            error=str(exc),
        )


def analyze_javascript(
    js_directory: Path,
) -> JSAnalysisResult:
    """
    Analyze all JS files in a directory.
    """

    files = sorted(
        js_directory.glob("*.js")
    )

    analyses = []

    for file_path in files:

        analyses.append(
            analyze_js_file(
                file_path
            )
        )

    totals = {
        name: 0
        for name in PATTERNS
    }

    files_failed = 0

    for analysis in analyses:

        if analysis.error:

            files_failed += 1
            continue

        for name, count in (
            analysis.patterns.items()
        ):

            totals[name] += count

    return JSAnalysisResult(
        files=analyses,
        totals=totals,
        files_analyzed=(
            len(analyses) - files_failed
        ),
        files_failed=files_failed,
    )


def js_analysis_to_dict(
    result: JSAnalysisResult,
) -> dict:
    """
    Convert analysis result to JSON-safe data.
    """

    return {
        "files_analyzed": (
            result.files_analyzed
        ),
        "files_failed": (
            result.files_failed
        ),
        "totals": result.totals,
        "files": [
            {
                "file": item.file,
                "patterns": item.patterns,
                "total_matches": (
                    item.total_matches
                ),
                "error": item.error,
            }
            for item in result.files
        ],
    }