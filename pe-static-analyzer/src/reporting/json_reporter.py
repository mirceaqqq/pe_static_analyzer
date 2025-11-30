import json
from pathlib import Path
from typing import Any

from src.core.analyzer import AnalysisResult


def generate(result: AnalysisResult, path: str):
    """
    Salvează rezultatul analizei în JSON.
    """
    Path(path).write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8"
    )
