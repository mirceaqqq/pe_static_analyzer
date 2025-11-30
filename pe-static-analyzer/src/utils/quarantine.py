"""
Quarantine helper: move or copy suspicious files into an isolated folder.
"""

from pathlib import Path
import shutil
from typing import Dict, Optional


def _should_quarantine(result, cfg: Dict) -> bool:
    if not cfg.get("enabled", True):
        return False

    risk_levels = {lvl.upper() for lvl in cfg.get("risk_levels", ["HIGH", "CRITICAL"])}
    score_min = cfg.get("score_min", 60)
    vt_min = cfg.get("vt_malicious_min", 1)

    risk_ok = result.risk_level.upper() in risk_levels
    score_ok = result.suspicion_score >= score_min
    vt_stats = result.vt_report.get("stats", {}) if result.vt_report else {}
    vt_ok = vt_stats.get("malicious", 0) >= vt_min

    return risk_ok or score_ok or vt_ok


def _build_target_path(src: Path, quarantine_dir: Path, sha256: Optional[str]) -> Path:
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    base_name = sha256 or src.name
    target = quarantine_dir / base_name

    # Avoid overwriting if the name already exists
    if target.exists():
        counter = 1
        while True:
            candidate = quarantine_dir / f"{base_name}_{counter}"
            if not candidate.exists():
                target = candidate
                break
            counter += 1
    return target


def quarantine_if_needed(file_path: Path, result, cfg: Dict) -> Optional[Path]:
    """
    Apply quarantine policy: if the file is suspicious, move it to the quarantine folder.
    Returns the quarantine path or None.
    """
    try:
        if not _should_quarantine(result, cfg):
            return None

        if not file_path.exists():
            return None

        quarantine_dir = Path(cfg.get("folder", "quarantine"))
        sha256 = result.file_hash.get("sha256")
        target = _build_target_path(file_path, quarantine_dir, sha256)

        # Copy then optionally delete original to avoid partial moves
        shutil.copy2(file_path, target)
        if cfg.get("delete_original", True):
            try:
                file_path.unlink()
            except Exception:
                # Leave a best-effort; copy still exists
                pass

        result.quarantined = True
        result.quarantine_path = str(target)
        result.analysis_log.append({"module": "quarantine", "status": "quarantined", "path": str(target)})
        return target
    except Exception as exc:  # noqa: BLE001
        result.analysis_log.append({"module": "quarantine", "status": "error", "detail": str(exc)})
        return None
