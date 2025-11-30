from pathlib import Path
from typing import Any, Dict
import os
import json

from src.core.analyzer import AnalyzerModule, AnalysisResult


class VirusTotalModule(AnalyzerModule):
    """
    Optional VirusTotal lookup by SHA256 hash.
    Requires environment variable VT_API_KEY. Skips silently otherwise.
    Caches responses in temp/vt_cache.json to avoid repeated calls.
    """

    API_URL = "https://www.virustotal.com/api/v3/files/{sha256}"
    CACHE_PATH = Path("temp") / "vt_cache.json"

    def __init__(self):
        super().__init__("virus_total")
        self.api_key = os.getenv("VT_API_KEY")
        try:
            import requests  # type: ignore

            self._requests = requests
        except Exception:
            self._requests = None
        self.cache = self._load_cache()

    def _load_cache(self) -> Dict[str, Any]:
        if self.CACHE_PATH.exists():
            try:
                return json.loads(self.CACHE_PATH.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def _save_cache(self) -> None:
        try:
            self.CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            self.CACHE_PATH.write_text(json.dumps(self.cache, indent=2), encoding="utf-8")
        except Exception as e:
            self.logger.warning(f"Nu am putut salva cache VT: {e}")

    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        if not self.api_key:
            self.logger.info("VT_API_KEY missing; skipping VirusTotal lookup")
            result.heuristic_flags.append("VT_SKIPPED_NO_KEY")
            return
        if not self._requests:
            self.logger.warning("requests library missing; skipping VirusTotal lookup")
            result.errors.append("requests_missing_for_vt")
            return
        sha256 = result.file_hash.get("sha256")
        if not sha256:
            self.logger.warning("No SHA256 available; skipping VirusTotal lookup")
            return

        if sha256 in self.cache:
            result.vt_report = self.cache[sha256]
            self.logger.info("VirusTotal cache hit")
            return

        url = self.API_URL.format(sha256=sha256)
        headers = {"x-apikey": self.api_key}
        try:
            resp = self._requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 401:
                result.errors.append("VT unauthorized (check API key)")
                return
            if resp.status_code == 404:
                result.heuristic_flags.append("VT_NOT_FOUND")
                return
            resp.raise_for_status()
            data = resp.json()
            attr: Dict[str, Any] = data.get("data", {}).get("attributes", {})
            stats: Dict[str, int] = attr.get("last_analysis_stats", {})
            total = sum(stats.values()) if stats else 0
            malicious = stats.get("malicious", 0) if stats else 0
            ratio = f"{malicious}/{total}" if total else "0/0"
            report = {
                "detection_ratio": ratio,
                "stats": stats,
                "link": f"https://www.virustotal.com/gui/file/{sha256}",
            }
            result.vt_report = report
            self.cache[sha256] = report
            self._save_cache()
            if malicious > 0:
                result.heuristic_flags.append(f"VT_MALICIOUS:{ratio}")
            self.logger.info(f"VirusTotal lookup OK: {ratio}")
        except Exception as e:
            self.logger.error(f"Eroare VirusTotal: {e}")
            result.errors.append(f"virus_total_error:{e}")
