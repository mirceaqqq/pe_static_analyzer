from pathlib import Path
from typing import Any, Dict
import os
import json

from src.core.analyzer import AnalyzerModule, AnalysisResult


class OSINTLookup(AnalyzerModule):
    """
    Hash reputation lookup (optional).
    Supports MalwareBazaar (no key) and MalShare (requires MALSHARE_API_KEY).
    Skips gracefully if network or keys are missing.
    """

    MALWARE_BAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
    MALSHARE_URL = "https://malshare.com/api.php"

    def __init__(self):
        super().__init__("osint_lookup")
        try:
            import requests  # type: ignore

            self._requests = requests
        except Exception:
            self._requests = None
        self.malshare_key = os.getenv("MALSHARE_API_KEY")

    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        if not self._requests:
            self.logger.info("requests missing; skip OSINT lookup")
            return

        sha256 = result.file_hash.get("sha256")
        if not sha256:
            return

        # MalwareBazaar (public, but may be blocked by network)
        try:
            resp = self._requests.post(
                self.MALWARE_BAZAAR_URL,
                data={"query": "get_info", "hash": sha256},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok":
                    tags = data.get("data", [{}])[0].get("tags", [])
                    result.heuristic_flags.extend([f"MB_TAG:{t}" for t in tags[:5]])
                    result.iocs.append({"source": "MalwareBazaar", "tags": tags})
        except Exception as e:
            self.logger.debug(f"MalwareBazaar lookup failed: {e}")

        # MalShare (requires key)
        if not self.malshare_key:
            return
        try:
            resp = self._requests.get(
                self.MALSHARE_URL,
                params={"api_key": self.malshare_key, "action": "details", "hash": sha256},
                timeout=10,
            )
            if resp.status_code == 200:
                try:
                    data: Dict[str, Any] = json.loads(resp.text)
                    if data:
                        if data.get("F_TYPE"):
                            result.heuristic_flags.append(f"MS_TYPE:{data['F_TYPE']}")
                        if data.get("SOURCE"):
                            result.iocs.append({"source": "MalShare", "detail": data.get("SOURCE")})
                except Exception:
                    # MalShare may return plain text
                    result.iocs.append({"source": "MalShare", "detail": resp.text[:200]})
        except Exception as e:
            self.logger.debug(f"MalShare lookup failed: {e}")
