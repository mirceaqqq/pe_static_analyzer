import re
from pathlib import Path
from typing import Dict, List

from src.core.analyzer import AnalyzerModule, AnalysisResult


class StringsAnalyzer(AnalyzerModule):
    """
    Extracts interesting strings (URLs, IPs, registry paths, commands).
    """

    URL_RE = re.compile(rb"https?://[^\s\"']+", re.IGNORECASE)
    IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    REG_RE = re.compile(rb"\\\\?REG(?:ISTRY)?\\\\[^\s\"']+", re.IGNORECASE)
    CMD_RE = re.compile(rb"(cmd\.exe|powershell|wscript|schtasks|bcdedit|vssadmin)", re.IGNORECASE)

    def __init__(self):
        super().__init__("strings_analyzer")

    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        strings: Dict[str, List[str]] = {"urls": [], "ips": [], "registry": [], "commands": []}
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            for regex, key in [
                (self.URL_RE, "urls"),
                (self.IP_RE, "ips"),
                (self.REG_RE, "registry"),
                (self.CMD_RE, "commands"),
            ]:
                matches = regex.findall(data)
                decoded = [m.decode("utf-8", errors="ignore") for m in matches]
                # deduplicate while preserving order
                seen = set()
                unique = []
                for item in decoded:
                    if item not in seen:
                        seen.add(item)
                        unique.append(item)
                strings[key] = unique[:50]

            result.strings = strings

            # Heuristics
            if strings["urls"]:
                result.heuristic_flags.append("STRINGS_URL_PRESENT")
            if strings["commands"]:
                result.heuristic_flags.append("STRINGS_COMMANDS_PRESENT")

            self.logger.info(
                "Strings extrase: urls=%d ips=%d reg=%d cmds=%d",
                len(strings["urls"]),
                len(strings["ips"]),
                len(strings["registry"]),
                len(strings["commands"]),
            )
        except Exception as e:
            self.logger.error(f"Eroare strings analyzer: {e}")
            raise
