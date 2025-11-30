from pathlib import Path
from typing import Dict, Any, List

import pefile

from src.core.analyzer import AnalyzerModule, AnalysisResult


class ResourceAnalyzer(AnalyzerModule):
    """
    Extract resource info (friendly type names) and version metadata.
    """

    RESOURCE_TYPES = {
        1: "CURSOR",
        2: "BITMAP",
        3: "ICON",
        4: "MENU",
        5: "DIALOG",
        6: "STRING",
        7: "FONTDIR",
        8: "FONT",
        9: "ACCELERATOR",
        10: "RCDATA",
        11: "MESSAGETABLE",
        12: "GROUP_CURSOR",
        14: "GROUP_ICON",
        16: "VERSION",
        24: "MANIFEST",
    }

    def __init__(self):
        super().__init__("resource_analyzer")

    def _fmt_type(self, res_type):
        if isinstance(res_type, int):
            return self.RESOURCE_TYPES.get(res_type, f"TYPE_{res_type}")
        return str(res_type)

    def _fmt_name(self, name):
        return str(name) if name else "unnamed"

    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        try:
            pe = pefile.PE(str(file_path))
            resources: List[Dict[str, Any]] = []

            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    res_type = self._fmt_type(entry.id if entry.id else entry.name)
                    if not hasattr(entry, "directory"):
                        continue
                    for res_id in entry.directory.entries:
                        name = self._fmt_name(res_id.id if res_id.id else res_id.name)
                        if not hasattr(res_id, "directory"):
                            continue
                        for res_lang in res_id.directory.entries:
                            size = res_lang.data.struct.Size
                            resources.append(
                                {
                                    "type": res_type,
                                    "name": name,
                                    "lang": res_lang.data.lang,
                                    "sublang": res_lang.data.sublang,
                                    "size": size,
                                }
                            )

            # Version info
            if hasattr(pe, "VS_VERSIONINFO") and pe.FileInfo:
                for file_info in pe.FileInfo:
                    if not hasattr(file_info, "Key") or not hasattr(file_info, "StringTable"):
                        continue
                    if file_info.Key == b"StringFileInfo":
                        for st in file_info.StringTable:
                            for key, val in st.entries.items():
                                resources.append(
                                    {
                                        "type": "VERSION",
                                        "name": key.decode(errors="ignore"),
                                        "lang": getattr(st, "lang", None),
                                        "sublang": getattr(st, "sublang", None),
                                        "value": val.decode(errors="ignore"),
                                    }
                                )

            result.resources = resources
            pe.close()

            if any(r.get("type") == "VERSION" for r in resources):
                result.heuristic_flags.append("HAS_VERSION_INFO")

            self.logger.info("Resurse extrase: %d", len(resources))
        except Exception as e:
            self.logger.error(f"Eroare analiza resurse: {e}")
            raise
