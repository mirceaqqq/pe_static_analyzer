from pathlib import Path
from typing import Optional, Iterable

import yara

from src.core.analyzer import AnalyzerModule, AnalysisResult


class YARAScanner(AnalyzerModule):
    """
    Scanner cu reguli YARA.
    Suporta reguli locale si cele sincronizate din GitHub (vezi utilitarul src/utils/yara_sync.py).
    """

    def __init__(self, rules_path: Optional[Path] = None):
        super().__init__("yara_scanner")
        self.rules_path = rules_path or Path("yara_rules")
        self.compiled_rules = None

        if self.rules_path.exists():
            self._compile_rules()

    def _collect_rule_files(self) -> Iterable[Path]:
        """Returneaza toate fisierele .yar/.yara din arbore."""
        for pattern in ("*.yar", "*.yara"):
            yield from self.rules_path.rglob(pattern)

    def _compile_rules(self) -> None:
        """Compileaza toate regulile YARA din directorul configurat."""
        try:
            rule_files = {}
            for rule_file in self._collect_rule_files():
                rel = rule_file.relative_to(self.rules_path)
                namespace = rel.as_posix().replace("/", "_").replace(".", "_")
                rule_files[namespace] = str(rule_file)

            if not rule_files:
                self.compiled_rules = None
                self.logger.warning("Nu exista reguli YARA de compilat in %s", self.rules_path)
                return

            self.compiled_rules = yara.compile(filepaths=rule_files)
            self.logger.info("Compilate %d fisiere YARA din %s", len(rule_files), self.rules_path)

        except Exception as e:
            self.logger.error(f"Eroare compilare reguli YARA: {e}")
            self.compiled_rules = None

    def reload_rules(self) -> None:
        """Reincarca regulile dupa ce au fost adaugate/actualizate pe disc."""
        self._compile_rules()

    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        """Scaneaza fisierul cu regulile YARA compilate."""
        if not self.compiled_rules:
            self.logger.warning("Nu exista reguli YARA compilate")
            return

        try:
            matches = self.compiled_rules.match(str(file_path))

            for match in matches:
                match_info = {
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": match.tags,
                    "meta": match.meta,
                    "strings": [],
                }

                for string_match in match.strings:
                    match_info["strings"].append(
                        {
                            "offset": string_match.instances[0].offset,
                            "identifier": string_match.identifier,
                            "data": string_match.instances[0].matched_data[:50].hex(),
                        }
                    )

                result.yara_matches.append(match_info)
                result.heuristic_flags.append(f"YARA_MATCH:{match.rule}")

            self.logger.info("Detectate %d match-uri YARA", len(matches))

        except Exception as e:
            self.logger.error(f"Eroare scanare YARA: {e}")
