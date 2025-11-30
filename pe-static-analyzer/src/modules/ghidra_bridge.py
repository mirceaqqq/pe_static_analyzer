import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict

from src.core.analyzer import AnalyzerModule, AnalysisResult


class GhidraBridge(AnalyzerModule):
    """
    Integrare headless Ghidra pentru decompilare reală (cod C) și CFG-uri.
    Condiții:
      - Variabila de mediu GHIDRA_HOME setată (directorul cu Ghidra)
      - Scriptul ExportDecompile.java prezent în ghidra_scripts/ (îl livrăm în repo)
    Dacă lipsește, modulul este sărit și nu blochează analiza.
    """

    def __init__(self):
        super().__init__("ghidra_bridge")
        self.ghidra_home = os.getenv("GHIDRA_HOME")
        self.script_path = Path("ghidra_scripts") / "ExportDecompile.py"
        self.work_dir = Path("temp") / "ghidra_work"
        self.output_json = self.work_dir / "ghidra_export.json"
        self.cache_dir = Path("temp") / "ghidra_cache"

    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        if not self.ghidra_home:
            self.logger.info("GHIDRA_HOME nu este setat; sar peste decompilare Ghidra.")
            result.heuristic_flags.append("GHIDRA_SKIPPED_NO_HOME")
            return
        if not self.script_path.exists():
            self.logger.info("Scriptul Ghidra nu există; sar peste.")
            result.errors.append("ghidra_script_missing")
            return

        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        sha = result.file_hash.get("sha256") if result.file_hash else None
        cache_path = self.cache_dir / f"{sha}.json" if sha else None
        if cache_path and cache_path.exists():
            try:
                data: Dict[str, Any] = json.loads(cache_path.read_text(encoding="utf-8"))
                result.pseudocode = data.get("functions", [])
                result.func_graphs = data.get("graphs", [])
                self.logger.info("Ghidra cache hit")
                return
            except Exception:
                self.logger.warning("Ghidra cache corupt, re-rulare.")

        # Pregătește comanda analyzeHeadless
        project_dir = self.work_dir
        project_name = "ghidra_proj"
        analyze_headless = Path(self.ghidra_home) / "support" / "analyzeHeadless.bat"
        if not analyze_headless.exists():
            result.errors.append("analyzeHeadless_missing")
            return

        # Curăță vechiul export
        if self.output_json.exists():
            try:
                self.output_json.unlink()
            except Exception:
                pass

        cmd = [
            str(analyze_headless),
            str(project_dir.resolve()),
            project_name,
            "-import",
            str(file_path.resolve()),
            "-overwrite",
            "-scriptPath",
            str(self.script_path.parent.resolve()),
            "-postScript",
            "ExportDecompile.py",
            str(self.output_json.resolve()),
        ]

        try:
            proc = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300,
            )
            if proc.returncode != 0:
                self.logger.error("Ghidra headless a eșuat: %s", proc.stderr[:500])
                result.errors.append(f"ghidra_failed:{proc.returncode}")
                return
            if not self.output_json.exists():
                result.errors.append("ghidra_no_output")
                return
            data: Dict[str, Any] = json.loads(self.output_json.read_text(encoding="utf-8"))
            result.pseudocode = data.get("functions", [])
            result.func_graphs = data.get("graphs", [])
            if cache_path:
                try:
                    cache_path.write_text(json.dumps(data), encoding="utf-8")
                except Exception:
                    pass
            self.logger.info(
                "Ghidra export: %d functii, %d grafuri",
                len(result.pseudocode),
                len(result.func_graphs),
            )
        except subprocess.TimeoutExpired:
            result.errors.append("ghidra_timeout")
        except Exception as e:
            result.errors.append(f"ghidra_error:{e}")
