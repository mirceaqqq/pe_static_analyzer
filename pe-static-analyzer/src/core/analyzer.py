"""
Core engine for PE Static Analyzer.
Handles orchestration, plugin registration, and result aggregation.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import json
from src.core.config import load_config
from src.utils.quarantine import quarantine_if_needed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    file_path: str
    file_hash: Dict[str, str]
    timestamp: datetime = field(default_factory=datetime.now)

    # Core PE info
    pe_info: Dict[str, Any] = field(default_factory=dict)

    # Module outputs
    entropy_data: Dict[str, float] = field(default_factory=dict)
    imports: List[Dict[str, Any]] = field(default_factory=list)
    exports: List[Dict[str, Any]] = field(default_factory=list)
    sections: List[Dict[str, Any]] = field(default_factory=list)
    signatures: Dict[str, Any] = field(default_factory=dict)
    vt_report: Dict[str, Any] = field(default_factory=dict)
    resources: List[Dict[str, Any]] = field(default_factory=list)
    strings: Dict[str, List[str]] = field(default_factory=dict)
    analysis_log: List[Dict[str, Any]] = field(default_factory=list)
    anomalies: List[str] = field(default_factory=list)
    disassembly: List[Dict[str, Any]] = field(default_factory=list)
    pseudocode: List[Dict[str, Any]] = field(default_factory=list)
    func_graphs: List[Dict[str, Any]] = field(default_factory=list)
    scoring_breakdown: List[str] = field(default_factory=list)
    quarantined: bool = False
    quarantine_path: Optional[str] = None

    # Detections
    yara_matches: List[Dict[str, Any]] = field(default_factory=list)
    packer_detected: Optional[str] = None
    iocs: List[Dict[str, Any]] = field(default_factory=list)

    # Scoring & classification
    suspicion_score: float = 0.0
    risk_level: str = "UNKNOWN"  # LOW, MEDIUM, HIGH, CRITICAL
    heuristic_flags: List[str] = field(default_factory=list)

    # Metadata
    analysis_duration: float = 0.0
    modules_used: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dict for serialization."""
        return {
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "timestamp": self.timestamp.isoformat(),
            "pe_info": self.pe_info,
            "entropy_data": self.entropy_data,
            "imports": self.imports,
            "exports": self.exports,
            "sections": self.sections,
            "signatures": self.signatures,
            "vt_report": self.vt_report,
            "resources": self.resources,
            "strings": self.strings,
            "analysis_log": self.analysis_log,
            "disassembly": self.disassembly,
            "pseudocode": self.pseudocode,
            "func_graphs": self.func_graphs,
            "anomalies": self.anomalies,
            "scoring_breakdown": self.scoring_breakdown,
            "yara_matches": self.yara_matches,
            "packer_detected": self.packer_detected,
            "iocs": self.iocs,
            "suspicion_score": self.suspicion_score,
            "risk_level": self.risk_level,
            "heuristic_flags": self.heuristic_flags,
            "analysis_duration": self.analysis_duration,
            "modules_used": self.modules_used,
            "errors": self.errors,
            "quarantined": self.quarantined,
            "quarantine_path": self.quarantine_path,
        }


class AnalyzerModule:
    """Base class for analyzer modules."""

    def __init__(self, name: str):
        self.name = name
        self.enabled = True
        self.logger = logging.getLogger(f"module.{name}")

    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        raise NotImplementedError("Modulul trebuie sa implementeze analiza.")

    def get_metadata(self) -> Dict[str, Any]:
        return {"name": self.name, "enabled": self.enabled, "version": "1.1.0"}


class PluginManager:
    """Register and manage analyzer modules."""

    def __init__(self):
        self.modules: Dict[str, AnalyzerModule] = {}
        self.logger = logging.getLogger("PluginManager")

    def register_module(self, module: AnalyzerModule) -> None:
        if module.name in self.modules:
            self.logger.warning(
                f"Modulul {module.name} este deja inregistrat. Suprascriere."
            )
        self.modules[module.name] = module
        self.logger.info(f"Modul inregistrat: {module.name}")

    def unregister_module(self, module_name: str) -> None:
        if module_name in self.modules:
            del self.modules[module_name]
            self.logger.info(f"Modul dezactivat: {module_name}")

    def get_module(self, module_name: str) -> Optional[AnalyzerModule]:
        return self.modules.get(module_name)

    def list_modules(self) -> List[str]:
        return list(self.modules.keys())

    def enable_module(self, module_name: str) -> None:
        if module := self.modules.get(module_name):
            module.enabled = True
            self.logger.info(f"Modul activat: {module_name}")

    def disable_module(self, module_name: str) -> None:
        if module := self.modules.get(module_name):
            module.enabled = False
            self.logger.info(f"Modul dezactivat: {module_name}")


class PEStaticAnalyzer:
    """Main orchestrator for PE static analysis."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or load_config()
        self.plugin_manager = PluginManager()
        self.logger = logging.getLogger("PEStaticAnalyzer")

        # Stats
        self.total_analyses = 0
        self.successful_analyses = 0
        self.failed_analyses = 0

        # Scoring weights (can be overridden via config)
        defaults = {
            "yara_match": 10,
            "yara_max": 40,
            "packer": 10,
            "entropy_high": 10,
            "entropy_medium": 5,
            "heuristic_flag": 5,
            "heuristic_max": 25,
            "vt_malicious": 30,
            "signed_bonus": 15,
        }
        self.score_weights = {**defaults, **self.config.get("weights", {})}

    def analyze_file(self, file_path: str) -> AnalysisResult:
        """Run full analysis on a single PE file."""
        start_time = datetime.now()
        file_path_obj = Path(file_path)

        if not file_path_obj.exists():
            raise FileNotFoundError(f"Fisierul nu exista: {file_path}")
        if not file_path_obj.is_file():
            raise ValueError(f"Calea specificata nu este fisier: {file_path}")

        self.logger.info(f"Start analiza: {file_path}")

        result = AnalysisResult(
            file_path=str(file_path_obj.absolute()), file_hash={}
        )

        # Execute modules
        for module_name, module in self.plugin_manager.modules.items():
            if not module.enabled:
                self.logger.debug(f"Modul {module_name} dezactivat, skip")
                continue

            try:
                self.logger.info(f"Executie modul: {module_name}")
                result.analysis_log.append({"module": module_name, "status": "start"})
                module.analyze(file_path_obj, result)
                result.modules_used.append(module_name)
                result.analysis_log.append({"module": module_name, "status": "done"})
            except Exception as e:
                error_msg = f"Eroare in modulul {module_name}: {str(e)}"
                self.logger.error(error_msg)
                result.errors.append(error_msg)
                result.analysis_log.append(
                    {"module": module_name, "status": "error", "detail": str(e)}
                )

        # Scoring & classification
        result.suspicion_score = self._calculate_suspicion_score(result)
        result.risk_level = self._classify_risk(result.suspicion_score)

        # Quarantine if policy requires it
        quarantine_cfg = self.config.get("quarantine", {})
        quarantine_if_needed(file_path_obj, result, quarantine_cfg)

        # Duration
        end_time = datetime.now()
        result.analysis_duration = (end_time - start_time).total_seconds()

        # Stats
        self.total_analyses += 1
        if not result.errors:
            self.successful_analyses += 1
        else:
            self.failed_analyses += 1

        self.logger.info(
            "Analiza completata in %.2fs (Scor: %.1f, Risc: %s)",
            result.analysis_duration,
            result.suspicion_score,
            result.risk_level,
        )
        return result

    def analyze_batch(self, file_paths: List[str]) -> List[AnalysisResult]:
        results = []
        for file_path in file_paths:
            try:
                result = self.analyze_file(file_path)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Eroare analiza {file_path}: {e}")
                error_result = AnalysisResult(
                    file_path=file_path, file_hash={}, errors=[str(e)]
                )
                results.append(error_result)
        return results

    def _calculate_suspicion_score(self, result: AnalysisResult) -> float:
        score = 0.0
        breakdown: List[str] = []
        w = self.score_weights

        # YARA
        if result.yara_matches:
            yara_score = min(len(result.yara_matches) * w["yara_match"], w["yara_max"])
            score += yara_score
            breakdown.append(f"YARA: +{yara_score}")

        # Packer
        if result.packer_detected:
            score += w["packer"]
            breakdown.append(f"Packer: +{w['packer']}")

        # Entropy
        if result.entropy_data:
            avg_entropy = sum(result.entropy_data.values()) / len(result.entropy_data)
            if avg_entropy > 7.0:
                score += w["entropy_high"]
                breakdown.append(f"Entropie ridicata: +{w['entropy_high']}")
            elif avg_entropy > 6.5:
                score += w["entropy_medium"]
                breakdown.append(f"Entropie medie: +{w['entropy_medium']}")

        # Heuristic flags
        if result.heuristic_flags:
            heuristic_score = min(
                len(result.heuristic_flags) * w["heuristic_flag"], w["heuristic_max"]
            )
            score += heuristic_score
            breakdown.append(f"Heuristici: +{heuristic_score}")

        # VirusTotal
        if result.vt_report:
            stats = result.vt_report.get("stats", {})
            malicious = stats.get("malicious", 0)
            if malicious > 0:
                score += w["vt_malicious"]
                breakdown.append(f"VT malicious: +{w['vt_malicious']}")

        # Bonus pentru executabile semnate și verificate: reduce scorul
        if result.signatures and result.signatures.get("verified"):
            bonus = w.get("signed_bonus", 0)
            score = max(0.0, score - bonus)
            breakdown.append(f"Semnatura valida: -{bonus}")

        result.scoring_breakdown = breakdown
        return min(score, 100.0)

    def _classify_risk(self, score: float) -> str:
        if score < 25:
            return "LOW"
        elif score < 50:
            return "MEDIUM"
        elif score < 75:
            return "HIGH"
        else:
            return "CRITICAL"

    def get_statistics(self) -> Dict[str, Any]:
        return {
            "total_analyses": self.total_analyses,
            "successful": self.successful_analyses,
            "failed": self.failed_analyses,
            "success_rate": (
                self.successful_analyses / self.total_analyses * 100
                if self.total_analyses > 0
                else 0
            ),
            "registered_modules": self.plugin_manager.list_modules(),
        }


if __name__ == "__main__":
    analyzer = PEStaticAnalyzer()
    print("Framework de analiza PE initializat.")
    print(f"Statistici: {json.dumps(analyzer.get_statistics(), indent=2)}")
