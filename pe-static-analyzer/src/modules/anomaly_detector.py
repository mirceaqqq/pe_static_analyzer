from pathlib import Path
from typing import List
import pefile

from src.core.analyzer import AnalyzerModule, AnalysisResult


class AnomalyDetector(AnalyzerModule):
    """
    Detectează anomalii PE inspirate de manlyzer-like checks:
    - overlay (date după ultima secțiune)
    - secțiuni RWX sau nealiniate
    - timestamp suspect (pre-2000 sau în viitor îndepărtat)
    - entrypoint în afara secțiunilor
    """

    def __init__(self):
        super().__init__("anomaly_detector")

    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        anomalies: List[str] = []
        try:
            pe = pefile.PE(str(file_path))
            file_size = file_path.stat().st_size

            # Overlay check
            last = pe.sections[-1]
            overlay_start = last.PointerToRawData + last.SizeOfRawData
            if file_size > overlay_start:
                overlay_size = file_size - overlay_start
                anomalies.append(f"OVERLAY_PRESENT:{overlay_size} bytes")

            # Section checks
            for sec in pe.sections:
                name = sec.Name.decode(errors="ignore").strip("\x00")
                # RWX
                if sec.IMAGE_SCN_MEM_EXECUTE and sec.IMAGE_SCN_MEM_WRITE:
                    anomalies.append(f"RWX_SECTION:{name}")
                # alignment
                if sec.PointerToRawData % pe.OPTIONAL_HEADER.FileAlignment != 0:
                    anomalies.append(f"UNALIGNED_SECTION:{name}")

            # Entrypoint location
            ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            if not any(sec.VirtualAddress <= ep_rva < sec.VirtualAddress + sec.Misc_VirtualSize for sec in pe.sections):
                anomalies.append("ENTRYPOINT_OUTSIDE_SECTIONS")

            # Timestamp suspect
            ts = pe.FILE_HEADER.TimeDateStamp
            if ts < 946684800:  # before 2000
                anomalies.append("TIMESTAMP_OLD")
            # Very far future
            if ts > 1893456000:  # ~2030+
                anomalies.append("TIMESTAMP_FUTURE")

            if anomalies:
                result.anomalies.extend(anomalies)
                result.heuristic_flags.extend(anomalies)

            pe.close()
            self.logger.info("Anomalii detectate: %d", len(anomalies))
        except Exception as e:
            self.logger.error(f"Eroare anomaly detector: {e}")
