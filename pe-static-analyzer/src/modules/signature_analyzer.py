from pathlib import Path

from src.core.analyzer import AnalyzerModule, AnalysisResult
import lief


class SignatureAnalyzer(AnalyzerModule):
    """
    Verifica semnatura digitala si marcheaza invalid/unsigned.
    """

    def __init__(self):
        super().__init__("signature_analyzer")

    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        try:
            binary = lief.parse(str(file_path))

            if binary and binary.has_signature:
                sig = binary.signature
                try:
                    verified = bool(sig.check())
                except Exception:
                    verified = False
                signer = str(sig.signers[0].issuer) if sig.signers else "Unknown"
                result.signatures = {
                    "signed": True,
                    "verified": verified,
                    "signer": signer,
                }
                if not verified:
                    result.heuristic_flags.append("INVALID_SIGNATURE")
            else:
                result.signatures = {"signed": False}
                result.heuristic_flags.append("UNSIGNED_EXECUTABLE")

            self.logger.info(f"Verificare semnatura: {result.signatures}")

        except Exception as e:
            self.logger.warning(f"Nu s-a putut verifica semnatura: {e}")
            result.signatures = {"signed": False, "error": str(e)}
