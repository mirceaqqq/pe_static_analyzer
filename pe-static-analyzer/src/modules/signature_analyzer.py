from pathlib import Path

from src.core.analyzer import AnalyzerModule, AnalysisResult, PEStaticAnalyzer
import lief
class SignatureAnalyzer(AnalyzerModule):
    """
    Verificare semnături digitale
    Detecție: semnătură validă, expirată, self-signed
    """
    
    def __init__(self):
        super().__init__("signature_analyzer")
    
    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        """Verifică semnătura digitală"""
        try:
            binary = lief.parse(str(file_path))
            
            if binary.has_signature:
                sig = binary.signature
                
                result.signatures = {
                    'signed': True,
                    'verified': sig.check(),
                    'signer': str(sig.signers[0].issuer) if sig.signers else 'Unknown'
                }
                
                if not sig.check():
                    result.heuristic_flags.append("INVALID_SIGNATURE")
            else:
                result.signatures = {'signed': False}
                result.heuristic_flags.append("UNSIGNED_EXECUTABLE")
            
            self.logger.info(f"Verificare semnătură: {result.signatures}")
        
        except Exception as e:
            self.logger.warning(f"Nu s-a putut verifica semnătura: {e}")
            result.signatures = {'signed': False, 'error': str(e)}
