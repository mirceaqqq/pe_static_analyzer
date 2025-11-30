from pathlib import Path

from src.core.analyzer import AnalyzerModule, AnalysisResult, PEStaticAnalyzer
class PackerDetector(AnalyzerModule):
    """
    Detecție packere cunoscute
    Metode: verificare secțiuni, entropie, semnături cunoscute
    """
    
    PACKER_SIGNATURES = {
        'UPX': [b'UPX0', b'UPX1'],
        'ASPack': [b'aspack'],
        'PECompact': [b'PECompact2'],
        'Themida': [b'.themida'],
        'VMProtect': [b'VMProtect']
    }
    
    def __init__(self):
        super().__init__("packer_detector")
    
    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        """Detectează packer folosit"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Verificare semnături
            for packer, signatures in self.PACKER_SIGNATURES.items():
                for sig in signatures:
                    if sig in file_data:
                        result.packer_detected = packer
                        result.heuristic_flags.append(f"PACKER_DETECTED:{packer}")
                        self.logger.info(f"Detectat packer: {packer}")
                        return
            
            # Detecție bazată pe entropie
            avg_entropy = result.entropy_data.get('_average', 0)
            if avg_entropy > 7.2:
                result.packer_detected = "UNKNOWN_PACKER_HIGH_ENTROPY"
                result.heuristic_flags.append("POSSIBLE_PACKER_HIGH_ENTROPY")
            else:
                result.packer_detected = result.packer_detected or "NONE_DETECTED"
        
        except Exception as e:
            self.logger.error(f"Eroare detecție packer: {e}")
