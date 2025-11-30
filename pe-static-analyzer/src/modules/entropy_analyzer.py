from pathlib import Path

from src.core.analyzer import AnalyzerModule, AnalysisResult, PEStaticAnalyzer
import lief, math

class EntropyAnalyzer(AnalyzerModule):
    """
    Calculare entropie Shannon pentru fiecare secțiune
    Entropie ridicată (>7.0) poate indica criptare/compresie/packing
    """
    
    def __init__(self):
        super().__init__("entropy_analyzer")
    
    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        """Calculează entropia pentru fiecare secțiune"""
        try:
            binary = lief.parse(str(file_path))
            
            for section in binary.sections:
                section_data = bytes(section.content)
                entropy = self._calculate_entropy(section_data)
                
                result.entropy_data[section.name] = round(entropy, 3)
                
                # Flag pentru entropie suspectă
                if entropy > 7.0:
                    result.heuristic_flags.append(
                        f"HIGH_ENTROPY_SECTION:{section.name}:{entropy:.2f}"
                    )
            
            avg_entropy = sum(result.entropy_data.values()) / len(result.entropy_data)
            result.entropy_data['_average'] = round(avg_entropy, 3)
            
            self.logger.info(f"Entropie calculată: avg={avg_entropy:.2f}")
        
        except Exception as e:
            self.logger.error(f"Eroare calculare entropie: {e}")
            raise
    
    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculează entropia Shannon
        H(X) = -Σ P(xi) * log2(P(xi))
        """
        if not data:
            return 0.0
        
        # Frecvență bytes
        freq = [0] * 256
        for byte in data:
            freq[byte] += 1
        
        # Probabilități
        data_len = len(data)
        entropy = 0.0
        
        for count in freq:
            if count == 0:
                continue
            p = count / data_len
            entropy -= p * math.log2(p)
        
        return entropy
