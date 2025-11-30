# TODO: Hash Calculator module
from pathlib import Path

from src.core.analyzer import AnalyzerModule, AnalysisResult, PEStaticAnalyzer
import hashlib
import pefile
class HashCalculator(AnalyzerModule):
    """
    Modul pentru calculare hash-uri multiple
    Suportă: MD5, SHA1, SHA256, SHA512, Imphash
    """
    
    def __init__(self):
        super().__init__("hash_calculator")
    
    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        """Calculează toate hash-urile fișierului"""
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            # Hash-uri standard
            result.file_hash['md5'] = hashlib.md5(file_data).hexdigest()
            result.file_hash['sha1'] = hashlib.sha1(file_data).hexdigest()
            result.file_hash['sha256'] = hashlib.sha256(file_data).hexdigest()
            result.file_hash['sha512'] = hashlib.sha512(file_data).hexdigest()
            result.file_hash['size'] = len(file_data)
            
            # Import Hash (necesită pefile)
            try:
                pe = pefile.PE(str(file_path))
                imphash = pe.get_imphash()
                result.file_hash['imphash'] = imphash
                pe.close()
            except Exception as e:
                self.logger.warning(f"Nu s-a putut calcula imphash: {e}")
            
            self.logger.info(f"Hash-uri calculate: MD5={result.file_hash['md5'][:16]}...")
        
        except Exception as e:
            self.logger.error(f"Eroare calculare hash-uri: {e}")
            raise
