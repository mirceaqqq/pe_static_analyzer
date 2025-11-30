from pathlib import Path

from src.core.analyzer import AnalyzerModule, AnalysisResult, PEStaticAnalyzer
import lief
class SectionAnalyzer(AnalyzerModule):
    """
    Analiză detaliată secțiuni PE
    Verifică: permisiuni neobișnuite, secțiuni multiple executabile, etc.
    """
    
    def __init__(self):
        super().__init__("section_analyzer")
    
    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        """Analizează toate secțiunile PE"""
        try:
            binary = lief.parse(str(file_path))
            
            executable_sections = 0
            writable_executable = []
            
            for section in binary.sections:
                # Extrage caracteristici
                characteristics = section.characteristics
                is_executable = bool(characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
                is_writable = bool(characteristics & 0x80000000)    # IMAGE_SCN_MEM_WRITE
                is_readable = bool(characteristics & 0x40000000)    # IMAGE_SCN_MEM_READ
                
                if is_executable:
                    executable_sections += 1
                
                if is_executable and is_writable:
                    writable_executable.append(section.name)
                
                result.sections.append({
                    'name': section.name,
                    'virtual_address': hex(section.virtual_address),
                    'virtual_size': section.virtual_size,
                    'raw_size': section.size,
                    'entropy': result.entropy_data.get(section.name, 0.0),
                    'executable': is_executable,
                    'writable': is_writable,
                    'readable': is_readable,
                    'characteristics': hex(characteristics)
                })
            
            # Flag-uri suspicioase
            if executable_sections > 1:
                result.heuristic_flags.append(f"MULTIPLE_EXEC_SECTIONS:{executable_sections}")
            
            if writable_executable:
                for section in writable_executable:
                    result.heuristic_flags.append(f"WRITABLE_EXECUTABLE:{section}")
            
            self.logger.info(f"Analizate {len(result.sections)} secțiuni")
        
        except Exception as e:
            self.logger.error(f"Eroare analiză secțiuni: {e}")
