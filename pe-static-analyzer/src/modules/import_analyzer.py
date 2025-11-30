from pathlib import Path

from src.core.analyzer import AnalyzerModule, AnalysisResult, PEStaticAnalyzer
import lief
class ImportAnalyzer(AnalyzerModule):
    """
    Analiză API imports și DLL-uri importate
    Detectează API-uri suspicioase (CreateRemoteThread, VirtualAlloc, etc.)
    """
    
    SUSPICIOUS_APIS = {
        'VirtualAlloc', 'VirtualProtect', 'VirtualAllocEx',
        'CreateRemoteThread', 'WriteProcessMemory', 'ReadProcessMemory',
        'OpenProcess', 'CreateProcess', 'ShellExecute',
        'WinExec', 'URLDownloadToFile', 'InternetOpen',
        'CreateFile', 'WriteFile', 'RegSetValue', 'RegCreateKey'
    }
    
    def __init__(self):
        super().__init__("import_analyzer")
    
    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        """Analizează toate importurile"""
        try:
            binary = lief.parse(str(file_path))
            
            suspicious_imports = []
            
            for imported_lib in binary.imports:
                dll_name = imported_lib.name.lower()
                
                for func in imported_lib.entries:
                    if not func.is_ordinal:
                        func_name = func.name
                        
                        # Verificare API suspicioase
                        if func_name in self.SUSPICIOUS_APIS:
                            suspicious_imports.append(func_name)
                        
                        result.imports.append({
                            'dll': dll_name,
                            'function': func_name,
                            'address': hex(func.iat_address) if func.iat_address else 'N/A'
                        })
            
            # Adaugă flag-uri pentru API suspicioase
            if suspicious_imports:
                for api in suspicious_imports:
                    result.heuristic_flags.append(f"SUSPICIOUS_API:{api}")
            
            self.logger.info(f"Analizate {len(result.imports)} importuri, {len(suspicious_imports)} suspicioase")
        
        except Exception as e:
            self.logger.error(f"Eroare analiză imports: {e}")
