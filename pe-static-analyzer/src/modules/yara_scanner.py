from pathlib import Path
from typing import Optional

from src.core.analyzer import AnalyzerModule, AnalysisResult, PEStaticAnalyzer
import yara
class YARAScanner(AnalyzerModule):
    """
    Scanner cu reguli YARA
    Suportă: reguli custom, malware signatures, packer detection
    """
    
    def __init__(self, rules_path: Optional[Path] = None):
        super().__init__("yara_scanner")
        self.rules_path = rules_path or Path("yara_rules")
        self.compiled_rules = None
        
        if self.rules_path.exists():
            self._compile_rules()
    
    def _compile_rules(self):
        """Compilează toate regulile YARA din director"""
        try:
            rule_files = {}
            
            for rule_file in self.rules_path.rglob("*.yar"):
                namespace = rule_file.stem
                rule_files[namespace] = str(rule_file)
            
            if rule_files:
                self.compiled_rules = yara.compile(filepaths=rule_files)
                self.logger.info(f"Compilate {len(rule_files)} fișiere YARA")
        
        except Exception as e:
            self.logger.error(f"Eroare compilare reguli YARA: {e}")
    
    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        """Scanează fișierul cu reguli YARA"""
        if not self.compiled_rules:
            self.logger.warning("Nu există reguli YARA compilate")
            return
        
        try:
            matches = self.compiled_rules.match(str(file_path))
            
            for match in matches:
                match_info = {
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'strings': []
                }
                
                for string_match in match.strings:
                    match_info['strings'].append({
                        'offset': string_match.instances[0].offset,
                        'identifier': string_match.identifier,
                        'data': string_match.instances[0].matched_data[:50].hex()
                    })
                
                result.yara_matches.append(match_info)
                result.heuristic_flags.append(f"YARA_MATCH:{match.rule}")
            
            self.logger.info(f"Detectate {len(matches)} match-uri YARA")
        
        except Exception as e:
            self.logger.error(f"Eroare scanare YARA: {e}")
