# TODO: PE Parser module
from pathlib import Path

from src.core.analyzer import AnalyzerModule, AnalysisResult, PEStaticAnalyzer
import lief
class PEParser(AnalyzerModule):
    """
    Parser complet structură PE folosind LIEF și pefile
    Extrage: header, opțional header, secțiuni, importuri, exporturi
    """
    
    def __init__(self):
        super().__init__("pe_parser")
    
    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        """Parsează structura completă PE"""
        try:
            # Parsing cu LIEF (mai robust)
            binary = lief.parse(str(file_path))
            
            if not binary:
                raise ValueError("Fișier PE invalid sau corupt")
            
            # DOS Header
            result.pe_info['dos_header'] = {
                'e_magic': 'MZ',
                'e_lfanew': binary.dos_header.addressof_new_exeheader
            }
            
            # PE Header
            result.pe_info['pe_header'] = {
                'signature': 'PE',
                'machine': str(binary.header.machine),
                'number_of_sections': binary.header.numberof_sections,
                'time_date_stamp': int(binary.header.time_date_stamps),
                'characteristics': int(binary.header.characteristics)
            }
            
            # Optional Header
            opt = binary.optional_header
            result.pe_info['optional_header'] = {
                'magic': str(opt.magic),  # opt.magic este un enum (PE_TYPE)
                'image_base': hex(opt.imagebase),
                'entry_point': hex(opt.addressof_entrypoint),
                'code_base': hex(opt.baseof_code),
                'section_alignment': opt.section_alignment,
                'file_alignment': opt.file_alignment,
                'subsystem': str(opt.subsystem),
                'dll_characteristics': int(opt.dll_characteristics),
                'size_of_image': opt.sizeof_image,
                'size_of_headers': opt.sizeof_headers
            }
            
            # Data Directories
            result.pe_info['data_directories'] = []
            for directory in binary.data_directories:
                if directory.size > 0:
                    result.pe_info['data_directories'].append({
                        'type': str(directory.type),
                        'rva': hex(directory.rva),
                        'size': directory.size
                    })

            # Exported symbols
            result.exports = []
            if binary.has_exports:
                for exp in binary.exported_functions:
                    result.exports.append({
                        'name': exp.name,
                        'address': hex(exp.address) if exp.address else 'N/A',
                        'ordinal': exp.ordinal
                    })
            
            self.logger.info(f"Structură PE parsată: {binary.header.numberof_sections} secțiuni")
        
        except Exception as e:
            self.logger.error(f"Eroare parsing PE: {e}")
            raise
