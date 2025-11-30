from .hash_calculator import HashCalculator
from .pe_parser import PEParser
from .entropy_analyzer import EntropyAnalyzer
from .import_analyzer import ImportAnalyzer
from .section_analyzer import SectionAnalyzer
from .signature_analyzer import SignatureAnalyzer
from .packer_detector import PackerDetector
from .yara_scanner import YARAScanner
from .virus_total import VirusTotalModule
from .strings_analyzer import StringsAnalyzer
from .resource_analyzer import ResourceAnalyzer
from .disassembler import DisassemblerModule
from .pseudo_decompiler import PseudoDecompiler
from .ghidra_bridge import GhidraBridge


def create_default_modules():
    """Creează și returnează toate modulele default"""
    return [
        HashCalculator(),
        PEParser(),
        EntropyAnalyzer(),
        ImportAnalyzer(),
        SectionAnalyzer(),
        SignatureAnalyzer(),
        PackerDetector(),
        YARAScanner(),
        VirusTotalModule(),
        StringsAnalyzer(),
        ResourceAnalyzer(),
        DisassemblerModule(),
        PseudoDecompiler(),
        GhidraBridge(),
    ]
