from pathlib import Path
from typing import Any, Dict, List

import pefile

from src.core.analyzer import AnalyzerModule, AnalysisResult


class DisassemblerModule(AnalyzerModule):
    """
    Lightweight disassembler using Capstone for PE executables.
    Focus: entrypoint + executable sections; collects instructions and simple xrefs.
    """

    def __init__(self):
        super().__init__("disassembler")
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64  # noqa: F401
            self._capstone_available = True
        except Exception:
            self._capstone_available = False

    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        if not self._capstone_available:
            self.logger.warning("Capstone lipsește; sare disassembler")
            result.errors.append("capstone_missing")
            return

        try:
            import capstone  # type: ignore
        except Exception as e:
            result.errors.append(f"capstone_import_error:{e}")
            return

        try:
            pe = pefile.PE(str(file_path))
        except Exception as e:
            result.errors.append(f"pefile_disassembler_error:{e}")
            return

        # Arch detection
        arch = pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]
        if "AMD64" in arch or "IA64" in arch:
            cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
            arch_name = "x86_64"
        else:
            cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32
            arch_name = "x86"

        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = False

        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_va = image_base + entry_rva

        functions: List[Dict[str, Any]] = []
        sections_info: List[Dict[str, Any]] = []

        # Disassemble entrypoint (first 2048 bytes of its section)
        entry_section = self._section_from_rva(pe, entry_rva)
        if entry_section:
            code = entry_section.get_data()
            code_slice = code[:2048]
            addr_base = image_base + entry_section.VirtualAddress
            instrs = self._disasm(md, code_slice, addr_base)
            functions.append(
                {
                    "name": "entrypoint",
                    "address": hex(entry_va),
                    "section": entry_section.Name.decode(errors="ignore").strip("\x00"),
                    "instructions": instrs,
                }
            )

        # Disassemble executable sections (first 4KB each)
        for sec in pe.sections:
            characteristics = sec.Characteristics
            is_exec = bool(characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
            if not is_exec:
                continue
            sec_name = sec.Name.decode(errors="ignore").strip("\x00")
            code = sec.get_data()[:4096]
            addr_base = image_base + sec.VirtualAddress
            instrs = self._disasm(md, code, addr_base)
            sections_info.append(
                {
                    "section": sec_name,
                    "address": hex(addr_base),
                    "size": len(code),
                    "instructions": instrs,
                }
            )

        result.disassembly = {
            "arch": arch_name,
            "entrypoint": hex(entry_va),
            "functions": functions,
            "sections": sections_info,
        }

        # Heuristic flags
        if functions and len(functions[0].get("instructions", [])) < 3:
            result.heuristic_flags.append("SHORT_ENTRYPOINT")

        self.logger.info(
            "Disassembly: arch=%s, funcs=%d, sections=%d",
            arch_name,
            len(functions),
            len(sections_info),
        )

        pe.close()

    def _disasm(self, md, code: bytes, base_addr: int) -> List[Dict[str, Any]]:
        instrs = []
        for ins in md.disasm(code, base_addr):
            instrs.append(
                {
                    "address": hex(ins.address),
                    "mnemonic": ins.mnemonic,
                    "op_str": ins.op_str,
                }
            )
        return instrs

    def _section_from_rva(self, pe: pefile.PE, rva: int):
        for sec in pe.sections:
            start = sec.VirtualAddress
            end = start + sec.Misc_VirtualSize
            if start <= rva < end:
                return sec
        return None
