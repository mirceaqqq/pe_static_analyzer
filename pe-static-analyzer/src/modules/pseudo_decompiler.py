from pathlib import Path
from typing import Any, Dict, List

import pefile

from src.core.analyzer import AnalyzerModule, AnalysisResult


class PseudoDecompiler(AnalyzerModule):
    """
    Pseudo-decompiler inspirat de Ghidra: produce C-like (best effort) și un CFG textual.
    Folosește Capstone; dacă lipsește, trece peste fără să oprească analiza.
    """

    def __init__(self):
        super().__init__("pseudo_decompiler")
        try:
            from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64  # noqa: F401
            self._capstone_available = True
        except Exception:
            self._capstone_available = False

    def analyze(self, file_path: Path, result: AnalysisResult) -> None:
        if not self._capstone_available:
            result.heuristic_flags.append("PSEUDO_SKIPPED_NO_CAPSTONE")
            return

        try:
            import capstone  # type: ignore
        except Exception as e:
            result.errors.append(f"capstone_import_error:{e}")
            return

        try:
            pe = pefile.PE(str(file_path))
        except Exception as e:
            result.errors.append(f"pefile_pseudo_error:{e}")
            return

        arch = pefile.MACHINE_TYPE[pe.FILE_HEADER.Machine]
        if "AMD64" in arch or "IA64" in arch:
            cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_64
        else:
            cs_arch, cs_mode = capstone.CS_ARCH_X86, capstone.CS_MODE_32

        md = capstone.Cs(cs_arch, cs_mode)
        md.detail = False

        image_base = pe.OPTIONAL_HEADER.ImageBase
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_va = image_base + entry_rva
        entry_section = self._section_from_rva(pe, entry_rva)

        functions: List[Dict[str, Any]] = []
        graphs: List[Dict[str, Any]] = []

        # Helper to build pseudo + cfg for a blob
        def build_func(name: str, addr_base: int, code_bytes: bytes):
            instrs = list(md.disasm(code_bytes, addr_base))[:800]
            pseudo_lines = self._pseudoize(instrs)
            cfg = self._build_cfg(instrs)
            functions.append(
                {
                    "name": name,
                    "address": hex(addr_base),
                    "source": "\n".join(pseudo_lines),
                    "lines": pseudo_lines,
                }
            )
            graphs.append({"name": name, "nodes": cfg["nodes"], "edges": cfg["edges"]})

        if entry_section:
            code = entry_section.get_data()[:4096]
            addr_base = image_base + entry_section.VirtualAddress
            build_func("entrypoint", addr_base, code)

        # First executable section (if different from entry)
        for sec in pe.sections:
            characteristics = sec.Characteristics
            is_exec = bool(characteristics & 0x20000000)
            if not is_exec:
                continue
            addr_base = image_base + sec.VirtualAddress
            name = sec.Name.decode(errors="ignore").strip("\x00") or "exec_section"
            if functions and functions[0]["address"] == hex(addr_base):
                continue
            code = sec.get_data()[:4096]
            build_func(name, addr_base, code)
            break  # only first exec section for brevity

        result.pseudocode = functions
        result.func_graphs = graphs
        pe.close()

    # --- Helpers ---
    def _pseudoize(self, instrs) -> List[str]:
        lines = []
        indent = 0
        for ins in instrs:
            mnem = ins.mnemonic
            ops = ins.op_str
            addr = hex(ins.address)
            if mnem == "ret":
                lines.append("    " * indent + "return;")
                continue
            if mnem.startswith("call"):
                lines.append("    " * indent + f"{self._fmt_call(ops)}; // {addr}")
                continue
            if mnem.startswith("j"):
                cond = self._fmt_jump(mnem, ops)
                lines.append("    " * indent + cond + f" // {addr}")
                continue
            if mnem == "mov":
                parts = ops.split(",")
                if len(parts) == 2:
                    dst = parts[0].strip()
                    src = parts[1].strip()
                    lines.append("    " * indent + f"{dst} = {src}; // {addr}")
                    continue
            if mnem in ("push", "pop"):
                lines.append("    " * indent + f"// {mnem} {ops} ({addr})")
                continue
            lines.append("    " * indent + f"// {mnem} {ops} ({addr})")
        return lines

    def _fmt_call(self, ops: str) -> str:
        # best-effort pretty call
        target = ops.replace("ptr", "").strip()
        return f"{target}()"

    def _fmt_jump(self, mnem: str, ops: str) -> str:
        if mnem == "jmp":
            return f"goto {ops};"
        if mnem in ("je", "jz"):
            return f"if (==) goto {ops};"
        if mnem in ("jne", "jnz"):
            return f"if (!=) goto {ops};"
        if mnem in ("ja", "jg", "jnbe"):
            return f"if (>) goto {ops};"
        if mnem in ("jb", "jl", "jnae"):
            return f"if (<) goto {ops};"
        return f"if (cond) goto {ops};"

    def _build_cfg(self, instrs) -> Dict[str, Any]:
        nodes = []
        edges = []
        leaders = set()
        addrs = [ins.address for ins in instrs]
        addr_to_index = {a: i for i, a in enumerate(addrs)}
        if addrs:
            leaders.add(addrs[0])
        for ins in instrs:
            if ins.mnemonic.startswith("j") or ins.mnemonic.startswith("call"):
                try:
                    target = int(ins.op_str, 16)
                    leaders.add(target)
                    next_idx = addr_to_index.get(ins.address) + 1
                    if next_idx < len(addrs):
                        leaders.add(addrs[next_idx])
                except Exception:
                    pass
        leaders = sorted(leaders)
        leader_set = set(leaders)
        for leader in leaders:
            block_instrs = []
            idx = addr_to_index.get(leader, None)
            if idx is None:
                continue
            while idx < len(instrs):
                ins = instrs[idx]
                block_instrs.append(f"{hex(ins.address)}: {ins.mnemonic} {ins.op_str}")
                idx += 1
                if idx < len(instrs) and instrs[idx].address in leader_set and instrs[idx].address != leader:
                    break
            nodes.append({"label": hex(leader), "lines": block_instrs})
        for ins in instrs:
            if ins.mnemonic.startswith("j") or ins.mnemonic.startswith("call"):
                try:
                    target = hex(int(ins.op_str, 16))
                    edges.append({"src": hex(ins.address), "dst": target})
                except Exception:
                    continue
        return {"nodes": nodes, "edges": edges}

    def _section_from_rva(self, pe: pefile.PE, rva: int):
        for sec in pe.sections:
            start = sec.VirtualAddress
            end = start + sec.Misc_VirtualSize
            if start <= rva < end:
                return sec
        return None
