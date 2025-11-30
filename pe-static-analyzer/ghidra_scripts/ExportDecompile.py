# Ghidra headless Jython script
# Usage: -postScript ExportDecompile.py <output_json>
# Produces: JSON cu functii (name, address, source, lines) si graf (nodes/edges)

import json
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.block import BasicBlockModel


def run():
    args = getScriptArgs()
    if currentProgram is None:
        println("No program loaded")
        return
    if not args:
        println("Output path not specified")
        return

    out_path = args[0]
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    ifc.setSimplificationStyle("decompile")

    listing = currentProgram.getListing()
    funcs = listing.getFunctions(True)
    functions = []
    graphs = []

    bbm = BasicBlockModel(currentProgram)

    while funcs.hasNext() and not monitor.isCancelled():
        f = funcs.next()
        fn = {"name": f.getName(), "address": str(f.getEntryPoint())}

        res = ifc.decompileFunction(f, 60, monitor)
        if res and res.getDecompiledFunction():
            c = res.getDecompiledFunction().getC()
            fn["source"] = c
            fn["lines"] = c.splitlines()
        else:
            fn["source"] = "// decompilare indisponibila"
            fn["lines"] = []
        functions.append(fn)

        g = {"name": f.getName(), "nodes": [], "edges": []}
        it = bbm.getCodeBlocksContaining(f.getBody(), monitor)
        while it.hasNext() and not monitor.isCancelled():
            block = it.next()
            g["nodes"].append({"label": str(block.getFirstStartAddress())})
            dests = block.getDestinations(monitor)
            while dests.hasNext():
                ref = dests.next()
                g["edges"].append(
                    {
                        "src": str(block.getFirstStartAddress()),
                        "dst": str(ref.getDestinationBlock().getFirstStartAddress()),
                    }
                )
        graphs.append(g)

    root = {"functions": functions, "graphs": graphs}
    with open(out_path, "w") as fh:
        fh.write(json.dumps(root, indent=2))
    println("Export complet: %s" % out_path)


if __name__ == "__main__":
    run()
