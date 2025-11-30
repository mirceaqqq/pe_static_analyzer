rule Suspicious_Process_Injection {
    meta:
        description = "Detecteaza pattern-uri de process injection"
        author = "Codex"
    strings:
        $a = "OpenProcess" ascii
        $b = "VirtualAllocEx" ascii
        $c = "WriteProcessMemory" ascii
        $d = "CreateRemoteThread" ascii
    condition:
        2 of ($a,$b,$c,$d)
}
