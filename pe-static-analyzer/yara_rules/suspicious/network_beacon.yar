rule Suspicious_Network_Beacon {
    meta:
        description = "Detecteaza string-uri de beaconing/HTTP malware"
        author = "Codex"
    strings:
        $u1 = "User-Agent: Mozilla/4.0" ascii nocase
        $u2 = "User-Agent: Mozilla/5.0" ascii nocase
        $p1 = "cmd.exe /c" ascii
        $c2 = "connect" ascii
        $url = /http[s]?:\/\/[a-z0-9\.\-]+/ nocase
    condition:
        $url and (1 of ($u1,$u2) or $p1) and $c2
}
