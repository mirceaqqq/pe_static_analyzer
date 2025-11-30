rule Suspicious_Crypto_Miner {
    meta:
        description = "Detecteaza string-uri asociate cu mineri crypto"
        author = "Codex"
    strings:
        $k1 = "stratum+tcp://" ascii
        $k2 = "minerd" ascii
        $k3 = "xmrig" ascii
        $k4 = "cpuminer" ascii
        $pool = /[a-z0-9\.\-]+:3333/ ascii
    condition:
        $k1 or $k2 or $k3 or $k4 or $pool
}
