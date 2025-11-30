rule Example_Rule {
    meta:
        description = "Example YARA rule"
    strings:
        $a = "test"
    condition:
        $a
}
