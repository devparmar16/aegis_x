
rule AegisX_Demo_Suspicious_Keyword {
    meta:
        description = "Detects demo threat keyword"
        author = "Aegis-X Review Demo"
        severity = "High"
    strings:
        $str1 = "AEGISX_SUSPICIOUS_PAYLOAD_TRIGGER"
    condition:
        $str1
}
