rule Trojan_Sample_4b27
{
    meta:
        description = "Custom YARA rule for Trojan sample 4b27..."
        author = "Jimmy CipherWing"
        hash = "4b2746ae0a820d91..."
        family = "trojan"

    strings:
        $api1 = "CreateRemoteThread" nocase
        $url = "http://evil.c2server.com" nocase
        $cmd = "cmd /c" nocase
        $blob = "SGVsbG8gV29ybGQ=" // suspicious Base64?
        $tag = "rat payload" nocase

    condition:
        uint16(0) == 0x5A4D and 3 of ($api1, $url, $cmd, $blob, $tag)
}
