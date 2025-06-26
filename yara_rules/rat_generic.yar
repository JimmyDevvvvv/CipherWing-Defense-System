rule RAT_Generic
{
    meta:
        description = "Generic Remote Access Trojan"
        author = "CipherWing"
        family = "rat"
        type = "malware"
        confidence = "0.7"
        behavior = "Reverse shell, persistence, keylogging"

    strings:
        $api_socket = "connect" nocase
        $api_shell = "WinExec" nocase
        $cmd = "cmd.exe" nocase
        $ps = "powershell.exe" nocase
        $mutex = "CreateMutexA" nocase
        $runkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $clipboard = "GetClipboardData" nocase
        $mz = { 4D 5A }

    condition:
        $mz at 0 and
        (
            2 of ($api_*) and
            1 of ($cmd, $ps, $mutex, $clipboard, $runkey)
        )
}
