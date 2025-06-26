rule High_Confidence_Malware
{
    meta:
        description = "High confidence malware detection with low false positives"
        author = "Security Analyst"
        date = "2025-06-17"
        version = "4.0"
        family = "malware"
        
    strings:
        // PE header
        $pe_header = { 4D 5A }
        
        // === OBVIOUS MALWARE STRINGS (Instant detection) ===
        $obvious1 = "your files have been encrypted" nocase
        $obvious2 = "bitcoin payment required" nocase
        $obvious3 = "decrypt_instruction" nocase
        $obvious4 = "ransomware" fullword nocase
        $obvious5 = "your computer is infected" nocase
        $obvious6 = "pay ransom" nocase
        $obvious7 = ".onion" nocase
        $obvious8 = "keylogger initialized" nocase
        $obvious9 = "backdoor established" nocase
        $obvious10 = "rootkit loaded" nocase
        
        // === MALICIOUS BEHAVIORAL COMBINATIONS ===
        
        // Complete keylogger pattern (need ALL these together)
        $keylog_hook = "SetWindowsHookEx" nocase
        $keylog_keyboard = "WH_KEYBOARD_LL" nocase
        $keylog_key = "GetAsyncKeyState" nocase
        $keylog_hide = "ShowWindow" nocase
        
        // Process hollowing/injection (suspicious combo)
        $hollow1 = "CreateProcess" nocase
        $hollow2 = "WriteProcessMemory" nocase
        $hollow3 = "ResumeThread" nocase
        $hollow4 = "CREATE_SUSPENDED" nocase
        
        // Ransomware file operations
        $ransom_crypt1 = "CryptEncrypt" nocase
        $ransom_crypt2 = "CryptGenKey" nocase
        $ransom_pattern1 = "*.doc" nocase
        $ransom_pattern2 = "*.pdf" nocase
        $ransom_pattern3 = "*.jpg" nocase
        $ransom_delete = "vssadmin delete shadows" nocase
        
        // Anti-analysis (strong indicators when combined)
        $anti_debug1 = "IsDebuggerPresent" nocase
        $anti_debug2 = "CheckRemoteDebuggerPresent" nocase
        $anti_vm1 = "vmware" fullword nocase
        $anti_vm2 = "virtualbox" fullword nocase
        $anti_vm3 = "sandboxie" fullword nocase
        
        // Network + stealth combo
        $stealth_net1 = "InternetOpen" nocase
        $stealth_net2 = "URLDownloadToFile" nocase
        $stealth_hide1 = "SetFileAttributes" nocase  
        $stealth_hide2 = "FILE_ATTRIBUTE_HIDDEN" nocase
        $stealth_persist = "\\CurrentVersion\\Run" nocase
        
        // Bot/RAT command patterns
        $bot_cmd1 = "download_execute" nocase
        $bot_cmd2 = "update_config" nocase
        $bot_cmd3 = "screenshot" nocase
        $bot_cmd4 = "keylog_start" nocase
        
        // Suspicious strings that indicate malicious intent
        $susp_string1 = "disable_antivirus" nocase
        $susp_string2 = "bypass_uac" nocase
        $susp_string3 = "elevate_privileges" nocase
        $susp_string4 = "inject_dll" nocase
        
    condition:
        $pe_header at 0 and
        (
            // Instant malware detection
            any of ($obvious*) or
            
            // Complete keylogger pattern
            ($keylog_hook and $keylog_keyboard and $keylog_key and $keylog_hide) or
            
            // Process hollowing pattern  
            ($hollow1 and $hollow2 and $hollow3 and $hollow4) or
            
            // Ransomware pattern
            (any of ($ransom_crypt*) and 2 of ($ransom_pattern*) and $ransom_delete) or
            
            // Anti-analysis + network (evasive malware)
            (2 of ($anti_debug*, $anti_vm*) and any of ($stealth_net*)) or
            
            // Stealth network + persistence (backdoor/trojan)
            (any of ($stealth_net*) and any of ($stealth_hide*) and $stealth_persist) or
            
            // Bot/RAT command pattern
            (2 of ($bot_cmd*)) or
            
            // Multiple suspicious behaviors
            (any of ($susp_string*) and 2 of ($anti*, $stealth*))
        )
}

rule Common_Malware_Patterns
{
    meta:
        description = "Detects common malware patterns with medium confidence"
        author = "Security Analyst"
        family = "malware"
        
    strings:
        $pe_header = { 4D 5A }
        
        // Crypto mining indicators
        $crypto1 = "stratum+tcp://" nocase
        $crypto2 = "xmr-stak" nocase
        $crypto3 = "cryptonight" nocase
        $crypto4 = "mining.pool" nocase
        
        // Remote access patterns
        $remote1 = "reverse_tcp" nocase
        $remote2 = "bind_tcp" nocase
        $remote3 = "meterpreter" nocase
        $remote4 = "shell_reverse_tcp" nocase
        
        // Data theft patterns
        $steal1 = "password" nocase
        $steal2 = "credential" nocase
        $steal3 = "cookie" nocase
        $steal4 = "browser" nocase
        $steal5 = "wallet" nocase
        
        // Network scanning
        $scan1 = "port_scan" nocase
        $scan2 = "network_scan" nocase
        $scan3 = "vulnerability_scan" nocase
        
        // Persistence mechanisms
        $persist1 = "schtasks" nocase
        $persist2 = "at.exe" nocase
        $persist3 = "wmic" nocase
        $persist4 = "reg add" nocase
        
    condition:
        $pe_header at 0 and
        (
            // Crypto mining
            (2 of ($crypto*)) or
            
            // Remote access tools
            (any of ($remote*)) or
            
            // Data theft + network
            (2 of ($steal*) and filesize < 10MB) or
            
            // Network scanning tools
            (any of ($scan*)) or
            
            // Persistence + small size (typical malware)
            (any of ($persist*) and filesize < 5MB)
        )
}

rule Packed_Malware
{
    meta:
        description = "Detects packed executables with suspicious characteristics"
        author = "Security Analyst"
        family = "malware"
        
    strings:
        $pe_header = { 4D 5A }
        
        // Packer signatures
        $upx1 = "UPX!" nocase
        $upx2 = "UPX0" nocase
        $upx3 = "UPX1" nocase
        $aspack = "ASPack" nocase
        $pecompact = "PECompact" nocase
        $fsg = "FSG!" nocase
        
        // Suspicious section names
        $sect1 = ".UPX0" nocase
        $sect2 = ".UPX1" nocase
        $sect3 = ".aspack" nocase
        $sect4 = ".packed" nocase
        
        // Network capability (to differentiate from legitimate packed software)
        $net1 = "InternetOpen" nocase
        $net2 = "URLDownloadToFile" nocase
        $net3 = "WinHttpOpen" nocase
        $net4 = "socket" nocase
        
        // Suspicious behavior for packed files
        $behavior1 = "CreateMutex" nocase
        $behavior2 = "RegSetValue" nocase
        $behavior3 = "WriteFile" nocase
        
    condition:
        $pe_header at 0 and
        (any of ($upx*, $aspack, $pecompact, $fsg) or any of ($sect*)) and
        any of ($net*) and
        any of ($behavior*) and
        filesize < 2MB  // Packed malware is usually smaller
}