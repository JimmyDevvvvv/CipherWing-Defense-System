rule Enhanced_Keylogger_Detection
{
    meta:
        description = "Comprehensive keylogger detection with multiple behavioral indicators"
        author = "CipherWing Security Research"
        family = "keylogger"
        type = "malware"
        date = "2025-06-17"
        confidence = "high"
        behavior = "keystroke_logging, persistence, steganography, clipboard_monitoring"
        version = "2.1"

    strings:
        $core_api1 = "GetAsyncKeyState" ascii nocase
        $core_api2 = "SetWindowsHookExA" ascii nocase
        $core_api3 = "SetWindowsHookExW" ascii nocase
        $core_api4 = "CallNextHookEx" ascii nocase
        $core_api5 = "UnhookWindowsHookEx" ascii nocase
        $core_api6 = "GetKeyboardState" ascii nocase
        $core_api7 = "GetKeyState" ascii nocase
        $core_api8 = "MapVirtualKeyA" ascii nocase
        $core_api9 = "MapVirtualKeyW" ascii nocase
        $core_api10 = "ToAscii" ascii nocase
        $core_api11 = "ToUnicode" ascii nocase

        $window_api1 = "GetForegroundWindow" ascii nocase
        $window_api2 = "GetWindowTextA" ascii nocase
        $window_api3 = "GetWindowTextW" ascii nocase
        $window_api4 = "GetClassName" ascii nocase
        $window_api5 = "FindWindowA" ascii nocase
        $window_api6 = "FindWindowW" ascii nocase
        $window_api7 = "EnumWindows" ascii nocase
        $window_api8 = "GetWindowThreadProcessId" ascii nocase

        $clipboard_api1 = "GetClipboardData" ascii nocase
        $clipboard_api2 = "SetClipboardViewer" ascii nocase
        $clipboard_api3 = "AddClipboardFormatListener" ascii nocase
        $clipboard_api4 = "OpenClipboard" ascii nocase
        $clipboard_api5 = "EmptyClipboard" ascii nocase

        $file_api1 = "CreateFileA" ascii nocase
        $file_api2 = "CreateFileW" ascii nocase
        $file_api3 = "WriteFile" ascii nocase
        $file_api4 = "AppendFile" ascii nocase
        $file_api5 = "SetFilePointer" ascii nocase
        $file_api6 = "FlushFileBuffers" ascii nocase

        $reg_api1 = "RegSetValueExA" ascii nocase
        $reg_api2 = "RegSetValueExW" ascii nocase
        $reg_api3 = "RegCreateKeyExA" ascii nocase
        $reg_api4 = "RegCreateKeyExW" ascii nocase
        $reg_api5 = "RegOpenKeyExA" ascii nocase
        $reg_api6 = "RegOpenKeyExW" ascii nocase

        $net_api1 = "InternetOpenA" ascii nocase
        $net_api2 = "InternetOpenW" ascii nocase
        $net_api3 = "HttpSendRequestA" ascii nocase
        $net_api4 = "HttpSendRequestW" ascii nocase
        $net_api5 = "FtpPutFileA" ascii nocase
        $net_api6 = "send" ascii nocase
        $net_api7 = "WSASend" ascii nocase

        $email_api1 = "MAPISendMail" ascii nocase
        $email_api2 = "MAPILogon" ascii nocase
        $email_api3 = "MAPIFreeBuffer" ascii nocase

        $steganography1 = "BitBlt" ascii nocase
        $steganography2 = "GetDIBits" ascii nocase
        $steganography3 = "SetDIBits" ascii nocase

        $log_file1 = "log.txt" ascii wide nocase
        $log_file2 = "keylog" ascii wide nocase
        $log_file3 = "keys.dat" ascii wide nocase
        $log_file4 = "system.log" ascii wide nocase
        $log_file5 = "temp.log" ascii wide nocase
        $log_file6 = "login.txt" ascii wide nocase
        $log_file7 = "passwords.txt" ascii wide nocase
        $log_file8 = "capture.dat" ascii wide nocase

        $reg_path1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide nocase
        $reg_path2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii wide nocase
        $reg_path3 = "SYSTEM\\CurrentControlSet\\Services" ascii wide nocase

        $suspicious1 = "Password:" ascii wide nocase
        $suspicious2 = "Username:" ascii wide nocase
        $suspicious3 = "Login:" ascii wide nocase
        $suspicious4 = "Key pressed:" ascii wide nocase
        $suspicious5 = "Window title:" ascii wide nocase
        $suspicious6 = "[ENTER]" ascii wide nocase
        $suspicious7 = "[BACKSPACE]" ascii wide nocase
        $suspicious8 = "[TAB]" ascii wide nocase
        $suspicious9 = "[SHIFT]" ascii wide nocase
        $suspicious10 = "[CTRL]" ascii wide nocase

        $hook_type1 = { 0D 00 00 00 }
        $hook_type2 = { 02 00 00 00 }

        $mutex1 = "Global\\KeyLogger" ascii wide nocase
        $mutex2 = "Global\\MyKeyLogger" ascii wide nocase
        $mutex3 = "KeyLoggerMutex" ascii wide nocase

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        (
            (3 of ($core_api*)) or
            (2 of ($core_api*) and 2 of ($window_api*)) or
            (1 of ($core_api*) and 1 of ($clipboard_api*) and 2 of ($file_api*)) or
            (2 of ($core_api*) and 1 of ($reg_api*) and 2 of ($suspicious*)) or
            (2 of ($window_api*) and 2 of ($file_api*) and 1 of ($net_api*) and 2 of ($suspicious*)) or
            (1 of ($core_api*) and 1 of ($window_api*) and 1 of ($file_api*) and 1 of ($reg_api*) and 3 of ($suspicious*)) or
            (1 of ($core_api*) and 1 of ($hook_type*)) or
            (1 of ($mutex*) and 2 of ($core_api*)) or
            (1 of ($core_api*) and 1 of ($reg_path*) and 1 of ($reg_api*)) or
            (1 of ($core_api*) and 2 of ($log_file*)) or
            (1 of ($core_api*) and 1 of ($steganography*)) or
            (1 of ($email_api*))
        )
}
