rule IsPEExecutable {
    meta:
        description = "Detects standard Windows MZ Portable Executable signature"
        severity = "Info"
    strings:
        $mz = { 4d 5a } // "MZ" signature at the beginning of the file
    condition:
        $mz at 0
}

rule SuspiciousShellcodeExecution {
    meta:
        description = "Detects strings often associated with shellcode and command execution"
        severity = "Medium"
    strings:
        $s1 = "cmd.exe /c" ascii wide nocase
        $s2 = "powershell.exe -ep" ascii wide nocase
        $s3 = "powershell -WindowStyle Hidden" ascii wide nocase
        $s4 = "Bypass -WindowStyle" ascii wide nocase
        $s5 = "VirtualAlloc" ascii wide
        $s6 = "WriteProcessMemory" ascii wide
        $s7 = "CreateRemoteThread" ascii wide
    condition:
        // Match suspicious command-line execution or combinations of process injection APIs (never single imports alone)
        ($s1 or $s2 or $s3 or $s4) or (2 of ($s5, $s6, $s7))
}

rule EvasionStringPatterns {
    meta:
        description = "Detects anti-debugging and evasion indicators in strings"
        severity = "Medium"
    strings:
        $e1 = "IsDebuggerPresent" ascii wide
        $e2 = "CheckRemoteDebuggerPresent" ascii wide
        $e3 = "NtQueryInformationProcess" ascii wide
    condition:
        // Match advanced evasion API or multiple anti-debugging APIs together
        $e3 or (2 of ($e1, $e2))
}

rule ProcessHollowingSuspiciousAPIs {
    meta:
        description = "Detects combinations of APIs typically used in process hollowing or remote thread hijacking techniques"
        severity = "High"
    strings:
        $p1 = "NtUnmapViewOfSection" ascii wide
        $p2 = "ZwUnmapViewOfSection" ascii wide
        $p3 = "SetThreadContext" ascii wide
        $p4 = "ResumeThread" ascii wide
        $p5 = "VirtualAllocEx" ascii wide
        $p6 = "QueueUserAPC" ascii wide
    condition:
        // Requires at least 3 of these specific process hijacking APIs to be present
        3 of them
}

rule RansomwareBehavioralPatterns {
    meta:
        description = "Detects cryptographic encryption coupled with recursive directory enumeration, typical of ransomware payload structures"
        severity = "Critical"
    strings:
        $f1 = "FindFirstFileW" ascii wide
        $f2 = "FindFirstFileA" ascii wide
        $f3 = "FindNextFileW" ascii wide
        $f4 = "FindNextFileA" ascii wide
        $c1 = "CryptEncrypt" ascii wide
        $c2 = "BCryptEncrypt" ascii wide
        $c3 = "CryptGenKey" ascii wide
        $r1 = "HELP_DECRYPT" ascii wide nocase
        $r2 = "YOUR_FILES_ARE_ENCRYPTED" ascii wide nocase
        $r3 = "ransom" ascii wide nocase
    condition:
        // Directory search APIs AND Crypto APIs AND any ransom note indicators
        (any of ($f*)) and (any of ($c*)) and (any of ($r*))
}

rule KeyloggerHookingBehaviors {
    meta:
        description = "Detects hooking or keystroke monitoring APIs associated with keyloggers or spy agent malware"
        severity = "High"
    strings:
        $k1 = "SetWindowsHookEx" ascii wide
        $k2 = "GetAsyncKeyState" ascii wide
        $k3 = "GetKeyboardState" ascii wide
        $k4 = "MapVirtualKey" ascii wide
    condition:
        // Requires at least two hook or polling APIs in combination
        2 of them
}

rule SuspiciousDownloaderC2 {
    meta:
        description = "Detects strings and user agents frequently matching downloader backdoors or custom remote access tools (RATs)"
        severity = "High"
    strings:
        $u1 = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)" ascii wide // standard spoofed agent
        $u2 = "URLDownloadToFile" ascii wide
        $u3 = "InternetReadFile" ascii wide
        $u4 = "InternetOpenUrl" ascii wide
    condition:
        // URL Download API combined with suspicious legacy spoofed browser user agent
        $u1 and (any of ($u2, $u3, $u4))
}
