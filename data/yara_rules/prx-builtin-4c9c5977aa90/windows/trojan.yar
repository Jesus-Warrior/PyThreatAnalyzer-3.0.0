// Source: https://github.com/openprx/prx-sd-signatures@4c9c5977aa9058ec03b28602c37567bd0655cbe4 (yara/builtin/windows/trojan.yar)
// Modified by PyThreatAnalyzer: removed unreferenced string declarations for compiler compatibility; see META.json.
// Original author metadata is preserved; MIT attribution: prx-sd.
// License: see PRX-SD-BUILTIN-LICENSE-MIT.txt and upstream README.

rule Trojan_Process_Injection
{
    meta:
        description = "Detects classic process injection techniques"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "high"

    strings:
        $api1 = "VirtualAllocEx"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $api4 = "OpenProcess"
        $api5 = "NtUnmapViewOfSection"

    condition:
        ($api1 and $api2 and $api3) or
        ($api1 and $api2 and $api4) or
        ($api5 and $api2)
}

rule Trojan_Keylogger_Indicators
{
    meta:
        description = "Detects keylogger behavior patterns"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "high"

    strings:
        $api1 = "SetWindowsHookExA"
        $api2 = "SetWindowsHookExW"
        $api3 = "GetAsyncKeyState"
        $api4 = "GetKeyState"
        $api5 = "GetKeyboardState"
        $api6 = "MapVirtualKeyA"
        $log1 = "keylog" nocase
        $log2 = "keystroke" nocase

    condition:
        (1 of ($api1, $api2) and 1 of ($api3, $api4, $api5)) or
        (2 of ($api*) and 1 of ($log*))
}

rule Trojan_Downloader_Generic
{
    meta:
        description = "Detects generic downloader trojan patterns"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "medium"

    strings:
        $dl1 = "URLDownloadToFileA"
        $dl2 = "URLDownloadToFileW"
        $dl3 = "InternetOpenUrlA"
        $dl4 = "InternetOpenUrlW"
        $dl5 = "HttpSendRequestA"
        $dl6 = "WinHttpSendRequest"
        $exec1 = "ShellExecuteA"
        $exec2 = "ShellExecuteW"
        $exec3 = "CreateProcessA"
        $exec4 = "CreateProcessW"
        $exec5 = "WinExec"
        $temp = "%TEMP%" nocase
        $appdata = "%APPDATA%" nocase

    condition:
        (1 of ($dl*)) and (1 of ($exec*)) and (1 of ($temp, $appdata))
}
