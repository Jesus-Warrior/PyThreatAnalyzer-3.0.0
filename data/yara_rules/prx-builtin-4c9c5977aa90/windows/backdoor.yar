// Source: https://github.com/openprx/prx-sd-signatures@4c9c5977aa9058ec03b28602c37567bd0655cbe4 (yara/builtin/windows/backdoor.yar)
// Modified by PyThreatAnalyzer: removed unreferenced string declarations for compiler compatibility; see META.json.
// Original author metadata is preserved; MIT attribution: prx-sd.
// License: see PRX-SD-BUILTIN-LICENSE-MIT.txt and upstream README.

rule Backdoor_Reverse_Shell
{
    meta:
        description = "Detects reverse shell patterns"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "critical"

    strings:
        $ws1 = "WSAStartup"
        $ws2 = "WSASocketA"
        $ws3 = "WSASocketW"
        $sock1 = "socket"
        $sock2 = "connect"
        $sock3 = "bind"
        $cmd1 = "cmd.exe" nocase
        $cmd2 = "/bin/sh"
        $cmd3 = "/bin/bash"
        $pipe1 = "CreatePipe"
        $pipe2 = "PeekNamedPipe"
        $proc1 = "CreateProcessA"
        $proc2 = "CreateProcessW"

    condition:
        (1 of ($ws*) or 1 of ($sock*)) and
        (1 of ($cmd*)) and
        (1 of ($proc*) or 1 of ($pipe*))
}

rule Backdoor_Persistence_Registry
{
    meta:
        description = "Detects registry-based persistence mechanisms"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "high"

    strings:
        $reg1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $reg3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase
        $reg4 = "SYSTEM\\CurrentControlSet\\Services" nocase
        $api1 = "RegSetValueExA"
        $api2 = "RegSetValueExW"
        $api3 = "RegCreateKeyExA"
        $api4 = "RegCreateKeyExW"

    condition:
        (1 of ($reg*)) and (1 of ($api*))
}

rule Backdoor_C2_Communication
{
    meta:
        description = "Detects command-and-control communication patterns"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "high"

    strings:
        $http1 = "InternetOpenA"
        $http2 = "InternetOpenW"
        $http3 = "HttpOpenRequestA"
        $http4 = "HttpSendRequestA"
        $http5 = "InternetReadFile"
        $sleep1 = "Sleep"
        $loop1 = "beacon" nocase
        $loop2 = "heartbeat" nocase
        $enc1 = "CryptEncrypt"
        $enc2 = "base64" nocase

    condition:
        (2 of ($http*)) and ($sleep1) and
        (1 of ($loop*) or 1 of ($enc*))
}
