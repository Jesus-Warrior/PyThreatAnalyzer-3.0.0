// Source: https://github.com/openprx/prx-sd-signatures@4c9c5977aa9058ec03b28602c37567bd0655cbe4 (yara/builtin/windows/ransomware.yar)
// Modified by PyThreatAnalyzer: removed unreferenced string declarations for compiler compatibility; see META.json.
// Original author metadata is preserved; MIT attribution: prx-sd.
// License: see PRX-SD-BUILTIN-LICENSE-MIT.txt and upstream README.

rule Ransomware_Generic_Strings
{
    meta:
        description = "Detects generic ransomware indicators via string patterns"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "high"

    strings:
        $ransom1 = "Your files have been encrypted" nocase
        $ransom2 = "All your files have been locked" nocase
        $ransom3 = "send bitcoin" nocase
        $ransom4 = "decrypt your files" nocase
        $ransom5 = "pay the ransom" nocase
        $ransom6 = "your personal decryption key" nocase
        $ransom7 = ".onion" nocase
        $crypto1 = "CryptEncrypt"
        $crypto2 = "CryptGenKey"
        $crypto3 = "CryptAcquireContext"
        $shadow = "vssadmin delete shadows" nocase
        $shadow2 = "wmic shadowcopy delete" nocase
        $bcdedit = "bcdedit /set {default} recoveryenabled no" nocase

    condition:
        (2 of ($ransom*)) or
        (1 of ($ransom*) and 1 of ($crypto*)) or
        (1 of ($shadow*) and 1 of ($crypto*)) or
        ($bcdedit and 1 of ($crypto*))
}

rule Ransomware_File_Encryption_Pattern
{
    meta:
        description = "Detects patterns typical of ransomware file encryption routines"
        author = "prx-sd"
        date = "2026-03-16"
        severity = "high"

    strings:
        $api1 = "FindFirstFileW"
        $api2 = "FindNextFileW"
        $api3 = "CryptEncrypt"
        $api4 = "MoveFileExW"
        $api5 = "DeleteFileW"
        $api6 = "WriteFile"

    condition:
        4 of them
}
