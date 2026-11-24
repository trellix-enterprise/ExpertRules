Rule {
    Reaction    BLOCK
    Severity    CRITICAL
    Group       "Custom Expert Rules"
    Description "Block VM_WRITE/CREATE_THREAD access to lsass.exe"

    Process {
        Include OBJECT_NAME { -v "**" }
        Exclude OBJECT_NAME { -v "**\\MsMpEng.exe" }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "**\\lsass.exe" }
            Include -nt_access "!0x0020 !0x0002"
        }
    }
}
