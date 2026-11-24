# expect:I302
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "nt_access mask decodes to named rights"
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "**\\target.exe" }
            Include -nt_access "0x1"
        }
    }
}
