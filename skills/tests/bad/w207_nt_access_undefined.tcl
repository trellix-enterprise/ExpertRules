# expect:W207
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "nt_access mask has undefined bits"
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\secret.txt" }
            Include -nt_access "0x8000"
        }
    }
}
