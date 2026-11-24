# expect:W202
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "READ access is high frequency"
    Process {
        Include OBJECT_NAME { -v "**\\reader.exe" }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\secret.txt" }
            Include -access "READ"
        }
    }
}
