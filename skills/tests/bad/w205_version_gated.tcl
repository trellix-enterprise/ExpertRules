# expect:W205
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Version-gated access token"
    Process {
        Include OBJECT_NAME { -v "**\\reader.exe" }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\secret.txt" }
            Include -access "RENAME"
        }
    }
}
