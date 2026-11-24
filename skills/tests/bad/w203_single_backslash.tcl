# expect:W203
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Single backslash in path"
    Process {
        Include OBJECT_NAME { -v "C:\Windows\reader.exe" }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\secret.txt" }
            Include -access "WRITE"
        }
    }
}
