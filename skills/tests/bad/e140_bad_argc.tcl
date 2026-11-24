# expect:E140
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Match has too many arguments"
    Target {
        Match FILE EXTRA {
            Include OBJECT_NAME { -v "**\\x" }
        }
    }
}
