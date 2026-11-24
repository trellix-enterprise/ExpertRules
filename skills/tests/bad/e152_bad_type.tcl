# expect:E152
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Unknown -type value"
    Target {
        Match FILE {
            Include OBJECT_NAME -type NONSENSE { -v "**\\x" }
        }
    }
}
