# expect:E130
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Unknown object type"
    Target {
        Match WIDGET {
            Include OBJECT_NAME { -v "**\\x" }
        }
    }
}
