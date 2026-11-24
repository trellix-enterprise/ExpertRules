# expect:E153
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Cannot specify both -name and -key"
    Target {
        Match KEY {
            Include OBJECT_NAME -name "a" -key "b" { -v "x" }
        }
    }
}
