# expect:E150
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Unknown access token"
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\x" }
            Include -access "BOGUS_TOKEN"
        }
    }
}
