# expect:E170
Rule -id "R1" {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "First rule"
}
Rule -id "R1" {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Duplicate id"
}
