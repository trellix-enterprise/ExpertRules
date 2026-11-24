# expect:E151
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "REGVAL_DATA smart match needs -type"
    Target {
        Match VALUE {
            Include REGVAL_DATA { -v "malware" }
        }
    }
}
