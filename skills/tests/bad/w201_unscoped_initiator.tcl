# expect:W201
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Unscoped initiator matches everything"
    Process {
        Include OBJECT_NAME { -v "**" }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\secret.txt" }
            Include -access "WRITE"
        }
    }
}
