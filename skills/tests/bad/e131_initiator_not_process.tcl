# expect:E131
Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Initiator must be PROCESS"
    Initiator {
        Match FILE {
            Include OBJECT_NAME { -v "**\\x.exe" }
        }
    }
}
