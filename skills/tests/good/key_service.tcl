Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Block deletion/modification of a protected service key"

    Process {
        Include OBJECT_NAME { -v "**" }
    }
    Target {
        Match KEY {
            Include OBJECT_NAME { -v "**\\Services\\MyProtectedSvc" }
            Include -access "DELETE WRITE"
        }
    }
}
