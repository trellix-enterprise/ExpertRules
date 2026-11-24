Rule {
    Reaction    BLOCK
    Severity    CRITICAL
    Group       "Custom Expert Rules"
    Description "Block raw disk writes by non-system processes"

    Process {
        Include OBJECT_NAME { -v "**" }
        Exclude OBJECT_NAME { -v "**\\System32\\**" }
    }
    Target {
        Match DISK {
            Include OBJECT_NAME { -v "**\\PhysicalDrive*" }
            Include -access "WRITE"
        }
    }
}
