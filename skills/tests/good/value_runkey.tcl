Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Block writes to HKLM Run key autostart values"

    Process {
        Include OBJECT_NAME { -v "**" }
        Exclude OBJECT_NAME { -v "**\\msiexec.exe" }
        Exclude OBJECT_NAME { -v "**\\TiWorker.exe" }
    }
    Target {
        Match VALUE {
            Include OBJECT_NAME { -v "**\\CurrentVersion\\Run\\**" }
            Include -access "WRITE"
        }
    }
}
