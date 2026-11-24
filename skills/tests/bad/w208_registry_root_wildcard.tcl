# expect:W208
Rule {
    Reaction BLOCK
    Target {
        Match VALUE {
            Include OBJECT_NAME { -v "HK*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\*" }
            Include -access "CREATE WRITE"
        }
    }
}
