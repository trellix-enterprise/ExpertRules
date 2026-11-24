# expect:E150
Rule {
    Reaction BLOCK
    Target {
        Match SECTION {
            Include OBJECT_NAME { -v "**" }
            Include -access "CREATE"
            Include -nt_access "!0x40"
        }
    }
}
