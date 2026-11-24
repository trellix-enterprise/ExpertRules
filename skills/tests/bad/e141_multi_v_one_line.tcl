# expect:E141
Rule {
    Reaction BLOCK
    Target {
        Match VALUE {
            Include OBJECT_NAME { -v "HKLM\\Software\\Example\\Value" }
            Include REGVAL_DATA -type MULTI_STRING { -v "alpha" -v "beta" }
            Include -access "CREATE WRITE"
        }
    }
}
