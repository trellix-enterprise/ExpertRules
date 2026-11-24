# expect:E154
Rule {
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\evil.exe" }
            Include FILE_HIDDEN { -v "1" }
            Include -access "CREATE"
        }
    }
}
