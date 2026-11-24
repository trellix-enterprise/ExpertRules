# expect:E155
Rule {
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\*.exe" }
            Include DRIVE_TYPE { -v "REMOVABLE" }
            Include -access "EXECUTE"
        }
    }
}
