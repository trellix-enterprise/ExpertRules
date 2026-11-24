# expect:E140
Rule {
    Reaction BLOCK
    set tempdirs [iSystem users_folders Temp]
    Target {
        Match FILE {
            Include OBJECT_NAME { -sfx "\\testfile.txt" -l $tempdirs }
            Include -access "CREATE"
        }
    }
}
