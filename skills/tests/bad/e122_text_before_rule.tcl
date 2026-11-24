# expect:E122
# A comment before "Rule {" stops the ENS console inserting the form's Reaction,
# so this compiles as "Rule: Reaction was not set" (verified on ENS 10.7).
Rule {
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\evil.exe" }
            Include -access "CREATE"
        }
    }
}
