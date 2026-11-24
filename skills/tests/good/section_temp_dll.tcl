Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Block executable section mapping from the temp directory"

    Process {
        Include OBJECT_NAME { -v "**\\rundll32.exe" }
    }
    Target {
        Match SECTION {
            Include OBJECT_NAME { -v "**\\Temp\\**.dll" }
            Include -access "EXECUTE"
        }
    }
}
