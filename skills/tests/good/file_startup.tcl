Rule {
    Reaction    BLOCK
    Severity    MAJOR
    Group       "Custom Expert Rules"
    Description "Block script hosts writing executables to the Startup folder"

    Process {
        Include OBJECT_NAME { -v "**\\powershell.exe" }
        Include OBJECT_NAME { -v "**\\wscript.exe" }
        Include OBJECT_NAME { -v "**\\cscript.exe" }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\Start Menu\\Programs\\Startup\\**.exe" }
            Include -access "CREATE WRITE"
        }
    }
}
