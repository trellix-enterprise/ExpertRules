Rule {
    # Symbolic bitmask values as accepted by the ENS rule compiler
    # (compile-checked on ENS 10.7.20).
    Process {
        Include OBJECT_NAME { -v "**" }
        Exclude VTP_PRIVILEGES -type BITMASK { -v ISG }
        Exclude VTP_TRUST true
    }
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\*.exe" }
            Include DRIVE_TYPE { -v "DT_REMOVABLE" }
            Include -file_attributes "HIDDEN"
            Include -access "EXECUTE"
        }
    }
}
