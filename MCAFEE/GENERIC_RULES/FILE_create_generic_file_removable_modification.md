# FILE IN REMOVABLE STORAGE MODIFICATION PROTECTION RULE

## Description
This rule detects the modification of any file on a removable storage.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v "**"
        }
    }
	Target {
		Match FILE {
			Include OBJECT_NAME {
				-v "**"
			}
			
			Include -file_properties "FILE_REMOVABLE FILE_FLOPPY FILE_CD"
			# Te same rule could be to protect the creation of any file by any process on a network device
			Include -file_properties "FILE_NETWORK"
			Include -access "CREATE WRITE DELETE READ EXECUTE WRITE_ATTRIBUTE SET_REPARSE"
		}
	}
}
```

## Trigger
TBC

## Notes