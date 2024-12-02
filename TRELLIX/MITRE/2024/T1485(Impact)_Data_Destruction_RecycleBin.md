# T1485(Impact) Data Destruction - Recycle Bin

## Author
Trellix

## Description
This Expert rule detects deletion of files in Recycle.Bin folder and its sub-folders.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\\$Recycle.Bin\\**" }
            Include -access "DELETE"
        }
    }
}
```

## Tested Platforms
NA

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.

