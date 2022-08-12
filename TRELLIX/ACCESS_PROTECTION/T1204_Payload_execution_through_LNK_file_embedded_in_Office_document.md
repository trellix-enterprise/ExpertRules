# T1204 – Payload execution through LNK file embedded in Office document

## Author
McAfee

## Description
This rule trigger indicates an attempt to create a .lnk file from a Word application.   

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
  Process {
      Include OBJECT_NAME { -v "winword.exe" }
  }
  Target {
    Match FILE {
      Include OBJECT_NAME { -v "**\\temp\\*.lnk" }
      Include -access "CREATE"
    }
  }
}
```

## Trigger
TBC.

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
This rule is for monitoring/telemetry. Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives.
