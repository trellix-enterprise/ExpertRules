# T1083 scheduled task

## Author
Trellix

## Description
This Expert rule detects scheduled tasks creation.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
    Process {
        Include AggregateMatch -xtype "inc1" {
            Include OBJECT_NAME { -v "**" }
            Exclude OBJECT_NAME { -v "WSQMCONS.exe" }
            Exclude OBJECT_NAME { -v "%programfiles%\\Common Files\\microsoft shared\\ClickToRun\\*.exe" }
            Exclude OBJECT_NAME { -v "%programfiles(x86)%\\Common Files\\microsoft shared\\ClickToRun\\*.exe" }
            Exclude OBJECT_NAME { -v "%programfiles%\\microsoft office\\**.exe" }
            Exclude OBJECT_NAME { -v "%programfiles(x86)%\\microsoft office\\**.exe" }
            Exclude OBJECT_NAME { -v "%programfiles%\\McAfee\\**" }
            Exclude OBJECT_NAME { -v "%programfiles(x86)%\\McAfee\\**" }
            Exclude OBJECT_NAME { -v "%programfiles(x86)%\\FireEye\\xagt\\xagt.exe" }
         }
        Include AggregateMatch -xtype "inc2" {
       
            Exclude VTP_PRIVILEGES -type BITMASK { -v 0x8 }
        }

}
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "schtasks.exe" }    
            Include PROCESS_CMD_LINE { -v "*/create*" }
            Include PROCESS_CMD_LINE { -v "*/delete*" }
            Include PROCESS_CMD_LINE { -v "*/change*" }


            Include -access "CREATE EXECUTE"
        }
    }
}
```

## Tested Platforms
Win 11x64 and Win server 2022

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
