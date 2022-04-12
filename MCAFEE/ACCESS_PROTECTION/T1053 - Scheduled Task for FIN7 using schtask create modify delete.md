# T1053 - Scheduled Task for FIN7 using schtask create/modify/delete

## Author
McAfee

## Description
This rule trigger indicates an attempt to abuse the Task Scheduler feature for persistence and execution.  

## Rule Class 
Processes

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v "**" }
            Exclude OBJECT_NAME { -v "WSQMCONS.exe" }
            Exclude OBJECT_NAME { -v "**\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\*.exe" }
            Exclude OBJECT_NAME { -v "**\\Program Files (x86)\\Common Files\\microsoft shared\\ClickToRun\\*.exe" }
            Exclude OBJECT_NAME { -v "**\\program files\\microsoft office\\**.exe" }
            Exclude OBJECT_NAME { -v "**\\program files (x86)\\microsoft office\\**.exe" }
Exclude OBJECT_NAME { -v "**\\Program Files\\McAfee\\**" }
            Exclude OBJECT_NAME { -v "**\\Program Files (x86)\\McAfee\\**" }
            Exclude PROCESS_CMD_LINE { -v "**\\McAfee\\MAR\\scripts\\**" }

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

## Trigger
TBC.

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
This rule is for monitoring/telemetry. Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives.