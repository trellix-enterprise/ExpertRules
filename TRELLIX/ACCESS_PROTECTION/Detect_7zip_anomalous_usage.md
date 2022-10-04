# Detect 7zip anomalous usage

## Author
McAfee

## Description
This rule trigger indicates abuse of 7zip application by applications like SolarWinds.

## Rule Class 
Processes

## Rule TCL
```tcl
The original rule: 
Rule {
              Process {
                             Include OBJECT_NAME { -v "rundll32.exe" }
                             Include OBJECT_NAME { -v "dllhost.exe" }
                             Include GROUP_SID { -v "S-1-16-12288" }
                             Include GROUP_SID { -v "S-1-16-16384" }
              }
              Target {
                             Match PROCESS {                   
                                           Include OBJECT_NAME { -v "7z*" }
                                           Include PROCESS_CMD_LINE { -v "*-mx9*" }
                                           Include -access "CREATE"
                             }
              }
}

```

## Trigger
NA

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.