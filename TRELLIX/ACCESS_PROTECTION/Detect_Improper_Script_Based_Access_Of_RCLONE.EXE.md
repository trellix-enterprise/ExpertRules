# Detect Improper Script Based Access of RCLONE.EXE

## Author
McAfee

## Description
This rule detects the script based access of RCLONE.EXE by potentially malicious actors based on command line usage. This behavior is observed with a few ransomware actors.

## Rule Class 
Processes

## Rule TCL
```tcl
The original rule: 
Rule {
    Process {
        Include OBJECT_NAME { -v "powershell.exe" }
        Include OBJECT_NAME { -v "cmd.exe" }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v "rclone.exe" }
            Include PROCESS_CMD_LINE {
                -v "** pass **"
                -v "** user **"
                -v "** copy **"
                -v "** mega **"
                -v "** sync **"
                -v "** config **"
                -v "** lsd **"
                -v "** remote **"
                -v "** ls **"
            }
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