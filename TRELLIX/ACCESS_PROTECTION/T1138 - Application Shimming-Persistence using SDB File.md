# T1138 - Application Shimming-Persistence using SDB File

## Author
McAfee

## Description
This rule trigger indicates an attempt to abuse application shimming through SDB file creation and execution via PowerShell 

## Rule Class 
Processes

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {  -v "powershell.exe"  }
        Include OBJECT_NAME {  -v "powershell_ise.exe"  }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME {   -v  "sdbinst.exe"  }            
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
N/A