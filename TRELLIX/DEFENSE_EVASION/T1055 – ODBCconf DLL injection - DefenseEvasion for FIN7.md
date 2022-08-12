# T1055 – ODBCconf DLL injection - DefenseEvasion for FIN7

## Author
McAfee

## Description
This rule trigger indicates an attempt to abuse odbcconf.exe to inject a potentially malicious DLL.  

## Rule Class 
Processes

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v "**" }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME  {  -v "odbcconf.exe"  }
            Include PROCESS_CMD_LINE { -v "*REGSVR*" }
            Include PROCESS_CMD_LINE { -v "*-encodedcommand*" }
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
N/A