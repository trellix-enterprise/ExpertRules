# T1175 – COM - Word.Application using PowerShell and Python

## Author
McAfee

## Description
This rule trigger indicates an attempt to abuse the Windows Component object for code execution locally/remotely through the Word application via Python/PowerShell. 

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v "powershell.exe"
            -v "powershell_ise.exe"
            -v "python.exe"
            -v "python3.exe"
        }
   }
    Target {
        Match KEY {
            Include OBJECT_NAME { -v "HKCR\\Word.Application\\CLSID\\**" }
            Include OBJECT_NAME { -v "HKCR\\Word.Application.*\\CLSID\\**" }
            Include -access "READ"
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