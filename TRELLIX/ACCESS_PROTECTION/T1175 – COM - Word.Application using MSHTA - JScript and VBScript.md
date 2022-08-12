# T1175 – COM - Word.Application using MSHTA - JScript and VBScript

## Author
McAfee

## Description
This rule trigger indicates an attempt to abuse the COM object using MSHTA via JavaScript or VBScript. 

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v "mshta.exe"
        }
        Include DLL_LOADED -name "jscript9" { -v 0x1 }
        Include DLL_LOADED -name "vbscript" { -v 0x1 }
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