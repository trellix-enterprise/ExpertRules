# T1088 – Bypass UAC-Sysprep DLL Hijack

## Author
McAfee

## Description
This rule trigger indicates an attempt to bypass user account control by hijacking system DLLs. 

## Rule Class 
Processes

## Rule TCL
```tcl
Rule {
   Process {
        Include OBJECT_NAME { -v "sysprep.exe" }
        Include CERT_NAME { -v "*Microsoft Corporation*" }
   }
   Target {
        Match SECTION {
            Include OBJECT_NAME { -v "cryptsp.dll" }
            Include OBJECT_NAME { -v "cryptbase.dll" }
            Include OBJECT_NAME { -v "RpcRtRemote.dll" }
            Include OBJECT_NAME { -v "UxTheme.dll" }
            Include OBJECT_NAME { -v "dwmapi.dll" }
            Include OBJECT_NAME { -v "SHCORE.dll" }
            Include OBJECT_NAME { -v "OLEACC.dll" }
            Exclude OBJECT_NAME { -v "%windir%\\system32\\cryptsp.dll" }
            Exclude OBJECT_NAME { -v "%windir%\\system32\\cryptbase.dll" }
            Exclude OBJECT_NAME { -v "%windir%\\system32\\RpcRtRemote.dll" }
            Exclude OBJECT_NAME { -v "%windir%\\system32\\UxTheme.dll" }
            Exclude OBJECT_NAME { -v "%windir%\\system32\\dwmapi.dll" }
            Exclude OBJECT_NAME { -v "%windir%\\system32\\SHCORE.dll" }
            Exclude OBJECT_NAME { -v "%windir%\\system32\\OLEACC.dll" }
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