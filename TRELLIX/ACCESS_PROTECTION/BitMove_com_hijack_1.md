# BitMove COM HIJACKING

## Author
Trellix

## Description
The expert rule detects when we can configure a COM Hijack via the remote registry, drop a malicious DLL via SMB and trigger loading/execution of this DLL via DCOM.


## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
    Target {
        Match VALUE {
            Include OBJECT_NAME { -v "HKCU\\SOFTWARE\\Classes\\CLSID\\{A7A63E5C-3877-4840-8727-C1EA9D7A4D50}\\InProcServer32\\**" }
            Include REGVAL_DATA -type STRING { -v "**.dll"}
            Include -access "CREATE WRITE"
        }
    }
}
```

## Tested Platforms
OS: Windows 10 20H1 x86 and Windows 11 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.