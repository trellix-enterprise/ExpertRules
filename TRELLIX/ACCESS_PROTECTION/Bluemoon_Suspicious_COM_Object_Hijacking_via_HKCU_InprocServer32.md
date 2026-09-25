# Bluemoon Suspicious COM Object Hijacking via HKCU InprocServer32


## Author
Trellix

## Description
Rule Detects any process attempting to CREATE or WRITE a registry value under a specific CLSID's InprocServer32 key in the current user hive (HKCU).

## Rule Class 
Process

## Rule TCL
```tcl
 Rule {
      Target {
          Match VALUE {
              Include OBJECT_NAME {
                  -v "HKCU\\SOFTWARE\\Classes\\CLSID\\{5D4CFCB7-222C-4CA3-96B6-1F8195FBBB4B}\\InprocServer32\\**"
              }
              Include -access "CREATE WRITE"
          }
      }
  }

```


## Tested Platforms
OS: Windows 10 20H2 x64 and Win 20 H1x86
ENS: 10.7.0 

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.