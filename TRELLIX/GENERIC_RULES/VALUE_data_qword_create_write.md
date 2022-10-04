# REGISTRY VALUE DATA QWORD ASSIGNMENT PROTECTION RULE

## Description
This rule allows creating a new **qword** registry value with the range of data from **60 to 64**, or assign such data to an already existing one in the hive **HKEY_LOCAL_MACHINE\\SOFTWARE\\TestRegvalData\\** using any program. Any other data out of that range of values will be blocked.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v ** }
    }
    Target {
        Match VALUE {
            Include OBJECT_NAME {
               -v "HKLM\\Software\\TestRegvalData\\**"
            }
            Include REGVAL_DATA -type INT64 {
               -v *
            }
            Include -access "CREATE WRITE"
        }
        Match VALUE {
            Include OBJECT_NAME {
               -v "HKLM\\Software\\TestRegvalData\\**"
            }
            Exclude REGVAL_DATA -type INT64 {
               -v 60 64
            }
            Include -access "CREATE WRITE"
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
1. Open Windows CMD with Admin rights.
1. Run the following command:<br>
`reg add HKEY_LOCAL_MACHINE\SOFTWARE\TestRegvalData /v testqw /t REG_QWORD /d 59`

## Notes