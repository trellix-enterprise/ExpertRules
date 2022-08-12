# REGISTRY VALUE DATA MULTI STRING ASSIGNMENT PROTECTION RULE

## Description
This rule prevents from creating a new **multi string** registry value with a data like **test\0multi\0string\0\0** or assign such data to an already existing one in the hive **HKEY_LOCAL_MACHINE\\SOFTWARE\\TestRegvalData\\** using any program.

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
            Include REGVAL_DATA -type MULTI_STRING {
               -v "test\0multi\0string\0\0"
            }
            Include -access "CREATE WRITE"
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows CMD with Admin rights.
3. Run the following command:<br>
`reg add HKEY_LOCAL_MACHINE\SOFTWARE\TestRegvalData /v testmultisz /t REG_MULTI_SZ /d test\0multi\0string`

## Notes