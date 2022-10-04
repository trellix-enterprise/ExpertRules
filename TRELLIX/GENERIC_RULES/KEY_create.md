# REGISTRY KEY CREATION PROTECTION RULE

## Description
This rule prevents from creating a registry key with a name like **testkey** in the hive **HKEY_LOCAL_MACHINE\\SOFTWARE\\** using the **Registry Editor**.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v regedit.exe
        }
    }
    Target {
        Match KEY {
            Include OBJECT_NAME {
                -v "HKLMS\\test**"
            }
            Include -access "CREATE" ; # Prevents key creation
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows Registry Editor.
3. Expand the registry hive **HKEY_LOCAL_MACHINE\\SOFTWARE\\**.
4. Create a new key called **testkey**.

## Notes