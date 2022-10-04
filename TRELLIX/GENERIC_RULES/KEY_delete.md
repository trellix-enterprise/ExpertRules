# REGISTRY KEY DELETION PROTECTION RULE

## Description
This rule prevents from deleting a registry key with a name like **testkey** in the hive **HKEY_LOCAL_MACHINE\\SOFTWARE\\** using the **Registry Editor**.

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
            Include -access "DELETE" ; # Prevents key deletion
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows Registry Editor.
3. Expand the registry hive **HKEY_LOCAL_MACHINE\\SOFTWARE\\**.
4. Create a new key called **testkey**.
5. Delete the recently created key **testkey**.

## Notes
Something interesting related to the **Registry Editor** is that when you create a new key, it will internally manage the new key with a name like **New Key #N**. So, in order to avoid some tricks to bypass the rule, is also recommended to add the value **New Key\*\*** within the **OBJECT_NAME** statement.