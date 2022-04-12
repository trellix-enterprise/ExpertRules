# REGISTRY KEY WRITING PROTECTION RULE

## Description
This rule prevents from writing a registry key with a name like **testkey** in the hive **HKEY_LOCAL_MACHINE\\SOFTWARE\\** using the **Registry Editor**.

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
            Include -access "WRITE" ; # Prevents key writing
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows Registry Editor.
3. Expand the registry hive **HKEY_LOCAL_MACHINE\\SOFTWARE\\**.
4. Create a new key called **testkey**.
5. Create a new key or value within the recently created **testkey**. 

## Notes
The access **WRITE** will monitor a key from being opened for write. Having said that, it will look for a registry value that is being created/written/deleted (the registry values, in this case, are thought of as the ‘data’ of a key).<br><br>
Something interesting related to the **Registry Editor** is that when you create a new key, it will internally manage the new key with a name like **New Key #N**. So, in order to avoid some tricks to bypass the rule, is also recommended to add the value **New Key\*\*** within the **OBJECT_NAME** statement.