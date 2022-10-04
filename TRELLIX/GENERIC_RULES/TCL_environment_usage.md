# PROCESS CREATION PROTECTION RULE USING ENVIRONMENT VARIABLES

## Description
This rule prevents from starting **notepad** using **Windows Explorer**.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v explorer.exe
        }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME {
                -v "%windir%\\notepad.exe"
            }
            Include -access "CREATE" ; # Prevents process creation
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows Explorer.
3. Navigate to the folder **C:\\Windows\\**.
4. Double click on the file **notepad.exe**.

## Notes
The environment variables can be directly used within an **OBJECT_NAME** statement. The only thing to keep in mind is that te values you will get, are te ones related to the **mfeesp** process.