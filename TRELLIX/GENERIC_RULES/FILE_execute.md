# FILE EXECUTION PROTECTION RULE

## Description
This rule prevents executing the file called **notepad.exe** in the path **C:\\Windows\\** using **Windows Explorer**.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v explorer.exe
        }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME {
                -v "C:\\Windows\\notepad.exe"
            }
            Include -access "EXECUTE" ; # Prevents file execution
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