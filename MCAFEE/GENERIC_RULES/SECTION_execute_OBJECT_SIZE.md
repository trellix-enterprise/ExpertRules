# SECTION EXECUTION PROTECTION RULE

## Description
This rule prevents **explorer.exe** from executing the file called **notepad.exe** taking also in count the size of the main module memory section.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v explorer.exe
        }
    }
    Target {
        Match SECTION {
            Include OBJECT_NAME {
                -v "notepad.exe"
            }
            Include OBJECT_SIZE {
                -v 12345678
            }
            Include -access "EXECUTE" ; # Prevents section execution
        }
    }
}
```

## Trigger
1. Open Windows Explorer.
2. Navigate to the folder **C:\\Windows\\**.
3. Right click on the file **notepad.exe** and open Properties.
4. Copy the **Size** field value in bytes and change it in the Tule TCL.
5. Add and enforce the rule to the exploit prevention policy.
6. Go again to Windows Explorer and execute the file **C:\\Windows\\notepad.exe**.

## Notes
This rule will work because the size in mytes of the executable will be the same of the main module memory section that is created to acheve the execution.
