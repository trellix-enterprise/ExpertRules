# FILE CREATION PROTECTION RULE

## Description
This rule prevents creating a file called **testfile.txt** in the path **C:\\Users\\Admin\\Downloads\\** using **cmd**.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v cmd.exe
        }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME {
                -v "C:\\Users\\Admin\\Downloads\\testfile.txt"
            }
            Include -access "CREATE" ; # Prevents file creation
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows CMD.
3. Run the following command:<br>
`echo hello > c:\Users\Admin\Downloads\testfile.txt`

## Notes