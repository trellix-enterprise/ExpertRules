# FILE CREATION PROTECTION RULE USING *-v* SWITCH

## Description
This rule prevents creating a file called **testfile1.txt** or **testfile2.txt** or **testfile3.txt** in the path **C:\\Users\\Admin\\Downloads\\** using **cmd**.

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
                -v "C:\\Users\\Admin\\Downloads\\testfile1.txt"
                -v "C:\\Users\\Admin\\Downloads\\testfile2.txt"
                -v "C:\\Users\\Admin\\Downloads\\testfile3.txt"
            }
            Include -access "CREATE" ; # Prevents file creation
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
1. Open Windows CMD.
1. Run one of the following commands:<br>
`echo hello > c:\Users\Admin\Downloads\testfile1.txt`<br>
`echo hello > c:\Users\Admin\Downloads\testfile2.txt`<br>
`echo hello > c:\Users\Admin\Downloads\testfile3.txt`

## Notes
As you can see in this rule, the **-v** switch can be used to specify a single value (as in the initiator block) or multiples values (as in the target block) within a single statement.