# FILE CREATION PROTECTION RULE USING *-pfx* SWITCH

## Description
This rule prevents creating a file called **testfile1.txt** or **testfile2.txt** or **testfile3.txt** in the path **C:\\Users\\Admin\\Downloads\\** using **cmd**.

## Rule TCL
```tcl
Rule {
    
    lappend listOfFiles "testfile1.txt"
    lappend listOfFiles "testfile2.txt"
    lappend listOfFiles "testfile3.txt"

    Process {
        Include OBJECT_NAME {
            -v cmd.exe
        }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME -type PATH {
                -pfx "c:\\Users\\Admin\\Downloads\\"
                -l $listOfFiles
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
As you can see in this rule, the **-pfx** switch can be used to specify a single value and append to it all the values specified within the statement.