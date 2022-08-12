# FILE CREATION PROTECTION RULE USING *-sfx* SWITCH

## Description
This rule prevents creating a file called **testfile.txt** in the path **C:\\Users\\Admin\\Downloads\\** or **C:\\Users\\Admin\\Documents\\** or **C:\\Users\\Admin\\Desktop\\** using **cmd**.

## Rule TCL
```tcl
Rule {
    
    lappend listOfFolders "c:\\Users\\Admin\\Downloads\\"
    lappend listOfFolders "c:\\Users\\Admin\\Documents\\"
    lappend listOfFolders "c:\\Users\\Admin\\Desktop\\"

    Process {
        Include OBJECT_NAME {
            -v cmd.exe
        }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME -type PATH {
                -sfx "\\testfile.txt"
                -l $listOfFolders
            }
            Include -access "CREATE" ; # Prevents file creation
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows CMD.
3. Run one of the following commands:<br>
`echo hello > c:\Users\Admin\Downloads\testfile.txt`<br>
`echo hello > c:\Users\Admin\Documents\testfile.txt`<br>
`echo hello > c:\Users\Admin\Desktop\testfile.txt`

## Notes
As you can see in this rule, the **-sfx** switch can be used to specify a single value and append it to all the values specified within the statement.