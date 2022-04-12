# FILE CREATION PROTECTION RULE USING *iUser* COMMAND AND *for* LOOP

## Description
This rule prevents creating a file called **testfile.txt** in any user profile folder by using **cmd**.

## Rule TCL
```tcl
Rule {

    set users_list [ iUser list ]
    iDump users_list

    for {set x 0} { $x < [llength $users_list] } {incr x} {
        set tempstring [ lindex $users_list $x ]
        append tempstring "\\testfile.txt"
        lappend users_list_with_file $tempstring
    }

    Process {
        Include OBJECT_NAME {
            -v cmd.exe
        }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME -type PATH {
                -pfx "c:\\Users\\"
                -l $users_list_with_file
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
`echo hello > c:\Users\User1\testfile.txt`<br>
`echo hello > c:\Users\User2\testfile.txt`<br>
`echo hello > c:\Users\User3\testfile.txt`

## Notes