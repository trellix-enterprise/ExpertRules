# FILE REPARSE POINT CREATION PROTECTION RULE

## Description
This rule prevents from creating a reparse point in a symbolic link called **testfilelink.txt** in the path **C:\\Users\\Admin\\Downloads\\** using **cmd**.

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
                -v "C:\\Users\\Admin\\Downloads\\testfilelink.txt"
            }
            Include -access "SET_REPARSE" ; # Prevents reparse data creation
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
1. Open Windows CMD.
1. Run the following command:<br>
`echo hello > c:\Users\Admin\Downloads\testfile.txt`
1. Create a symbolic link to the file running the following command:<br>
`mklink c:\Users\Admin\Downloads\testfilelink.txt c:\Users\Admin\Downloads\testfile.txt`

## Notes
The access **SET_REPARSE** will monitor the reparse point operation [FSCTL_SET_REPARSE_POINT](https://msdn.microsoft.com/en-us/library/Aa364595(v=VS.85).aspx). So, this access will not block actions such getting or deletting the reparse point data.<br>
On the other hand, a symbolic link is just one reparse point example. For more informations about other examples of reparse points, have a look at the [reparse point Microsoft documentation](https://docs.microsoft.com/en-us/windows/desktop/fileio/reparse-points).