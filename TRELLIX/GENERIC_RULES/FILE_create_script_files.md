# SCRIPT FILES CREATION PROTECTION RULE

## Description
This Rule detects the creation of script files.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v "**"
        }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME {
                -v **.vbs
                -v **.wsf
                -v **.wsc
                -v **.bat
                -v **.cmd
                -v **.btm
                -v **.ps1
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
`echo "echo Hello... This is a script" > c:\Users\Admin\Downloads\testscript.bat`

## Notes