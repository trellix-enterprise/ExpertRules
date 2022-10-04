# FILE WRITING PROTECTION RULE

## Description
This rule prevents writing a file called **testfile.txt** in the path **C:\\Users\\Admin\\Downloads\\** using **Notepad**.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v notepad.exe
        }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME {
                -v "C:\\Users\\Admin\\Downloads\\testfile.txt"
            }
            Include -access "WRITE" ; # Prevents file writing
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
1. Open Windows CMD.
1. Run the following command:<br>
`echo hello > c:\Users\Admin\Downloads\testfile.txt`
1. Open the recently created **testfile.txt** file with Windows Notepad.
1. Modify the text and save.

## Notes