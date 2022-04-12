# FILE EXECUTION PROTECTION RULE

## Description
This rule prevents the user **Admin** from executing the file called **notepad.exe** in the path **C:\\Windows\\**.

## Rule TCL
```tcl
Rule {
    Process {
        Include USER_NAME {
            -v ".\\Admin"
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
1. Log in in the system as a user called **Admin**.
2. Add and enforce the rule to the exploit prevention policy.
3. Open Windows Explorer.
4. Navigate to the folder **C:\\Windows\\**.
5. Double click on the file **notepad.exe**.

## Notes
Note the back slash used previous to the user name to separate the domain and user name. If you dont know the domain, it is possibe to use wildcards.