# PROCESS CREATION PROTECTION RULE USING *iEnv* and *iDump* COMMANDS

## Description
This rule prevents from starting **notepad** using **Windows Explorer**.

## Rule TCL
```tcl
Rule {

    set myvariable_computername [iEnv COMPUTERNAME]
    set myvariable_processorid  [iEnv PROCESSOR_IDENTIFIER]
    set myvariable_username     [iEnv USERNAME]
    set myvariable_profile      [iEnv USERPROFILE]
    set myvariable_windir       [iEnv WINDIR]
    iDump myvariable_*

    Process {
        Include OBJECT_NAME {
            -v explorer.exe
        }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME {
                -pfx $myvariable_windir
                -v "\\notepad.exe"
            }
            Include -access "CREATE" ; # Prevents process creation
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows Explorer.
3. Navigate to the folder **C:\\Windows\\**.
4. Double click on the file **notepad.exe**.

## Notes
The variables created by using the **iEnv** command can be used in the rule to create a specific string to look for. The purpose of the example is to show how you can get environment variables values to be used in the rules, and also how to check the values you are getting in the **ExploitPrevention_Debug.log** by using the **iDump** command.