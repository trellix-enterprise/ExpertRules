# PROCESS CREATION PROTECTION RULE

## Description
This rule prevents from starting **powershell** with the *-NonInteractive* switch using **cmd**.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v cmd.exe
        }
    }

    Target {
        Match PROCESS {
            Include OBJECT_NAME {
                -v powershell.exe
            }
            Include PROCESS_CMD_LINE {
                -v "*-NonInteractive*"
            }
            Include -access "CREATE" ; # Prevents process creation
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows CMD.
3. Run the following command:<br>
`powershell -NonInteractive`

## Notes