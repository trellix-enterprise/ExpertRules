# BEHAVIORAL RULE TO PREVENT A SPECIFIC CHAIN OF PROCESSES BEING STARTED

## Description
This rule detects when **Windows Explorer** launches **cmd**, and then from **cmd** is launched **calc**.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v explorer.exe }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME { -v cmd.exe }
            Include -access "CREATE"
        }

        Next_Process_Behavior {
            Target {
                Match PROCESS {
                    Include OBJECT_NAME { -v calc.exe }
                    Include -access "CREATE"
                }
            }
        }
    }
}
```

## Trigger
1. Open the folder **C:\Windows\System32** using **Windows Explorer**.
2. Double click on **cmd.exe**.
3. run **calc.exe**.

## Notes
Note that to chain the actions, we use the *Next_Process_Behavior* keyword. This keyword should be part of a *Target* block. If the action is an intermediate chain link, the keyword should be together with a **Match PROCESS** block to indicate that the specified process within the block is the one that is taking the action. The last link in the chain es the only one that can use any *Match_OBJECT*.