# PROCESS TERMINATING PROTECTION RULE

## Description
This rule prevents from terminating **notepad** using **Task Manager**.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v taskmgr.exe
        }
    }
    Target {
        Match PROCESS {
            Include OBJECT_NAME {
                -v notepad.exe
            }
            Include -access "DELETE" ; # Prevents process terminating
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows Explorer.
3. Navigate to the folder **C:\\Windows\\**.
4. Double click on the file **notepad.exe**.
5. Right click on the task bar and open **Task Manager**.
6. Go to the details tab and look for **notepad.exe**.
7. Right click on **notepad.exe** and click on **End Process Tree**.

## Notes
As you can realize, if instead of clicking on **End Process Tree** you clicked on **End Task**, the **Notepad** process will be terminated. This is because the access **DELETE** is specifically for terminating a running process. The **End Task** action doesn’t forcefully terminate the process. It asks the process to close gracefully, which is a different sort of operation. The process goes through the process of cleaning up resources and exiting cleanly. The access **DELETE** can’t block the *WM_CLOSE* message itself because that’s being transmitted from one user-mode process to the other, and at the end of the day the terminating action is being done by the process itself instead of **Task Manager**.