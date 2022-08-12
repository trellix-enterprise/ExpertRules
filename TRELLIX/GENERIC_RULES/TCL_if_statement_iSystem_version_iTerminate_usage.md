# FILE CREATION PROTECTION RULE USING *iSystem*, *if* STATEMENT AND *iTerminate* COMMAND

## Description
This rule prevents creating a file called **testfile.txt** in any path by using **cmd**. If the OS version is the one specified in the *if* statement by *major.minor.build*, the rule will be enforced. If not, the **iTerminate** message will be logged and the rule syntax check will fail.

## Rule TCL
```tcl
Rule {
    
    set os_version [ iSystem version ]
    iDump os_*

    if { $os_version == "10.0.16299" } {

        Process {
            Include OBJECT_NAME {
                -v cmd.exe
            }
        }
        Target {
            Match FILE {
                Include OBJECT_NAME {
                    -v "**\\testfile.txt"
                }
                Include -access "CREATE" ; # Prevents file creation
            }
        }

    } else {
        iTerminate "Rule not supported for this OS version."
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
As you can see in this rule, the *if* statement can be used to filter parts of the rule or directly avoid the rule enforcement in some specific endpoints. In this particular case the rule will be enforced only if the OS version is 10.0.16299.