# T1569 – Service execution using PSExec

## Author
McAfee

## Description
This rule trigger indicates an attempt to abuse PSExec by using named pipes to transfer standard output, input and error.  

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v *.exe
        }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME {
                -v "**pipe\\psexesvc*"
            }
            Include OBJECT_NAME {
                -v "**pipe\\remcom*"
            }
            Include OBJECT_NAME {
                -v "**pipe\\PAExec*"
            }
            Include OBJECT_NAME {
                -v "**pipe\\csexec*"
            }
            Include -access "CONNECT_NAMED_PIPE"
        }
    }
}
```

## Trigger
TBC.

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
This rule is for monitoring/telemetry. Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives.
