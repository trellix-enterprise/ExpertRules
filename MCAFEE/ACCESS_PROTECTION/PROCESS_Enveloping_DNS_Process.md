# DNS.EXE ENVELOPING RULE 

## Description
This rule detects when DNS.EXE process tries to execute another application or process. This is an enveloping type of rule for restricting the access of a process.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v "%windir%\\system32\\dns.exe"
        }
    }
    Target {
        Match PROCESS {
            Exclude OBJECT_NAME {
                -v "%windir%\\system32\\werfault.exe"
                -v "%windir%\\system32\\dnscmd.exe"
            }
            Include -access "CREATE"
        }
    }
}
```

## Trigger
TBC.

## Notes
This rule can be considered as a workaround for protecting against the CVE-2020-1350 where DNS.EXE will be prevented from executing any new process and thus reducing the risk of a potential attack. 