# WINDOWS SUBSYSTEM FOR LINUX PROTECTION RULE

## Description
This rule detects when the Windows Subsystem for Linux BASH command line is being launched with admin rights.

## Rule TCL
```tcl
Rule {
    Process {
        Include GROUP_SID {
            -v "S-1-16-12288"
        }
        Include GROUP_SID {
            -v "S-1-16-16384"
        }
        Include DESCRIPTION {
            -v "Microsoft Windows Subsystem for Linux Launcher"
        }
        Include DESCRIPTION {
            -v "Microsoft Bash Launcher"
        }
    }
    Target {
        Match SECTION {
            Include OBJECT_NAME {
                -v "**\\LxssManagerProxyStub.dll"
            }
            Include -access "CREATE"
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Search for *Bash* in the start menu.
3. Right click and run it as Administrator.

## Notes