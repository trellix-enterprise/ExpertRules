# Detect Abuse of Huorong Sword GUI Frontend

## Author
Trellix

## Description
This rule trigger indicates Huorong sword process attempted to create a process usysdiag.exe 

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
            Process {
                    
                    Include DESCRIPTION { -v "Huorong Sword GUI Frontend" }
                }
                Target {
                    Match PROCESS {
                        Include OBJECT_NAME { -v "usysdiag.exe" }
                        Include -access "CREATE"
                    }
                }
    }
```

## Notes
Threat actors might abuse this tool to kill EDR related processes. Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
