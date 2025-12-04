# Npm Supplychain attack - Killswitch - II

## Author
Trellix

## Description
The expert rule detects when bun.exe causes cmd.exe to delete files or directories (using rd or del) inside the Users directory.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
                Process {
                        Include OBJECT_NAME { -v "bun.exe" }
                }
                Target {
                        Match PROCESS {
                            Include OBJECT_NAME { -v "cmd.exe" }
                            Include AggregateMatch -xtype "Inc1" {
                                      Include PROCESS_CMD_LINE { -v "**rd**" }
                            }
                            Include AggregateMatch -xtype "Inc2" {
                                      Include PROCESS_CMD_LINE { -v "** /Q **" }
                            }
                            Include AggregateMatch -xtype "Inc3" {
                                      Include PROCESS_CMD_LINE { -v "**Users\\**" }
                            }
                            Include -access "CREATE"
                        }
                        Match PROCESS {
                            Include OBJECT_NAME { -v "cmd.exe" }
                            Include AggregateMatch -xtype "Inc1" {
                                      Include PROCESS_CMD_LINE { -v "**del**" }
                            }
                            Include AggregateMatch -xtype "Inc2" {
                                      Include PROCESS_CMD_LINE { -v "** /Q **" }
                            }
                            Include AggregateMatch -xtype "Inc3" {
                                      Include PROCESS_CMD_LINE { -v "**Users\\**" }
                            }
                            Include -access "CREATE"
                        }
						
                }
            }
```

## Tested Platforms
OS: Windows 10 20H1 x64 
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
