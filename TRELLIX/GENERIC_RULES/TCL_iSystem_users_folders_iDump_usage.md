# FILE CREATION PROTECTION RULE USING *iSystem* and *iDump* COMMANDS

## Description
This rule prevents from creating a file with the name **testfile.txt** within a user Temp folder using **Windows Explorer**.

## Rule TCL
```tcl
Rule {

    set temp_folders [iSystem users_folders -no_defaults Temp]
    iDump temp_folders

    Process {
        Include OBJECT_NAME {
            -v explorer.exe
            -v dllhost.exe
        }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME {
                -sfx "\\testfile.txt"
                -l $temp_folders
            }
            Include -access "CREATE" ; # Prevents file creation
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows Explorer.
3. Navigate to the folder **C:\\Windows\\TEMP**.
4. Create a new plain text file with the name **testfile.txt**.

## Notes
When you are asking for the Temp folders in the iSystem command, it will always return the values of the variables TEMP and TMP in the registry key *SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment*.<br>
After that, the rule compiler will start iterating all the subkeys in *SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList*, and for all the user profiles (including .DEFAULT), it will get the values of TEMP and TMP in the key *HKEY_USERS\\<user_sid>\\Environment*.<br>
Considering that the rule compiler starts with the .DEFAULT profile, the first value that the rule compiler will save as default value is normally *%USERPROFILE%\AppData\Local\Temp*. Then, for all the other user profiles, it will compare the TEMP and TMP values with the one saved for the default user account, and here:
* If the value is the same and the -no_defaults switch was specified, the value is discarded.
* For any other case, the value is expanded to the actual %USERPROFILE% value and stored.<br>

Note that the **dllhost.exe** process is specified in the initiator block to also block a retry with admin right by **Windows Explorer**.