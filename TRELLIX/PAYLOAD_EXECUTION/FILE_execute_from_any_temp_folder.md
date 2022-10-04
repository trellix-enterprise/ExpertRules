# FILE IN TEMP FOLDERS EXECUTION PROTECTION BY WEB BROWSERS AND EMAIL CLIENTS RULE

## Description
This rule prevents executing files from any temp folder by using a set of web browsers and email clients.

## Rule TCL
```tcl
Rule {

    # Get the list of temp folders and temp internet folders for all users that have 
    # not been changed from their default values.
    set EPTempFolders [iSystem users_folders -no_defaults Temp Cache]

    # Create variable for default browser
    set EPDefaultBrowser [iReg value HKCR\\http\\shell\\open\\command ""]
    set EPDefaultBrowser [iUtil cvt2args $EPDefaultBrowser ]
    set EPDefaultBrowser [lindex $EPDefaultBrowser 0]

    # Create variable for default email client
    set EPDefaultEmailClient [iReg value HKCR\\mailto\\shell\\open\\command ""]
    set EPDefaultEmailClient [iUtil cvt2args $EPDefaultEmailClient ]
    set EPDefaultEmailClient [lindex $EPDefaultEmailClient 0]

    # reg call to get language specific value for %SystemDrive%\Users
    set EPProfilesDirectory [iReg value "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList" EPProfilesDirectory]

    #uncomment command below to get a dump of variables content
    #iDump EP*

    Process {
        Include OBJECT_NAME {
            -v $EPDefaultBrowser
            -v $DefaultEmailClient
            -v explorer.exe
            -v iexplore.exe
            -v chrome.exe
            -v MicrosoftEdge.exe
            -v firefox.exe
            -v mozilla.exe
            -v netscp.exe
            -v opera.exe
        }
    }

    Target {
        Match FILE {
            Include OBJECT_NAME {
                -v $EPTempFolders
                -v "$EPProfilesDirectory\\*\\**"
                -v "$EPProfilesDirectory\\*\\AppData\\Local\\Temp\\**"
                -v "$EPProfilesDirectory\\*\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\**"
            }
            
            Exclude OBJECT_NAME {
                -v "$EPProfilesDirectory\\*\\AppData\\Local\\Temp\\FNT*.exe"
            }
            
            Include -access "EXECUTE" ; # Prevents file execution
        }
    }
}
```

## Trigger
TBC

## Notes