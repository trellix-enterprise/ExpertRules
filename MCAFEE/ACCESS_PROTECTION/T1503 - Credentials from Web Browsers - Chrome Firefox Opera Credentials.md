# T1503 - Credentials from Web Browsers - Chrome/Firefox/Opera Credentials

## Author
McAfee

## Description
This rule trigger indicates an attempt to access files used to store credentials in browsers. 

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
    Process {
        Include AggregateMatch -xtype "not_excluded_path" {
            Include OBJECT_NAME { -v "**" }
            Exclude OBJECT_NAME {
                -v "**\\Google\\Chrome\\Application\\chrome.exe"
                -v "**\\Mozilla Firefox\\firefox.exe"
                -v "**\\Windows\\System32\\browserexport.exe"
                -v "**\\chrome-win\\chrome.exe"
                -v "**\\Microsoft\\Edge\\Application\\msedge.exe"
                -v "**\\Opera\\*\\opera.exe"
                -v "**\\Vivaldi\\Application\\vivaldi.exe"
                -v "**\\Chromium\\Application\\chrome.exe"
                -v "ir_agent.exe"
            }
        }
        Include AggregateMatch -xtype "not_trusted" {
            Exclude VTP_PRIVILEGES -type BITMASK { -v 0x8 }
        }

    }
    Target {
        Match FILE {
            Include OBJECT_NAME {
                -v "**\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data"
                -v "**\\AppData\\Local\\Google\\Chrome\\User Data\\Profile *\\Login Data"
                -v "**\\AppData\\Local\\Chromium\\User Data\\Default\\Login Data"
                -v "**\\AppData\\Local\\Chromium\\User Data\\Profile *\\Login Data"
                -v "**\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data"
                -v "**\\AppData\\Local\\Microsoft\\Edge\\User Data\\Profile *\\Login Data"
                -v "**\\AppData\\Roaming\\Opera Software\\Opera Stable\\Login Data"
                -v "**\\AppData\\Local\\Vivaldi\\User Data\\Default\\Login Data"
                -v "**\\AppData\\Local\\Vivaldi\\User Data\\Profile *\\Login Data"
                -v "**\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*\\logins.json"
            }
            Include -access "READ WRITE DELETE RENAME"
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