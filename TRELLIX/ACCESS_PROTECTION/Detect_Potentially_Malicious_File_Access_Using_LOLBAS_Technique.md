# Detect Potentially Malicious File access using LOLBAS technique

## Author
McAfee

## Description
This is a monitoring based rule to detect accessing of potentially malicious files using Living Of the Land Binaries and Scripts (LOLBAS) technique

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
	Process {
		Exclude VTP_PRIVILEGES -type BITMASK { -v 0x8 }
        Include OBJECT_NAME {
            -v "winword.exe"
            -v "excel.exe"
            -v "powerpnt.exe"     
			-v "outlook.exe"
			-v "MSACCESS.exe"
			-v "IMEWDBLD.exe"
        }
    }
	Target {
        Match FILE {
            Exclude OBJECT_NAME { -v "**\\**\\*.tmp" }
            Include OBJECT_NAME {                
                -v "**\\AppData\\Local\\Microsoft\\Windows\\INetCache\\**\\*.*"
                -v "**\\AppData\\Local\\Microsoft\\Windows\\Temporary Internet Files\\**\\*.*"
            }           
            Include -access "CREATE READ EXECUTE" 
        }
    }
}
```

## Trigger
NA

## Tested Platforms
OS: Windows 10 20H1 x86, Windows Server 2016 x64
ENS: 10.7.0 November'20 update

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.