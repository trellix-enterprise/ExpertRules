# BigDiskBuster

## Author
Trellix

## Description
The newly disclosed technique, named BigDiskBuster, targets the process Microsoft Defender Antivirus uses to stage and install updates. If successfully deployed, it can keep the security product running while quietly preventing it from receiving the latest malware signatures, detection logic, scanning-engine components and platform improvements.

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
		Process {
				Exclude VTP_TRUST true
		}
		Target {
			Match FILE {
				Include OBJECT_NAME { -v "%systemdrive%\\Users\\*\\AppData\\Local\\Temp\\{????????-????-????-????-????????????}" }
				Include  IS_DIRECTORY { -v 0x0 }
				Include -access "CREATE"
			}
		}
}

```
## Tested Platforms
OS: Windows 10 20H1 x86 and Windows 10 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.