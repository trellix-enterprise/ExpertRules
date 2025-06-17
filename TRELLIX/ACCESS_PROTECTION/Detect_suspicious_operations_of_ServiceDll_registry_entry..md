# Detect suspicious operations of ServiceDll registry entry.

 ## Author
 Trellix

 ## Description
 This expert rule detect suspicious operations performed to the ServiceDll registry entry.

 ## Rule Class
 Registry

 ## Rule TCL
 ```tcl
Rule {
	Process {
			Exclude OBJECT_NAME {-v "**\\Windows\\System32\\svchost.exe"}
			Exclude OBJECT_NAME {-v "**\\Windows\\system32\\services.exe"}
		}

    Target {
        Match VALUE  {
		Include -access "CREATE WRITE REPLACE_KEY"
                Include OBJECT_NAME {-v "HKLM\\SYSTEM\\CurrentControlSet\\Services\\tapisrv\\Parameters\\ServiceDll"}
                Include OBJECT_NAME {-v "HKLM\\SYSTEM\\CurrentControlSet\\Services\\swprv\\Parameters\\ServiceDll"}
                Include OBJECT_NAME {-v "HKLM\\SYSTEM\\CurrentControlSet\\Services\\appmgmt\\Parameters\\ServiceDll"}
				}
        }
}
 ```

 ## Tested Platforms
 OS: Windows 10 x64
 ENS: 10.7.0

 ## Notes
 Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.