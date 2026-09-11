# Suspicious shell execution from apache server

## Author
Trellix

## Description
This expert rule detects Suspicious shell execution from apache server. An apache server executing cmd.exe usually refers to one of three completely different scenarios: a critical security breach (Remote Code Execution), a legitimate administrative startup task, or a Windows CGI script configuration.


## Rule Class 
Process

## Rule TCL
```tcl
Rule {
	Process {
		Include OBJECT_NAME { -v "httpd.exe" }
		Include OBJECT_NAME { -v "php-cgi.exe" }
	}
	Target {
		Match PROCESS {
			Include OBJECT_NAME { -v "cmd.exe" }
			Include OBJECT_NAME { -v "pwsh.exe" }
			Include OBJECT_NAME { -v "powershell.exe" }
			Include -access "CREATE"
		}
	}
}
```

## Tested Platforms
OS: Windows 10 20H1 x86, Windows 11 x64 and Win server 2022
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
