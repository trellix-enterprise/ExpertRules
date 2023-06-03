# T1105 - CertUtil Download With URLCache and Split Arguments

## Author
Elad Levi

## Description
Certutil.exe may download a file from a remote destination using -urlcache. 

This behavior does require a URL to be passed on the command-line. In addition, -f (force) and -split (Split embedded ASN.1 elements, and save to files) will be used. 

It is not entirely common for certutil.exe to contact public IP space. However, it is uncommon for certutil.exe to write files to world writeable paths.

During triage, capture any files on disk and review. Review the reputation of the remote IP or domain in question.

## Rule Class 
Processes

((Processes.process=*urlcache* Processes.process=*split*) OR Processes.process=*urlcache*)

## Rule TCL
```tcl
The original rule: 

Rule {
	Target {
		Match PROCESS {
			Include OBJECT_NAME { -v "certutil.exe" }
			Include PROCESS_CMD_LINE { -v "*-urlcache*" }
			Include AggregateMatch {
				Include PROCESS_CMD_LINE { -v "*-urlcache*" }
				Include PROCESS_CMD_LINE { -v "*-split*" }
			}
			Include -access "CREATE"
		}
	}
}
```

## Trigger
NA

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.