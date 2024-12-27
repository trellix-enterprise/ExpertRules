# T1055.002 - PE Injection

## Author
Elad levi

## Description
This detection signature identifies potential process injection attempts by monitoring the creation of memory sections with Read-Write-Execute (RWX) permissions, which is often used to load and execute malicious code within another process's memory space.

## Rule Class 
Process

## Rule TCL
```tcl
Rule {
	Initiator {
		Match PROCESS {
			Include OBJECT_NAME {
				-v **
			}
			# Exclude processes signed by a Trellix or Microsoft
			Exclude VTP_TRUST true
		}
	}
	Target {
		Match PROCESS {
			Include OBJECT_NAME {
				-v **
			}
			Include -access "WRITE"
			Exclude -access "DELETE"
			# Exclude every memory protection execpt PAGE_EXECUTE_READWRITE (0x40)
			Include NT_ACCESS_MASK {
				-v "!0x10"
				-v "!0x20"
				-v "!0x80"
				-v "!0x01"
				-v "!0x02"
				-v "!0x04"
				-v "!0x08"
			}
		}
	}
}
```

## Tested Platforms
NA

## Notes
- Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
- Because I've used the access mask LOAD_IMAGE the signature cannot be used for prevention

## References
- [MSDN - Memory Protection Constants](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)
- [Trellix - ACCESS_MASK flags](https://docs.trellix.com/bundle/endpoint-security-10.7.x-product-guide-windows/page/UUID-d86ef855-0807-b492-c6d4-6abd56b47d2e.html#:~:text=with%20traverse%20access.-,LOAD_IMAGE,-SECTION)
