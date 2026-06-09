# DigiCert Misissued Revoked Certificate Detection

## Author
Trellix

## Description
Signature Detects binaries signed using valid Extended Validation (EV) Code Signing certificates fraudulently obtained via the April 2026 DigiCert support portal breach. These stolen certificate hashes were weaponized by threat actors to bypass endpoint protections and sign the malware binaries.

## Rule Class
Files

## Rule TCL
```tcl
Rule {
	Process {
		Include OBJECT_NAME { -v "**" }
	}
	Target {
		Match FILE {
				Include CERT_HASH { -v "c120124ee8d34ffbac15a6c1982cf707" }
				Include CERT_HASH { -v "fc99ad6b4867e4739bac91c85e28069e" }
				Include CERT_HASH { -v "201a1a3757be7d9ffa9de8a092298690" }
				Include CERT_HASH { -v "2e9d0638dd6bd23955d3284ed4c09034" }
				Include CERT_HASH { -v "67af75ef5d2a2ee626bfdd7cd0ffda82" }
				Include CERT_HASH { -v "99b203e379ea7e97085cf5242d650328" }
				Include CERT_HASH { -v "6e2889d0cd362558e887f1aad0eceb4f" }
				Include CERT_HASH { -v "19b4f43c90ac7140316f41ce2c16204b" }
				Include CERT_HASH { -v "cf6352a21f0cca3c12e758f8d950ef0a" }
				Include CERT_HASH { -v "028e3d00caad1d1ec0de86996df84f60" }
				Include CERT_HASH { -v "be27e8616956dc610cba14734a404246" }
				Include CERT_HASH { -v "8e16ffd44aaf0188ee05d2f2aa836dc2" }
				Include CERT_HASH { -v "a74500372f63460067cdcfbf19fc4803" }
				Include CERT_HASH { -v "385f0b5364ab0489472757f5e9ca49ac" }
				Include CERT_HASH { -v "fc210ea12a6b75783d26bd8f8995ef48" }
				Include CERT_HASH { -v "44e90f01b1ff691d35f274f63805d4cf" }
				Include CERT_HASH { -v "b946288c7365e1f3bfb593a168077ca3" }
				Include CERT_HASH { -v "54930595887dcbae940e89f6faed532a" }
				Include -access "EXECUTE"
		}
	}
}

```

## Tested Platforms
OS: Windows 11 x64 and Windows 10 x64 and x86
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.