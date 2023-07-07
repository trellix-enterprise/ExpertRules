# T1486 - Attempt to Encrypt data for Impact

## Author
Trellix

## Description
This expert rule detects suspicious attempt to write into or delete files with monitored extension. 

## Rule Class 
Process

## Rule TCL
```tcl

Rule {
	Process {
		Include PROCESS_STATE_BITS -name DAC_CONTAIN_PID_BITS { -v 0x1 }
	}
	Target { 
		Match FILE {
				Include OBJECT_NAME { -v "**.bin" }
				Include OBJECT_NAME { -v "**.sys" }
				Include OBJECT_NAME { -v "**.png" }
				Include OBJECT_NAME { -v "**.html" }
				Include OBJECT_NAME { -v "**.htm" }
				Include OBJECT_NAME { -v "**.css" }
				Include OBJECT_NAME { -v "**.js" }
				Include OBJECT_NAME { -v "**.vbs" }
				Include OBJECT_NAME { -v "**.bat" }
				Include OBJECT_NAME { -v "**.3ds" }
				Include OBJECT_NAME { -v "**.7z" }
				Include OBJECT_NAME { -v "**.accdb" }
				Include OBJECT_NAME { -v "**.ai" }
				Include OBJECT_NAME { -v "**.asp" }
				Include OBJECT_NAME { -v "**.aspx" }
				Include OBJECT_NAME { -v "**.avhd" }
				Include OBJECT_NAME { -v "**.back" }
				Include OBJECT_NAME { -v "**.bak" }
				Include OBJECT_NAME { -v "**.c" }
				Include OBJECT_NAME { -v "**.cfg" }
				Include OBJECT_NAME { -v "**.conf" }
				Include OBJECT_NAME { -v "**.cpp" }
				Include OBJECT_NAME { -v "**.cs" }
				Include OBJECT_NAME { -v "**.ctl" }
				Include OBJECT_NAME { -v "**.dat" }
				Include OBJECT_NAME { -v "**.dbf" }
				Include OBJECT_NAME { -v "**.disk" }
				Include OBJECT_NAME { -v "**.djvu" }
				Include OBJECT_NAME { -v "**.doc" }
				Include OBJECT_NAME { -v "**.docx" }
				Include OBJECT_NAME { -v "**.dwg" }
				Include OBJECT_NAME { -v "**.eml" }
				Include OBJECT_NAME { -v "**.fdb" }
				Include OBJECT_NAME { -v "**.gz" }
				Include OBJECT_NAME { -v "**.h" }
				Include OBJECT_NAME { -v "**.hdd" }
				Include OBJECT_NAME { -v "**.kdbx" }
				Include OBJECT_NAME { -v "**.mail" }
				Include OBJECT_NAME { -v "**.mdb" }
				Include OBJECT_NAME { -v "**.msg" }
				Include OBJECT_NAME { -v "**.nrg" }
				Include OBJECT_NAME { -v "**.ora" }
				Include OBJECT_NAME { -v "**.ost" }
				Include OBJECT_NAME { -v "**.ova" }
				Include OBJECT_NAME { -v "**.ovf" }
				Include OBJECT_NAME { -v "**.pdf" }
				Include OBJECT_NAME { -v "**.php" }
				Include OBJECT_NAME { -v "**.pmf" }
				Include OBJECT_NAME { -v "**.ppt" }
				Include OBJECT_NAME { -v "**.pptx" }
				Include OBJECT_NAME { -v "**.pst" }
				Include OBJECT_NAME { -v "**.pvi" }
				Include OBJECT_NAME { -v "**.py" }
				Include OBJECT_NAME { -v "**.pyc" }
				Include OBJECT_NAME { -v "**.rar" }
				Include OBJECT_NAME { -v "**.rtf" }
				Include OBJECT_NAME { -v "**.sln" }
				Include OBJECT_NAME { -v "**.sql" }
				Include OBJECT_NAME { -v "**.tar" }
				Include OBJECT_NAME { -v "**.vbox" }
				Include OBJECT_NAME { -v "**.vbs" }
				Include OBJECT_NAME { -v "**.vcb" }
				Include OBJECT_NAME { -v "**.vdi" }
				Include OBJECT_NAME { -v "**.vfd" }
				Include OBJECT_NAME { -v "**.vmc" }
				Include OBJECT_NAME { -v "**.vmdk" }
				Include OBJECT_NAME { -v "**.vmsd" }
				Include OBJECT_NAME { -v "**.vmx" }
				Include OBJECT_NAME { -v "**.vsdx" }
				Include OBJECT_NAME { -v "**.vsv" }
				Include OBJECT_NAME { -v "**.work" }
				Include OBJECT_NAME { -v "**.xls" }
				Include OBJECT_NAME { -v "**.xlsx" }
				Include OBJECT_NAME { -v "**.xvd" }
				Include OBJECT_NAME { -v "**.zip" }
			Include -access "WRITE DELETE"
		}
	}	
}

```

## Trigger
TBC

## Tested Platforms
OS: Windows 10 20H2 x64
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.
