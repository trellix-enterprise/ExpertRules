# T1559 - Local Named Pipe Communication

## Author
Trellix

## Description
This detects local named pipe creation and communication to perform command execution.

## Rule Class 
FILE

## Rule TCL
```tcl
Rule {
  
    Process {
                        Exclude VTP_PRIVILEGES { 1 }
			Exclude OBJECT_NAME {-v "SYSTEM:REMOTE"}
    }
    Target {

        Match FILE {

           	        Include OBJECT_NAME {-v **pipe\\**}
			Exclude OBJECT_NAME {-v **pipe\\lsass}
			Exclude OBJECT_NAME {-v **pipe\\ntapvsrq}
			Exclude OBJECT_NAME {-v **pipe\\srvsvc}
			Exclude OBJECT_NAME {-v **pipe\\wkssvc}
			Exclude OBJECT_NAME {-v **pipe\\MSME**}
			Exclude OBJECT_NAME {-v **pipe\\MsFteWds**}
			Exclude OBJECT_NAME {-v **pipe\\mfehc**}
			Exclude OBJECT_NAME {-v **pipe\\mmsserver**}
			Exclude OBJECT_NAME {-v **pipe\\scerpc**}
			Exclude OBJECT_NAME {-v **pipe\\winreg**}
			Exclude OBJECT_NAME {-v **pipe\\ma_named_pipe**}
			
			Include -access "READ WRITE CONNECT_NAMED_PIPE"

        }

    }

}
```

## Notes

