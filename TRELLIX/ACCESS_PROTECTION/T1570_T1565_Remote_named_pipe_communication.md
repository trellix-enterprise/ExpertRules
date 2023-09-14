# T1570/T1565 - Remote Named Pipe Connection

## Author
Trellix

## Description
The expert rule detects namedpipe communication from remote machine.

## Rule Class 
Processes

## Rule TCL
```tcl
Rule {
  
    Process {
    
			Include OBJECT_NAME {-v "SYSTEM:REMOTE"}
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

## Tested Platforms
OS: Windows 10 20H1 x64
ENS: 10.7.0

## Notes
Helpful in detecting applications like psexec and its clone that can execute commands in the remote machine often abused by threat actor for lateral movement.
