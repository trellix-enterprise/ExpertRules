# NAMED PIPE CONNECTION PROTECTION RULE

## Description
This rule protects from connecting to the named pipe called **\\\\.\\pipe\\testpipe** by using using **PowerShell**.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v powershell.exe
        }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME {
                -v "**pipe\\testpipe"
            }
            Include -access "CONNECT_NAMED_PIPE" ; # Prevents pipe connection
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows PowerShell ISE.
3. Copy, paste and run the following script:<br>
```powershell
$pipe=new-object System.IO.Pipes.NamedPipeServerStream("\\.\pipe\testpipe");
'Created server side of "\\.\pipe\testpipe"'
$pipe.WaitForConnection(); 
 
$sr = new-object System.IO.StreamReader($pipe); 
while (($cmd= $sr.ReadLine()) -ne 'exit') 
{
    $cmd
}; 
 
$sr.Dispose();
$pipe.Dispose();
```
Note: You will realize that the execution will be waiting for connections.

4. Open a Windows PowerShell console.
5. Copy, paste and run the following script:<br>
```powershell
$pipe = new-object System.IO.Pipes.NamedPipeClientStream("\\.\pipe\testpipe");
$pipe.Connect(); 
 
$sw = new-object System.IO.StreamWriter($pipe);
$sw.WriteLine("Client connected"); 
 
$sw.Dispose(); 
$pipe.Dispose();
```

## Notes
