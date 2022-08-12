# FILE LOCKING RANGE FILE PROTECTION RULE

## Description
This rule prevents from creating a byte range lock on a file called **testfile.txt** in the path **C:\\Users\\Admin\\Downloads\\** using a **Powershell** script.

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
                -v "C:\\Users\\Admin\\Downloads\\testfile.txt"
            }
            Include -access "LOCK_RANGE" ; # Prevents lock creation
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
1. Open Windows CMD.
1. Run the following command:<br>
`echo hello > c:\Users\Admin\Downloads\testfile.txt`
1. Create a filestream lock to the file by running the following command sequense in Powershell:<br>
```powershell
$filePath = "c:\Users\Admin\Downloads\testfile.txt"
$fileObject = New-Object IO.FileStream $filePath ,'Append','Write','Read'
$fileObject.Lock(10, 10)
```

## Notes
The access **LOCK_RANGE** looks for an attempt to lock or unlock a byte range lock on a file. This monitoring action will be done by analyzing the usage of the windows APIs [**LockFile**](https://docs.microsoft.com/es-es/windows/desktop/api/fileapi/nf-fileapi-lockfile), [**LockFileEx**](https://docs.microsoft.com/en-us/windows/desktop/api/fileapi/nf-fileapi-lockfileex), [**UnlockFile**](https://docs.microsoft.com/es-es/windows/desktop/api/fileapi/nf-fileapi-unlockfile) and [**UnlockFileEx**](https://docs.microsoft.com/es-es/windows/desktop/api/fileapi/nf-fileapi-unlockfileex).