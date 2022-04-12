# FILE RENAME PROTECTION RULE

## Description
This rule prevents from renaming a file called **origin.txt** to the name **destination.txt** in any path by using **Windows Explorer**.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v explorer.exe
            -v dllhost.exe
        }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME {
                -v origin.txt
            }
            Include TARGET_OBJECT_NAME {
                -v destination.txt
            }
            Include -access "RENAME" ; # Prevents file rename
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows Explorer and navigate to the folder **C:\\Users\\Admin\\Downloads\\**.
3. Create a new plain text file called **origin.txt**.
4. Right click on the file **origin.txt** and then *Rename*.
5. Set the name to **destination.txt**.

## Notes
As you probably have realized, the initiator specifies two processes **explorer.exe** and **dllhost.exe**. This is because Microsoft Windows has some internal retry mechanisms to ensure that the modification of the file name is done. So, when the first attempt performed by *explorer.exe* is blocked, then a retry will be performed by *dllhost.exe*, achieving the action if we didn't specify it.<br>
A good exercise is to perform an actions monitoring using the **Procmon** *SysInternals* tool. Set a filter for paths containing **origin.txt** and paths that contains **destination.txt**, perform the actions and you will see both blocked events.<br>
This was verified using Windows 10 RS3.<br><br>