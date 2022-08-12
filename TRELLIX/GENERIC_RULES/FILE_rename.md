# FILE RENAME PROTECTION RULE

## Description
This rule prevents from renaming a file called **testfile.txt** in the path **C:\\Users\\Admin\\Downloads\\** using **Windows Explorer**.

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
                -v "C:\\Users\\Admin\\Downloads\\testfile.txt"
            }
            Include -access "RENAME" ; # Prevents file rename
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
1. Open Windows CMD.
1. Run the following command:<br>
`echo hello > c:\Users\Admin\Downloads\testfile.txt`
1. Open Windows Explorer and navigate to the folder **C:\\Users\\Admin\\Downloads\\**.
1. Right click on the file **testfile.txt** and then *Rename*.
2. Set the name to **filetest.txt**.

## Notes
As you probably have realized, the initiator specifies two processes **explorer.exe** and **dllhost.exe**. This is because Microsoft Windows has some internal retry mechanisms to ensure that the modification of the file name is done. So, when the first attempt performed by *explorer.exe* is blocked, then a retry will be performed by *dllhost.exe*, achieving the action if we didn't specify it.<br>
A good exercise is to perform an actions monitoring using the **Procmon** *SysInternals* tool. Set a filter for paths containing **testfile.txt**, perform the actions and you will see both blocked events.<br>
This was verified using Windows 10 RS3.<br><br>
The renaming operation monitoring can be more specific. You can also specify the target name that you want to block from being used. To do that, you have to use also the **TARGET_OBJECT_NAME** match type.