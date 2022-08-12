# FILE ATTRIBUTES MODIFICATION PROTECTION RULE

## Description
This rule prevents modifying the attributes of a file called **testfile.txt** in the path **C:\\Users\\Admin\\Downloads\\** using **Windows Explorer**.

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
            Include -access "WRITE_ATTRIBUTE" ; # Prevents file attributes modification
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
1. Right click on the file **testfile.txt** and open *Properties*.
1. Set the *Hidden* checkbox and click *OK*.

## Notes
As you probably have realized, the initiator specifies two processes **explorer.exe** and **dllhost.exe**. This is because Microsoft Windows has some internal retry mechanisms to ensure that the modification of the attributes finishes successfully. So, when the first attempt performed by *explorer.exe* is blocked, then a retry will be performed by *dllhost.exe*, achieving the action if we didn't specify it.<br>
A good exercise is to perform an actions monitoring using the **Procmon** *SysInternals* tool. Set a filter for paths containing **testfile.txt**, perform the actions and you will see both blocked events.<br>
This was verified using Windows 10 RS3.