# ENSW-134697 workaround: prevent VirtualBoxVM.exe from loading the ENS AMSI provider so the LogLib post-unload crash chain never starts

## Author
Trellix

## Issue
After upgrading to ENS 26.8, powering on any VirtualBox guest terminates VirtualBoxVM.exe with Exception Code 0xC0000005 (Access Violation — execute). 

## RCA
LogLib is pulled into VirtualBoxVM.exe through the Windows AMSI path — amsi.dll -> MfeAmsiProvider.dll -> blframeworku.dll -> LogLib.dll. During the AMSI provider's teardown in this foreign host process, LogLib.dll is unloaded, but blframework retains and subsequently triggers a crash of VirtualBoxVM.exe.

## Description
This rule blocks loading of MfeAmsiProvider.dll from "VirtualBoxVM.exe". To resolve this issue with LogLib.dll unloading, we blocked MfeAmsiProvider.dll from loading inside VirtualBoxVM.exe. This prevents the subsequent loading and unloading of LogLib.dll, eliminating the exception errors and allowing the VM to start successfully.

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME { -v "VirtualBoxVM.exe" }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "MfeAmsiProvider.dll" }
            Include -access "EXECUTE"
        }
    }
}
```

## Tested Platforms
OS: Windows 10/11 and Windows Server 2022/2019/2016 - x64 
ENS: 26.8
VirtualBox: 7.2.20

## Notes
If using any other vendor virtual box (which have different exe name) and encountering the same issue, replace the "VirtualBoxVM.exe" with the executable name that loads "MfeAmsiProvider.dll".
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.