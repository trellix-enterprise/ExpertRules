# T1003 – Export SAM from registry or LSA Export Registry entry

## Author
McAfee

## Description
This rule trigger indicates an attempt to export SAM from the registry. 

## Rule Class 
Registry

## Rule TCL
```tcl
Rule {
    Process {
        Include AggregateMatch -xtype "1" {
            Exclude VTP_PRIVILEGES -type BITMASK { -v 0x8 }
        }
        Include AggregateMatch -xtype "2" {
            Exclude OBJECT_NAME { -v "TIWORKER.EXE" }
            Exclude OBJECT_NAME { -v "DEVICECENSUS.EXE" }
            Exclude OBJECT_NAME { -v "TRUSTEDINSTALLER.EXE" }
            Exclude OBJECT_NAME { -v "TASKHOSTW.EXE" }
            Exclude OBJECT_NAME { -v "OMADMCLIENT.EXE" }
            Exclude OBJECT_NAME { -v "SERVICES.EXE" }
            Exclude OBJECT_NAME { -v "CSRSS.EXE" }
            Exclude OBJECT_NAME { -v "SVCHOST.EXE" }
            Exclude OBJECT_NAME { -v "WINLOGON.EXE" }
            Exclude OBJECT_NAME { -v "SCHTASKS.EXE" }
            Exclude OBJECT_NAME { -v "REGEDIT.EXE" }
            Exclude OBJECT_NAME { -v "UpdateNotificationMgr.exe" }
            Exclude OBJECT_NAME { -v "**\\Program Files\\Common Files\\microsoft shared\\ClickToRun\\*.exe" }
            Exclude OBJECT_NAME { -v "**\\Program Files (x86)\\Common Files\\microsoft shared\\ClickToRun\\*.exe" }
            Exclude OBJECT_NAME { -v "**\\program files\\microsoft office\\**.exe" }
            Exclude OBJECT_NAME { -v "**\\program files (x86)\\microsoft office\\**.exe" }
            }
      }
      Target {
          Match KEY {
Include OBJECT_NAME { -v "HKLM\\SAM" }
Include OBJECT_NAME { -v "HKLM\\SAM\\Domain\\Account" }
Include OBJECT_NAME { -v "HKLM\\SECURITY\\Policy\\Secrets"}
Include -access "READ"
}
}
}
```

## Trigger
TBC.

## Tested Platforms
OS: Windows 10 20H1 x64 and x86
ENS: 10.7.0 November'20 update

## Notes
This rule is for monitoring/telemetry. Customers are advised to fine-tune the rules to the applications used in their environment or disable the signature if there are false positives.