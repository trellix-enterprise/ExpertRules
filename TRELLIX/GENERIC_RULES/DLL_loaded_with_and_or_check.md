# DLL LOADED WITH an AND and OR CHECK

## Description
This rule demonstrates the use of the DLL_LOADED ability with an AND and OR check

## Rule TCL
```tcl
Rule  {
    Reaction BLOCK
	Process {
		Include OBJECT_NAME { -v Test_DLL_Loaded.exe }
		Include AggregateMatch -xtype "testa" {
			Include DLL_LOADED -name "testa" { -v 0x1 }
		}
		Include AggregateMatch -xtype "testb" {
			Include DLL_LOADED -name "testb" { -v 0x1 }
		}
		Include AggregateMatch -xtype "testc" {
			Include DLL_LOADED -name "testc" { -v 0x1 }
		}
		Include AggregateMatch -xtype "testd_or_teste" {
			Include DLL_LOADED -name "testd" { -v 0x1 }
			Include DLL_LOADED -name "teste" { -v 0x1 }
		}
	}
	Target {
		Match FILE {
			Include OBJECT_NAME { -v notepad.exe }
			Include -access "EXECUTE"
		}
	}
}
```

## Trigger
1. Create a test executable named Test_DLL_Loaded.exe Have it load DLLs that are named TestA.dll, TestB.dll, TestC.dll, and either TestD.dll OR TestE.dll, and have it launch notepad.exe
2. Run the test executable Test_DLL_Loaded.exe 
3. The launching of notepad.exe will be blocked

## Notes
This example shows how to use the DLL_LOADED ability along with AND and OR matching on the loaded DLLs.  This is primarily useful in narrowing initiator matches
This rule will match if "Test_DLL_Loaded.exe" has loaded "TestA.dll" AND "TestB.dll" AND "TestC.dll" AND ("TestD.dll" OR "TestE.dll") and attempts to launch notepad.exe
IMPORTANT: The -xtype name must be unique as shown in the example above