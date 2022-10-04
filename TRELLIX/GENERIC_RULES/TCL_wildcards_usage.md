# FILE CREATION PROTECTION RULE USING WILDCARDS

## Description
This rule prevents creating a file with a name like **testfile1.txt** in any path using **cmd**.

## Rule TCL
```tcl
Rule {
    Process {
        Include OBJECT_NAME {
            -v "cmd*"
        }
    }
    Target {
        Match FILE {
            Include OBJECT_NAME {
                -v "**\\testfile?.txt"
            }
            Include -access "CREATE" ; # Prevents file creation
        }
    }
}
```

## Trigger
1. Add and enforce the rule to the exploit prevention policy.
2. Open Windows CMD.
3. Run the following command:<br>
`echo hello > c:\Users\Admin\Downloads\testfile1.txt`<br>
`echo hello > c:\Users\Admin\Documents\testfile2.txt`<br>
`echo hello > c:\Users\Admin\Desktop\testfile3.txt`

## Notes
Wildcard usage explanation:<br>
* Single asterisk **(\*)**<br>
Matches any number of characters, but not directory separators. This is used at the end of **cmd** in the initiator statement and will allow the rule to match the **.exe** extension.
* Double asterisks **(\*\*)**<br>
Matches any number of characters, including directory separators. This is used at the beginning of the file name allowing the rule to match any path used to create the file.
* Single question mark **(?)**<br>
Matches any single character, except for directory separators. This allows the rule to match files with a name starting with **testfile**, followed by a single character, and ending with **.txt** extension.