# COMMUNITY

## Contributing

The repository license is Apache 2.0. Making a contribution to this repository means you are licensing the contribution under the repository license.

Pull requests are accepted and encouraged so users can share their approaches for detecting different events. For the benefit of the community, authors are required to document the rules with the fields described below and place them in the *COMMUNITY* folder. Pull requests have to contain a markdown file for each rule in the pull request with the following fields. Any pull requests not conforming to the below best practices will be rejected.

* **Title**: A short and descriptive title for the rule. e.g. *REMOTE FILE EXECUTION PROTECTION RULE*.

* **Author**: Here is the place to add the Author's details like the name, Company / organization, etc for the version of the Expert rule (starts from version 1.0). The modification to the rule will be recorded as an increment to the minor version along with the Author details.
For Example: Version 1.0 - <Author_name>, <Company/Organization_name>

* **Description**: A deep description of the purpose of the rule, techniques covered, stuff and actions that are supposed to be blocked by the use of the rule.

* **Rule TCL**: The rule TCL code that can be directly used in the *ENS Exploit Prevention* policy.  Something like:
```
Rule {
    Process {
        Include Match_Type { -v ... }
        Exclude Match_Type { -v ... }
    }
    Target {
        Match Match_Object {
            Include Match_Type { -v ... }
            Exclude Match_Type { -v ... }
            Include -access ...
        }
    }
}
```

* **Trigger**: Some steps to trigger the rule and verify that it actually works. You can put a reference here to any public and safe tool. 

* **Tested Platforms**: Provide the tested platform information like the OS version, OS architecture, Application name, Application version, Endpoint Security Product version, etc. 
For Example: OS: Windows 10 build 19041, Architecture: 64 bit, Application Name: Microsoft Edge, Application Version: 1.1.1.1, Endpoint Security version 10.7.0.1234

* **Notes**: Here is the place to add some clarifications related to the rule, how it works related to the OS, limitations (if any), references to any documentation that could help to understand it, etc.
