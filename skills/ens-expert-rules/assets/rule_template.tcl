Rule {
    # Starter skeleton for a Trellix ENS Exploit Prevention Expert Rule.
    # Copy this file, replace every TODO, then lint it:
    #     python scripts/lint_expert_rule.py this_rule.tcl
    # Keep "Rule {" as the very first line: the console only inserts the form's Reaction
    # when nothing (not even a comment) comes before it.
    #
    # Reaction, Description, Severity and Group are OPTIONAL here: the ePO / ENS console's
    # Expert Rule form normally supplies them. Delete these lines if you set them there.
    # Common reactions: BLOCK | ALLOW | TERMINATE_PROCESS | REPORT.
    # SCAN form: Reaction SCAN ACTOR_PROCESS SCANACTION REPORT
    Reaction BLOCK
    Description "TODO: what this rule protects against"
    Severity    MAJOR
    Group       "Custom Expert Rules"

    # Initiator — KEEP THIS SCOPED. Replace cmd.exe with the real actor process(es).
    # The initiator object type is always PROCESS.
    Process {
        Include OBJECT_NAME { -v "cmd.exe" }
    }

    # Target — choose ONE Match type:
    #   FILE | PROCESS | VALUE | KEY | SECTION | DISK | THREAD | SERVICE
    Target {
        Match FILE {
            Include OBJECT_NAME { -v "**\\TODO_target.ext" }
            # Access flags must be valid for the chosen Match type. See references/syntax.md.
            Include -access "CREATE"
        }
    }
}
