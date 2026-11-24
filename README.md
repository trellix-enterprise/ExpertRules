# ExpertRules

## Overview

This repository contains the set of rules that can be used with Trellix Endpoint Security in the Exploit Prevention policy. 
The rules are classified into 2 major groups:

*1. TRELLIX* : This folder contains Expert rules that are authored by Team Trellix or are derived from the Community authored expert rules. It contains different categories of Expert rules considering the purpose of the rule. All the rules within the *GENERIC_RULES* folder under *TRELLIX* can be considered as examples for learning. These Expert rules in all other sub folders, in their current form have undergone validation for syntax, functionality and limited quality analysis has been performed on a selected set of platforms. The rules are typically documented to provide details on the tested environment, links to techniques, limitations (if any), etc. Customers are encouraged to customize these rules to suit their environment and reduce false positive trigger alerts.
		
*2. COMMUNITY* : This folder contains rules authored by Expert Rule Community - The Expert Rule community comprises of External Contributors to Trellix Endpoint Security product in terms of authoring Exploit Prevention Expert Rules. This comprises of Blue teamers, Customers, Security Professionals, SOC, etc.

IMPORTANT: Trellix recommends testing Expert Rules in a non-production test environment to ensure rule integrity, and to prevent conflicts with unique environment configurations. Customers should exercise caution when deploying Expert Rules in their environment.


## 🤖 Write Expert Rules with your AI assistant

The [`skills/`](skills) folder contains **`ens-expert-rules`**, an [Agent Skill](https://agentskills.io) that teaches AI coding assistants — **Claude Code, GitHub Copilot, OpenAI Codex, Cursor, Gemini CLI** and others — to write, review, fix and lint Expert Rules in the style of the rules in this repository. Describe the behaviour you want to block or report in plain English; the assistant writes the rule, checks it with the bundled linter (verified against the ENS rule compiler), and tells you what to enter in the ePO Expert Rule form.

| Your assistant | Install |
| --- | --- |
| Any (Claude Code, Copilot, Codex, Cursor, Gemini CLI, …) | `npx skills add trellix-enterprise/ExpertRules --skill ens-expert-rules` |
| Claude Code | `/plugin install ens-expert-rules --marketplace trellix-enterprise/ExpertRules` |
| Gemini CLI | `gemini skills install https://github.com/trellix-enterprise/ExpertRules.git --path skills/ens-expert-rules` |
| Claude apps / manual | Download `ens-expert-rules.zip` from [Releases](https://github.com/trellix-enterprise/ExpertRules/releases), or copy [`skills/ens-expert-rules`](skills/ens-expert-rules) into your assistant's skills folder |

Then ask, for example: *"Write an ENS Expert Rule that blocks Microsoft Word from starting PowerShell."* See the **[skill install & usage guide](skills/README.md)** for every assistant, manual installation, verification and updates.

AI-generated rules follow the same advice as every rule here: check them in the console's Expert Rule Checker and test in report-only mode before blocking.


## 🚀 Adding an Expert Rule

1. Log on to EPO Console using your credentials
2. Go to `Policy Catalog` page from the menu

![image](https://github.com/user-attachments/assets/57538a04-d9c5-4d84-8980-20cbb03106e1)

3. Click on `Endpoint Security Threat Prevention` Product and select `Exploit Prevention`
4. Click on `Edit` button corresponding to policy you want to update

![image](https://github.com/user-attachments/assets/c1b9beb9-fa11-46df-931d-d87567565ef6)

5. Click on `Show Advanced` button to view advanced settings for Exploit Prevention
6. Go to `Signatures` section and click on `Add Expert Rule` button

![image](https://user-images.githubusercontent.com/89252889/184321778-48601b6b-ecc4-4469-b799-5dc933608b05.png)


7. Fill in details for *`Rule name`*, *`Severity`*, *`Action`*, *`Rule Type`* and *`Rule Content`* (the content must start with `Rule {`)
8. Click on `Check` in the Expert Rule Checker to compile the rule — one rule that fails to compile disables all Expert Rules on the endpoint
9. Click on `Save` to save an expert rule


## Support

For syntactical issues related to Expert Rules, please raise an [issue.](https://github.com/trellix-enterprise/ExpertRules/issues) <br/>
To know more on support for custom ENS rules. Refer [KB94889](https://thrive.trellix.com/s/article/KB94889)

## Resources
[Expert Rules training](https://training-catalog.trellix.com/Course/148256/elearning-detection-and-prevention-with-ens-expert-rules-essentials) <br/>
[10.7.x Product guide – Using Expert Rules](https://docs.trellix.com/bundle/endpoint-security-10.7.x-product-guide-windows/page/UUID-d11e2e43-4e3e-ce8d-299e-63d86b0ab48f.html) <br/>
[ENS Expert Rules AI agent skill – install & usage guide](skills/README.md) <br/>

## 🤝 Contributing

Thanks for taking the time to [contribute](COMMUNITY)! Pull requests that add or change rule documents are checked automatically by the **Rule lint** workflow; run `python3 skills/tools/lint_rule_docs.py <your_rule.md>` to check before you open one. Improvements to the AI skill are welcome too — see [skills/README.md](skills/README.md#contributing-to-the-skill).
