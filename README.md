# ExpertRules

## Overview

This repository contains the set of rules that can be used with Trellix Endpoint Security in the Exploit Prevention policy. 
The rules are classified into 2 major groups:

*1. TRELLIX* : This folder contains Expert rules that are authored by Team Trellix or are derived from the Community authored expert rules. It contains different categories of Expert rules considering the purpose of the rule. All the rules within the *GENERIC_RULES* folder under *TRELLIX* can be considered as examples for learning. These Expert rules in all other sub folders, in their current form have undergone validation for syntax, functionality and limited quality analysis has been performed on a selected set of platforms. The rules are typically documented to provide details on the tested environment, links to techniques, limitations (if any), etc. Customers are encouraged to customize these rules to suit their environment and reduce false positive trigger alerts.
		
*2. COMMUNITY* : This folder contains rules authored by Expert Rule Community - The Expert Rule community comprises of External Contributors to Trellix Endpoint Security product in terms of authoring Exploit Prevention Expert Rules. This comprises of Blue teamers, Customers, Security Professionals, SOC, etc.

IMPORTANT: Trellix recommends testing Expert Rules in a non-production test environment to ensure rule integrity, and to prevent conflicts with unique environment configurations. Customers should exercise caution when deploying Expert Rules in their environment.


## 🚀 Adding an Expert Rule

1. Log on to EPO Console using your credentials
2. Go to `Policy Catalog` page from the menu

![image](https://github.com/user-attachments/assets/298f5926-eacb-4db6-864f-25dd82e7f62e)

3. Click on `Endpoint Security Threat Prevention` Product and select `Exploit Prevention`
4. Click on `Edit` button corresponding to policy you want to update

![image](https://user-images.githubusercontent.com/89252889/184321097-eaaa7e72-9732-4b1c-9016-7f406d25bf8f.png)

5. Click on `Show Advanced` button to view advanced settings for Exploit Prevention
6. Go to `Signatures` section and click on `Add Expert Rule` button

![image](https://user-images.githubusercontent.com/89252889/184321778-48601b6b-ecc4-4469-b799-5dc933608b05.png)


7. Fill in details for *`Rule name`*, *`Severity`*, *`Action`*, *`Rule Type`* and *`Rule Content`*
8. Click on `Save` to save an expert rule


## Support

For syntactical issues related to Expert Rules, please raise an [issue.](https://github.com/trellix-enterprise/ExpertRules/issues) <br/>
To know more on support for custom ENS rules. Refer [KB94889](https://thrive.trellix.com/s/article/KB94889)

## Resources
[Expert Rules training videos](https://kbm.trellix.com/corporate/index?page=content&id=KB89677) <br/>
[10.7.x Product guide – Using Expert Rules](https://docs.trellix.com/bundle/endpoint-security-10.7.x-product-guide-windows/page/GUID-56587D0E-F87B-4534-B81F-07EF5FBAD057.html) <br/>
[10.6.x Product guide – Overview of Expert Rules](https://docs.trellix.com/bundle/endpoint-security-10.6.0-threat-prevention-product-guide-windows/page/GUID-7DDC330D-DF62-4CBE-9A48-486A70F8665B.html) <br/>

## 🤝 Contributing

Thanks for taking the time to [contribute](COMMUNITY)!
