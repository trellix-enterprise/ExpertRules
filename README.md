# ExpertRules

## Overview

This repository contains the set of rules that can be used with Trellix Endpoint Security in the Exploit Prevention policy. 
The rules are classified into 2 major groups:

*1. Trellix* 
		- Contains the rules that are either authored by Trellix or derived from the Community authored expert rules. It contains different categories of Expert rules considering the purpose of the rule. All the rules within the *GENERIC_RULES* folder under *TRELLIX* can be considered as examples for learning.
		- These Expert rules in their current form have undergone validation for syntax, functionality and limited QA has been performed on a selected set of platforms. The rules are typically documented to provide details on the tested environment, links to techniques, limitations (if any), etc. Customer may further customize these template rules to suit their environment.
		
*2. COMMUNITY* 
		- Contains rules authored by Expert Rule Community
		- The Expert Rule community comprises of External Contributors to Trellix Endpoint Security product in terms of authoring Exploit Prevention Expert Rules. This comprises of Blue teamers, Customers, Security Professionals, SOC, etc.

*Note:*
Trellix recommends that all the Expert rules listed under *TRELLIX* and *COMMUNITY* repositories are validated on a non-production test environment based on the Customer's requirement. Customers should exercise caution in deploying the Expert rules in their environment. 


## 🚀 Adding an Expert Rule

1. Log on to EPO Console using your credentials
2. Go to "Policy Catalog" page from the menu


3. Click on Endpoint Security Threat Prevention Product and select Exploit Prevention.


4. Click on Edit button corresponding to policy you want to update
5. Click on "Show Advanced" button to view advanced settings for Exploit Prevention
6. Go to "Signatures" section and click on Add Expert Rule button
7. Fill in details for *Rule name*, *Severity*, *Action*, *Rule Type* and *Rule Content*
8. Click on "Save" to save an expert rule

## BUGS and FEEDBACK

For bugs related to Expert Rules, please get in touch with Trellix Field Engineering Team and raise a ticket.

For any other issues or feedback. Please raise an [issue](https://github.com/mcafee-enterprise/ExpertRules/issues) 

## 🤝 Contributing
Thanks for taking the time to [contribute](COMMUNITY)!