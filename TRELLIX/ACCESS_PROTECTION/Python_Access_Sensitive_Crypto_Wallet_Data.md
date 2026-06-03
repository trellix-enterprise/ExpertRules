# Python Access Sensitive Crypto Wallet Data

## Author
Trellix

## Description
This rule blocks any Python process accessing known cryptocurrency wallet storage paths indicating potential sensitive data collection activity.

## Rule Class 
Files

## Rule TCL
```tcl
Rule {
            Process {
                 Include OBJECT_NAME { -v "python.exe" }
				 Include OBJECT_NAME { -v "pythonw.exe" }
            }
            Target {
				Match FILE { 
						Include OBJECT_NAME { -v "**\\Authy Desktop\\Local Storage\\leveldb**" }
						Include OBJECT_NAME { -v "**\\Exodus**" }
						Include OBJECT_NAME { -v "**\\Bitcoin\\wallets**" }
						Include OBJECT_NAME { -v "**\\com.liberty.jaxx\\IndexedDB\\file__0.indexeddb.leveldb**" }
						Include OBJECT_NAME { -v "**\\Binance**" }
						Include OBJECT_NAME { -v "**\\atomic\\Local Storage\\leveldb**" }
						Include OBJECT_NAME { -v "**\\Electrum\\wallets**" }
						Include OBJECT_NAME { -v "**\\Daedalus Mainnet\\wallets**" }
						Include OBJECT_NAME { -v "**\\Ledger Live**" }
						Include OBJECT_NAME { -v "**\\Coinomi\\Coinomi\\wallets**" }
						Include -access "READ"
                }
          
            }
      
			}

```
## Trigger
NA

## Tested Platforms
OS: Windows 10 19H2 x64 and Windows 10 x86
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.