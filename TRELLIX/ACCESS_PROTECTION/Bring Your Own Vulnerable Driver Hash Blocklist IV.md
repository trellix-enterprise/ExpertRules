# Bring Your Own Vulnerable Driver Hash Blocklist IV

## Author
Trellix

## Description
The expert rule detects and blocks the driver load for listed vulnerable driver hashes.

## Rule Class
File

## Rule TCL
```tcl
Rule {
			Process {
				Include OBJECT_NAME { -v "SYSTEM" }
			}
			Target {
				Match FILE {
					Include SHA2_256 { 
									-v "fd388cf1df06d419b14dedbeb24c6f4dff37bea26018775f09d56b3067f0de2c"
									-v "93b266f38c3c3eaab475d81597abbd7cc07943035068bb6fd670dbbe15de0131"
									-v "3871e16758a1778907667f78589359734f7f62f9dc953ec558946dcdbe6951e3"
									-v "f8886a9c759e0426e08d55e410b02c5b05af3c287b15970175e4874316ffaf13"
									-v "cb57f3a7fe9e1f8e63332c563b0a319b26c944be839eabc03e9a3277756ba612"
									-v "ece0a900ea089e730741499614c0917432246ceb5e11599ee3a1bb679e24fd2c"
									-v "6191c20426dd9b131122fb97e45be64a4d6ce98cc583406f38473434636ddedc"
									-v "9368e51ec98e2ad20893a5fc21e6a8b20c5bee158d5c49ca58649cff84db9d68"
									-v "5b9623da9ba8e5c80c49473f40ffe7ad315dcadffc3230afdc9d9226d60a715a"
									-v "16768203a471a19ebb541c942f45716e9f432985abbfbe6b4b7d61a798cea354"
									-v "03e0581432f5c8cc727a8aa387f5b69ff84d38d0df6f1226c19c6e960a81e1e9"
									-v "3243aab18e273a9b9c4280a57aecef278e10bfff19abb260d7a7820e41739099"
									-v "19a212e6fc324f4cb9ee5eba60f5c1fc0191799a4432265cbeaa3307c76a7fc0"
									-v "3a65d14fd3b1b5981084cdbd293dc6f4558911ea18dd80177d1e5b54d85bcaa0"
									-v "a5a4a3c3d3d5a79f3ed703fc56d45011c21f9913001fcbcc43a3f7572cff44ec"
									-v "28999af32b55ddb7dcfc26376a244aa2fe297233ce7abe4919a1aef2f7e2cee7"
									-v "29a90ae1dcee66335ece4287a06482716530509912be863c85a2a03a6450a5b6"
									-v "6de84caa2ca18673e01b91af58220c60aecd5cccf269725ec3c7f226b2167492"
									-v "e1980c6592e6d2d92c1a65acad8f1071b6a404097bb6fcce494f3c8ac31385cf"
									-v "9f1229cd8dd9092c27a01f5d56e3c0d59c2bb9f0139abf042e56f343637fda33"
									-v "708016fbe22c813a251098f8f992b177b476bd1bbc48c2ed4a122ff74910a965"
									-v "8111085022bda87e5f6aa4c195e743cc6dd6a3a6d41add475d267dc6b105a69f"
									-v "f7b3112b9745b766c8359d25e315975d3159935a8ddb3e3035d21ed124a9013f"
									-v "2b186926ed815d87eaf72759a69095a11274f5d13c33b8cc2b8700a1f020be1d"
									-v "7ec93f34eb323823eb199fbf8d06219086d517d0e8f4b9e348d7afd41ec9fd5d"
									-v "9f4ce6ab5e8d44f355426d9a6ab79833709f39b300733b5b251a0766e895e0e5"
									-v "1aaf4c1e3cb6774857e2eef27c17e68dc1ae577112e4769665f516c2e8c4e27b"
									-v "074ae477c8c7ae76c6f2b0bf77ac17935a8e8ee51b52155d2821d93ab30f3761"
									-v "0d133ced666c798ea63b6d8026ec507d429e834daa7c74e4e091e462e5815180"
									-v "bea8c6728d57d4b075f372ac82b8134ac8044fe13f533696a58e8864fa3efee3"
									-v "22be050955347661685a4343c51f11c7811674e030386d2264cd12ecbf544b7c"
									-v "cc687fe3741bbde1dd142eac0ef59fd1d4457daee43cdde23bb162ef28d04e64"
									-v "42e170a7ab1d2c160d60abfc906872f9cfd0c2ee169ed76f6acb3f83b3eeefdb"
									-v "b0dcdbdc62949c981c4fc04ccea64be008676d23506fc05637d9686151a4b77f"
					}
					Include -access "EXECUTE"
				}
			}
		}

```

## Tested Platforms
OS: Windows 10 20H2 x64 and x86
ENS: 10.7.0

## Notes
Customers are advised to fine-tune the rule in their environment or disable the signature if there are false positives.