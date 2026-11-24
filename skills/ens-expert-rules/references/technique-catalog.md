# ENS Expert Rules — Technique Catalog

A catalogue of attacker techniques an Expert Rule can counter, organised by MITRE
ATT&CK tactic. Use it to pick the right **target type** and **access flags** for an
intent, and to name and describe the rule the way the community rule set does (by
technique ID; see the Description house style in
[best-practices.md §3](best-practices.md)).

For the exact syntax of each pattern (process launch = `Match PROCESS` + `CREATE`,
DLL/driver load = `Match FILE` + `EXECUTE`, registry value = `Match VALUE` + `CREATE WRITE`,
when to omit the initiator) see [rule-patterns.md](rule-patterns.md).

Each entry lists: the technique (and ATT&CK ID), the `Match` target type and the
access to guard, and a Description in house style. These are starting points —
scope the initiator and anchor the target path before shipping, and lint.

**Coverage weighting.** In a comprehensive rule set the two highest-volume
categories are (1) **CVE-specific exploit-prevention rules** — one rule per notable
vulnerability (see the CVE section below) — and (2) technique families with many
variants (services, script interpreters, UAC bypass, LOLBINs), which warrant
several rules each rather than one. Expect many CVE rules and multiple rules per
technique, not a single rule per row here.

---

## Credential Access

- **LSASS memory dumping** (T1003.001) — `Match PROCESS` on `lsass.exe` with
  `-nt_access` read masks (`PROCESS_VM_READ`, `PROCESS_QUERY_INFORMATION`).
  *This rule prevents untrusted processes from opening lsass.exe with read access to steal credentials from memory.*
- **SAM / SYSTEM hive theft** (T1003.002) — `Match FILE` on the SAM/SYSTEM/SECURITY
  hive files (and `\Windows\System32\config\`) with `READ`/`READ_DATA`.
  *This rule prevents non-system processes from reading the SAM and SYSTEM registry hives to extract stored credentials offline.*
- **NTDS.dit extraction** (T1003.003) — `Match FILE` on `ntds.dit` with copy/read
  access.
  *This rule detects attempts to read or copy the Active Directory database ntds.dit for offline credential extraction.*
- **Browser credential store theft** (T1555.003) — `Match FILE` on browser
  `Login Data`/`cookies` databases with `READ`, initiator not the browser itself.
  *This rule prevents processes other than the browser from reading saved-password and cookie databases.*
- **WDigest plaintext downgrade** (T1112) — `Match VALUE` on
  `…\SecurityProviders\WDigest\UseLogonCredential` with `WRITE`.
  *This rule blocks modification of the WDigest UseLogonCredential value that re-enables plaintext credentials in memory.*

## Persistence

- **Run / RunOnce keys** (T1547.001) — `Match VALUE` under
  `…\CurrentVersion\Run` / `RunOnce` with `WRITE`.
  *This rule prevents untrusted processes from writing autostart values under the Run registry keys.*
- **Startup folder** (T1547.001) — `Match FILE` under the Start Menu `Startup`
  folder with `CREATE`/`WRITE`, initiator a script host.
  *This rule prevents script interpreters from dropping executables into the Startup folder for persistence.*
- **Scheduled tasks** (T1053.005) — `Match FILE` under `System32\Tasks`, or a
  `PROCESS` rule on `schtasks.exe`.
  *This rule detects creation of scheduled-task definitions by untrusted processes.*
- **Windows service create / modify** (T1543.003) — `Match KEY`/`Match VALUE`
  under `…\Services\` (`ImagePath`, `ServiceDll`) with `CREATE`/`WRITE`, or
  `Match SERVICE`.
  *This rule prevents untrusted processes from creating or repointing a Windows service to run attacker code.*
- **Winlogon Shell / Userinit hijack** (T1547.004) — `Match VALUE` on the Winlogon
  `Shell`/`Userinit` values with `WRITE`.
  *This rule blocks modification of the Winlogon Shell and Userinit values that hijack the logon sequence.*
- **Image File Execution Options debugger** (T1546.012) — `Match KEY`/`Match VALUE`
  under `…\Image File Execution Options\` `Debugger` with `WRITE`.
  *This rule prevents writes to IFEO Debugger values used to hijack execution of legitimate binaries.*
- **AppInit_DLLs injection** (T1546.010) — `Match VALUE` on `AppInit_DLLs` /
  `LoadAppInit_DLLs` with `WRITE`.
  *This rule blocks modification of the AppInit_DLLs value that forces a DLL into every user-mode process.*
- **COM hijack** (T1546.015) — `Match KEY` under HKCU `…\CLSID\…\InprocServer32`
  with `WRITE`.
  *This rule detects COM object hijacking via untrusted writes to HKCU InprocServer32 keys.*
- **Netsh helper DLL** (T1546.007) — `Match VALUE` under the netsh `Helper` DLL key.
  *This rule prevents registration of a netsh helper DLL used to load attacker code.*

## Privilege Escalation

- **UAC bypass (fodhelper / eventvwr / sdclt)** (T1548.002) — `Match VALUE` under
  the hijacked HKCU keys (`…\ms-settings\shell\open\command`), or a `PROCESS` rule
  on the auto-elevating binary's untrusted child.
  *This rule detects UAC-bypass registry hijacks that auto-elevate an attacker command.*
- **Access-token / thread impersonation** (T1134) — `Match THREAD` with
  `DIRECT_IMPERSONATION` on privileged process threads.
  *This rule prevents untrusted processes from impersonating threads of privileged processes to escalate.*
- **Named-pipe impersonation to SYSTEM** (T1134.001) — `Match FILE`/pipe target on
  privileged named pipes.
  *This rule detects connections to privileged named pipes used to impersonate SYSTEM tokens.*
- **PrintNightmare spooler driver drop** (CVE-2021-34527, T1068) — `Match FILE`
  under `spool\drivers\` with `WRITE`, initiator `spoolsv.exe`.
  *This rule prevents the print spooler from writing driver DLLs to the spooler directory (PrintNightmare).*

## Defense Evasion

- **Disable / exclude security tooling** (T1562.001) — `Match VALUE` under the
  Defender `Exclusions` / `DisableAntiSpyware` keys with `WRITE`.
  *This rule blocks writes to Windows Defender exclusion and disable values that hide attacker activity.*
- **Terminate security processes** (T1562.001) — `Match PROCESS` on protected agent
  processes with `TERMINATE`.
  *This rule prevents untrusted processes from terminating the endpoint security agent.*
- **Clear Windows event logs** (T1070.001) — `Match PROCESS` on `wevtutil.exe`
  (clear-log args), or a `FILE` rule on `\winevt\Logs\` with `DELETE`.
  *This rule detects clearing of Windows event logs to destroy forensic evidence.*
- **Shadow copy / backup deletion** (T1490) — `Match PROCESS` on `vssadmin.exe`,
  `wmic.exe`, `wbadmin.exe`, `bcdedit.exe` with delete/disable arguments.
  *This rule blocks deletion of volume shadow copies and backups before ransomware encryption.*
- **Bring-your-own-vulnerable-driver** (T1068, T1211) — block the *load*: initiator
  `SYSTEM`, `Match FILE` with an `SHA2_256` hash list and `-access "EXECUTE"`; or guard
  driver writes to `\System32\drivers\` / `Match SERVICE` on kernel-service creation.
  *This rule detects installation of a vulnerable or unsigned driver used to disable protections.*
- **Code-signing / trust subversion; unsigned execution** (T1553.002) —
  `Match FILE` with `Exclude VTP_TRUST true` (or `Exclude CERT_NAME_CHAINED`) and
  `-access "EXECUTE"`.
  *This rule prevents execution of untrusted (unsigned) images by matching on VTP trust state.*
- **DLL search-order / sideload hijack** (T1574.001, T1574.002) — initiator = the
  trusted (often signed) host app; `Match FILE` on the sideloaded DLL name with
  `-access "EXECUTE"` and `Exclude CERT_NAME_CHAINED { -v "*O=<expected signer>*" }`;
  or guard the DLL *write* next to the app with `CREATE`.
  *This rule prevents non-installer processes from planting a DLL beside a trusted executable to hijack its load order.*

## Execution & LOLBIN Abuse

- **PowerShell / WSH / VBScript abuse** (T1059.001, T1059.005, T1059.007) —
  `Match FILE` with `EXECUTE`/`CREATE` where the initiator is `powershell.exe`,
  `wscript.exe`, `cscript.exe`.
  *This rule detects script interpreters writing or executing payloads from user-writable locations.*
- **Rundll32 / regsvr32 (Squiblydoo)** (T1218.011, T1218.010) — `Match FILE`
  `EXECUTE` of a DLL/scriptlet from Temp or a user profile (or `Match PROCESS` `CREATE`
  of rundll32/regsvr32 with a `PROCESS_CMD_LINE` filter), initiator `rundll32.exe` /
  `regsvr32.exe`.
  *This rule blocks rundll32 and regsvr32 from loading code from user-writable directories.*
- **mshta script execution** (T1218.005) — `Match PROCESS` `CREATE` of `mshta.exe`
  with a `PROCESS_CMD_LINE` filter (e.g. `**http**`, `**javascript:**`).
  *This rule detects mshta.exe executing remote or local script payloads.*
- **certutil download / decode** (T1140, T1105) — `Match FILE` with `CREATE`,
  initiator `certutil.exe`.
  *This rule prevents certutil.exe from writing executables while decoding or downloading payloads.*
- **BITS jobs** (T1197) — `Match FILE` with `CREATE`, initiator `bitsadmin.exe`.
  *This rule detects bitsadmin.exe creating executables via Background Intelligent Transfer.*
- **Trusted developer utilities (MSBuild / InstallUtil)** (T1127) — `Match FILE`
  `EXECUTE` of code from user-writable paths, initiator `msbuild.exe` / `installutil.exe`.
  *This rule prevents trusted developer tools from executing code from user directories to bypass allow-listing.*
- **WMI execution** (T1047) — `Match FILE` with `CREATE`, initiator
  `WmiPrvSE.exe` / `wmic.exe`.
  *This rule detects the WMI provider host writing executables for remote code execution.*

## Initial Access & Payload Delivery

- **Office application spawns payload** (T1566, T1204.002) — `Match FILE` with
  `CREATE`, initiator `winword.exe` / `excel.exe` / `powerpnt.exe`.
  *This rule prevents Office applications from dropping executables to disk from a malicious document.*
- **Malicious LNK / shortcut execution** (T1204.001) — `Match FILE` on `.lnk`
  creation in autostart locations.
  *This rule detects creation of shortcut files that launch attacker payloads.*

## Lateral Movement

- **PsExec-style remote service** (T1021.002, T1570) — `Match FILE` on executable
  writes to `ADMIN$` / remote share paths, or `Match SERVICE` creation.
  *This rule detects remote service executables planted for PsExec-style lateral movement.*
- **Remote thread injection** (T1055) — `Match PROCESS` with `CREATE_THREAD` on
  system processes such as `svchost.exe`, `explorer.exe`.
  *This rule prevents untrusted processes from creating remote threads inside system processes.*

## Impact

- **Ransomware mass encryption** (T1486) — `Match FILE` with `WRITE`/`RENAME` on
  bulk document paths, initiator untrusted.
  *This rule detects rapid renaming or rewriting of user documents indicating mass encryption.*
- **Master Boot Record / raw disk wipe** (T1561.002) — `Match DISK` on
  `PhysicalDrive` with `WRITE`.
  *This rule prevents non-system processes from writing raw sectors to the physical disk (bootkit / wiper).*

## Supply Chain

Compromised dependencies are a large, recurring rule category — cover each major
ecosystem, since one rule per package manager is normal.

- **npm post-install execution** (T1195.002) — `Match PROCESS`/`FILE`, initiator
  `npm`/`node` spawning a shell or writing an executable during install.
  *This rule detects npm install scripts spawning shells or dropping executables during dependency installation.*
- **pip / Python package execution** (T1195.002) — initiator `pip`/`python`
  writing outside the project tree during install.
  *This rule detects Python package installers executing or dropping payloads outside the project directory.*
- **NuGet / MSBuild restore execution** (T1195.002) — initiator `nuget`/`dotnet`
  executing code during package restore.
  *This rule detects .NET package restore executing untrusted code from a compromised dependency.*
- **Installer / update masquerade** (T1195) — untrusted process writing to a
  trusted application's update or install directory.
  *This rule prevents untrusted processes from planting payloads in a trusted application's update path.*

## CVE-Specific Exploit Prevention

The largest category in a mature rule set: one rule per notable vulnerability,
titled with the CVE. Match the exploit's on-disk or in-registry behaviour (the
initiator/target the exploit forces), not a signature of the payload.

- **PrintNightmare** (CVE-2021-34527, T1068) — `Match FILE` under `spool\drivers\`,
  initiator `spoolsv.exe`.
  *This rule prevents the print spooler from writing driver DLLs to the spooler directory as exploited by PrintNightmare.*
- **Follina / MSDT** (CVE-2022-30190, T1203) — `Match PROCESS`, initiator
  `msdt.exe` spawned by an Office application.
  *This rule detects msdt.exe launched by an Office application to execute code via the Follina vulnerability.*
- **Zerologon** (CVE-2020-1472) — `Match VALUE`/`SERVICE` on Netlogon secure-channel
  tampering.
  *This rule detects Netlogon changes consistent with Zerologon exploitation against a domain controller.*
- **ProxyShell / Exchange** (CVE-2021-34473, T1190) — `Match FILE`, initiator
  `w3wp.exe` writing web shells to Exchange virtual directories.
  *This rule prevents the Exchange worker process from writing web shells to server directories via ProxyShell.*
- **General web-shell drop** (T1505.003) — `Match FILE` with `CREATE` on
  `.aspx`/`.jsp`/`.php` under a web root, initiator a web server worker process.
  *This rule detects a web server process writing script files to its web root, indicating a web shell.*
