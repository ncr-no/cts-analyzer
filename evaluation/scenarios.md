# Attack Scenarios

## Windows 1
- **Host**: g2-1-internal-m
- **IP address**: 10.12.1.10

### Procedures
1. **Impersonate user**
   - **ATT&CK**: Command and Scripting Interpreter - Powershell (T1059.001)
   - **Tactic**: Execution
   - **CALDERA timestamp**: 12/5/2023, 9:01:38 AM GMT+1
   - **Wazuh timestamp**: 2023-12-05T08:02:14.834+0000
   - **Detected as**: Valid Accounts (T1078), Account Access Removal (T1531)

2. **Access Saved Credentials via VaultCmd**
   - **ATT&CK**: Credentials from Password Stores - Windows Credential Manager (T1555.004)
   - **Tactic**: Credential Access
   - **CALDERA timestamp**: 12/5/2023, 9:36:43 AM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: -

3. **Activate Guest Account**
   - **ATT&CK**: Valid Accounts: Default Accounts (T1078.001)
   - **Tactics**: Initial Access, Defense Evasion, Persistence, Privilege Escalation
   - **CALDERA timestamp**: 12/5/2023, 3:12:38 PM GMT+1
   - **Wazuh timestamp**: 2023-12-05T14:12:52.003+0000
   - **Detected as**: Account Manipulation (T1098)

4. **Execute a Command as a Service**
   - **ATT&CK**: System Services - Service Execution (T1569.002)
   - **Tactic**: Execution
   - **CALDERA timestamp**: 12/5/2023, 3:25:54 PM GMT+1
   - **Wazuh timestamp**: 2023-12-05T14:26:20.456+0000
   - **Detected as**: Windows Service (T1543.003)

5. **Enabling Remote Desktop Protocol via Remote Registry**
   - **ATT&CK**: Modify Registry (T1212)
   - **Tactic**: Defense evasion
   - **CALDERA timestamp**: 12/7/2023, 11:32:51 AM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: Modify Registry (T1112)

6. **Discover local hosts**
   - **ATT&CK**: Remote System Discovery (T1018)
   - **Tactic**: Discovery
   - **CALDERA timestamp**: 12/7/2023, 1:52:21 PM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: -

7. **Install PowerShell Core 6**
   - **ATT&CK**: Ingress Tool Transfer (T1105)
   - **Tactic**: Command and Control
   - **CALDERA timestamp**: 12/8/2023, 9:21:56 AM GMT+1
   - **Wazuh timestamp**: 2023-12-08T08:22:57.353+0000
   - **Detected as**: "Application installed Product: PowerShell 6-x64"

8. **Crypto (Monero) Mining**
   - **ATT&CK**: Resource Hijacking (T1496)
   - **Tactic**: Impact
   - **CALDERA timestamp**: 12/8/2023, 10:28:27 AM GMT+1
   - **Wazuh timestamp**: 2023-12-08T09:29:32.682+0000
   - **Detected as**: Windows Service, Resource Hijacking

## Windows 2

- **Host**: g2-2-internal-m
- **IP address**: 10.12.1.20

### Procedures

1. **Brute Force Credentials of single Active Directory domain user via LDAP against domain controller (NTLM or Kerberos)** 
   - **ATT&CK**: Brute Force (T1110)
   - **Tactic**: Credential Access
   - **CALDERA timestamp**: 12/6/2023, 9:07:38 AM GMT+1
   - **Wazuh timestamp**: 2023-12-06T08:08:03.751+0000
   - **Detected as**: Brute Force (T1110)

2. **Create Hidden User in Registry**
   - **ATT&CK**: Hide Artifacts: Hidden Users (T1564.002)
   - **Tactic**: Defense evasion
   - **CALDERA timestamp**: 12/6/2023, 10:55:46 AM GMT+1
   - **Wazuh timestamp**: 2023-12-06T09:56:35.244+0000
   - **Detected as**: Account Manipulation (T1098)

3. **WMI Execute Local Process**
   - **ATT&CK**: Windows Management Instrumentation (T1047)
   - **Tactic**: Execution
   - **CALDERA timestamp**: 12/6/2023, 12:37:33 PM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: -

4. **Service Installation PowerShell**
   - **ATT&CK**: Create or Modify System Process - Windows Service (T1543.003)
   - **Tactic**: Persistence, Privilege Escalation
   - **CALDERA timestamp**: 12/6/2023, 3:52:23 PM GMT+1
   - **Wazuh timestamp**: 2023-12-06T14:52:35.222+0000
   - **Detected as**: Windows Service (T1543.003)

5. **Create and Hide a Service with sc.exe**
   - **ATT&CK**: Hide Artifacts (T1564)
   - **Tactic**: Defense evasion
   - **CALDERA timestamp**: 12/7/2023, 7:56:29 AM GMT+1
   - **Wazuh timestamp**: 2023-12-07T06:56:31.705+0000
   - **Detected as**: Windows Service (T1543.003)

6. **System Information Discovery**
   - **ATT&CK**: System Information Discovery (T1082)
   - **Tactic**: Discovery
   - **CALDERA timestamp**: 12/7/2023, 2:38:59 PM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: -

7. **Change User Password - Windows**
   - **ATT&CK**: Account Access Removal (T1531)
   - **Tactic**: Impact
   - **CALDERA timestamp**: 12/8/2023, 10:56:54 AM GMT+1
   - **Wazuh timestamp**: 2023-12-08T09:57:15.860+0000
   - **Detected as**: Account Manipulation (T1098)

8. **Windows - Stop service by killing process**
   - **ATT&CK**: Service Stop (T1489)
   - **Tactic**: Impact
   - **CALDERA timestamp**: 12/8/2023, 11:15:53 AM GMT+1
   - **Wazuh timestamp**: 2023-12-08T10:16:26.752+0000
   - **Detected as**: "Print Spooler terminated unexpectedly"

## Ubuntu 1

- **Hosts**: g2-1-dmz-machine, 1-web-machine-g2
- **IP addresses**: 10.12.3.10, 10.12.2.10

### Procedures

1. **Create a new user in Linux with `root` UID and GID.**
   - **ATT&CK**: Create Account - Local Account (T1136.001)
   - **Tactic**: Persistence
   - **CALDERA timestamp**: 12/5/2023, 9:56:21 AM GMT+1
   - **Wazuh timestamp**: 2023-12-05T08:56:36.778+0000
   - **Detected as**: Create Account (T1136)

2. **Malicious PAM rule**
   - **ATT&CK**: Modify Authentication Process - Pluggable Authentication Modules (T1556.003) 
   - **Tactics**: Persistence, Defense Evasion, Credential Access
   - **CALDERA timestamp**: 12/5/2023, 3:57:37 PM GMT+1
   - **Wazuh timestamp**: 2023-12-05T14:57:43.496+0000
   - **Detected as**: "PAM: Login session opened."

3. **Unlimited sudo cache timeout**
   - **ATT&CK**: Abuse Elevation Control Mechanism - Sudo and sudo caching (T1548.003)
   - **Tactics**: Privilege Escalation, Defense Evasion
   - **CALDERA timestamp**: 12/6/2023, 12:18:31 PM GMT+1
   - **Wazuh timestamp**: 2023-12-06T11:18:55.593+0000
   - **Detected as**: Sudo and Sudo Caching (T1548.003)

4. **Scan IP for ports**
   - **ATT&CK**: Network Service Discovery (T1046)
   - **Tactic**: Discovery
   - **CALDERA timestamp**: 12/7/2023, 12:28:41 PM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: -

5. **Start 54ndc47 (2)**
   - **ATT&CK**: Remote Services - SSH (T1021.004)
   - **Tactic**: Lateral Movement
   - **CALDERA timestamp**: 12/7/2023, 1:31:21 PM GMT+1
   - **Wazuh timestamp**: 2023-12-07T14:48:08.013+0000
   - **Detected as**: Lateral Tool Transfer (T1570) 

6. **Reboot System via `halt` - Linux**
   - **ATT&CK**: Impair Defenses - Disable or Modify Tools (T1562.001)
   - **Tactic**: Defense Evasion
   - **CALDERA timestamp**: 12/7/2023, 3:47:49 PM GMT+1
   - **Wazuh timestamps**: 2023-12-07T14:48:15.198+0000, 2023-12-07T14:48:54.946+0000
   - **Detected as**: System Shutdown/Reboot (T1529)

## Ubuntu 2

- **Host**: g2-2-dmz-machine
- **IP address**: 10.12.3.20

### Procedures

1. **Access /etc/{shadow,passwd,master.passwd} with shell builtins**
   - **ATT&CK**: OS Credential Dumping - /etc/passwd and /etc/shadow (T1003.008)
   - **Tactic**: Credential Access
   - **CALDERA timestamp**: 12/5/2023, 10:57:07 AM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: -

2. **Malicious PAM rule**
   - **ATT&CK**: Modify Authentication Process - Pluggable Authentication Modules (T1556.003)
   - **Tactics**: Persistence, Defense Evasion, Credential Access
   - **CALDERA timestamp**: 12/5/2023, 11:57:11 AM GMT+1
   - **Wazuh timestamp**: 2023-12-05T10:58:01.585+0000
   - **Detected as**: "PAM: Login session opened."

3. **Weak executable files**
   - **ATT&CK**: Hijack Execution Flow - Services File Permissions Weakness (T1574.010)
   - **Tactic**: Privilege Escalation
   - **CALDERA timestamp**: 12/6/2023, 9:16:54 AM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: -

4. **Sudo usage**
   - **ATT&CK**: Abuse Elevation Control Mechanism - Sudo and sudo caching (T1548.003)
   - **Tactics**: Privilege Escalation, Defense Evasion
   - **CALDERA timestamp**: 12/6/2023, 3:54:56 PM GMT+1
   - **Wazuh timestamp**: 2023-12-06T14:55:31.026+0000
   - **Detected as**: Sudo and Sudo Caching

5. **System Owner/User Discovery**
   - **ATT&CK**: System Owner/User Discovery (T1033)
   - **Tactic**: Discovery
   - **CALDERA timestamp**: 12/8/2023, 9:35:17 AM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: -

6. **Encrypt files using ccrypt (FreeBSD/Linux)**
   - **ATT&CK**: Data Encrypted for Impact (T1486)
   - **Tactic**: Impact
   - **CALDERA timestamp**: 12/8/2023, 2:51:08 PM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: -

## Ubuntu 3

- **Host**: 2-web-machine-g2
- **IP address**: 10.12.2.20

### Procedures

1. **Create and Execute Bash Shell Script**
   - **ATT&CK**: Command and Scripting Interpreter - Unix Shell (T1059.004)
   - **Tactic**: Execution
   - **CALDERA timestamp**: 12/6/2023, 9:31:00 AM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: -

2. **Create local account (Linux)**
   - **ATT&CK**: Valid Accounts - Local Accounts (T1078.003)
   - **Tactics**: Initial Access, Defense Evasion, Persistence, Privilege Escalation
   - **CALDERA timestamp**: 12/6/2023, 2:40:36 PM GMT+1
   - **Wazuh timestamps**: 2023-12-06T13:40:51.921+0000, 2023-12-06T13:40:53.925+0000
   - **Detected as**: Create Account (T1136), Valid Accounts (T1078)

3. **Set a SetGID flag on file**
   - **ATT&CK**: Abuse Elevation Control Mechanism - Setuid and Setgid (T1548.001)
   - **Tactics**: Privilege Escalation, Defense Evasion
   - **CALDERA timestamp**: 12/7/2023, 12:00:01 PM GMT+1
   - **Wazuh timestamps**: 2023-12-07T11:00:22.494+0000, 2023-12-07T11:00:22.539+0000
   - **Detected as**: Sudo and Sudo Caching (T1548.003), Valid Accounts (T1078)

4. **System Owner/User Discovery**
   - **ATT&CK**: System Owner/User Discovery (T1033)
   - **Tactic**: Discovery
   - **CALDERA timestamp**: 12/7/2023, 3:05:21 PM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: -

5. **Data Compressed - nix - gzip Single File**
   - **ATT&CK**: Archive Collected Data - Archive via Utility (T1560.001)
   - **Tactic**: Collection
   - **CALDERA timestamp**: 12/8/2023, 9:50:29 AM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: -

6. **Exfiltrate data HTTPS using curl freebsd,linux or macos**
   - **ATT&CK**: Exfiltration Over Alternative Protocol - Exfiltration Over Asymmetric Encrypted Non-C2 Protocol (T1048.002)
   - **Tactic**: Exfiltration
   - **CALDERA timestamp**: 12/8/2023, 1:54:32 PM GMT+1
   - **Wazuh timestamp**: -
   - **Detected as**: -
