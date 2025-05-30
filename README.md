
# Envy - Low-Privilege PowerShell Enumeration Tool

```
/$$$$$$$$                               
| $$_____/                               
| $$       /$$$$$$$  /$$    /$$ /$$   /$$
| $$$$$   | $$__  $$|  $$  /$$/| $$  | $$
| $$__/   | $$  \ $$ \  $$/$$/ | $$  | $$
| $$      | $$  | $$  \  $$$/  | $$  | $$
| $$$$$$$$| $$  | $$   \  $/   |  $$$$$$$
|________/|__/  |__/    \_/     \____  $$
                                /$$  | $$
                               |  $$$$$$/
                                \______/
```

**Author:** The_Red_Serpent  
**License:** MIT  
**Last Updated:** May 30, 2025

---

## 🔍 Overview

**Envy** is a stealthy, low-privilege PowerShell script for penetration testers and red teamers to enumerate Windows systems and Active Directory environments. Built entirely using native PowerShell, it operates in-memory, minimizes forensic traces, and provides detailed insight for reconnaissance and privilege escalation hunting.

---

## 🛠️ Features

- **Low-Privilege:** Functions under standard user permissions, with fallbacks for restricted environments.
- **Stealthy:** File-less execution; randomized temp files (e.g., `secpol_<GUID>.cfg`) auto-deleted.
- **Enumeration Coverage:**
  - **System:** OS, kernel, architecture, uptime, hotfixes, installed apps.
  - **Security:** Windows Defender, Sysmon, antivirus, firewall, password policies.
  - **Network:** IP configuration, ARP table, shares, network computers.
  - **Active Directory:** Domain info, trusts, users, groups, SIDs, OUs, GPOs.
- **Reliable Detection:** Office, Sysmon, and other software checks use redundant sources.
- **Clear Output:** 
  - Green ASCII art banner
  - Red author credit
  - Cyan-highlighted sections
- **Modular & Extendable:** Easily modify for custom enumeration tasks.

---

## ⚙️ Setup

### Clone the Repository
```bash
git clone https://github.com/TheRedSerpent/Envy.git
cd Envy
```

### Verify PowerShell Version

Ensure PowerShell **5.1+** (default on Windows 10/11):

```powershell
$PSVersionTable.PSVersion
```

### Run Envy

No dependencies or installation needed:

```powershell
.\Envy.ps1
```

---

## ▶️ Usage

Launch from a PowerShell console. No parameters needed.

```powershell
.\Envy.ps1
```

Envy will automatically detect domain context and adapt enumeration accordingly.

---

## ✅ Requirements

- Windows 10 or 11
- PowerShell 5.1+
- Standard user account (Domain access needed for AD enumeration)
- Native cmdlets (`Get-CimInstance`, `Get-ADDomain`, etc.)

---

## 💡 Tips

- **Non-Admin Mode:** Fallbacks like `wmic` ensure data collection even if some features are restricted.
- **AD Environment:** AD cmdlets use `ActiveDirectory` module if present; otherwise, fall back to tools like `nltest`.
- **Stealth:** All operations are performed in-memory. No persistent files are left behind.

---

## 📄 Sample Output

```
/$$$$$$$$                               
| $$_____/                               
| $$       /$$$$$$$ /$$    /$$ /$$   /$$
| $$$$$   | $$__  $$/  $$  /$$/| $$  $$
| $$__/   | $$  \ $$ \  $$/$$/ | $$  | $$
| $$      | $$  | $$  \  $$$/  | $$  | $$
| $$$$$$$$| $$  | $$   \  $/   |  $$$$$$$/
|________/|__/  |__/    \_/     \____  $$
                                /$$  | $$
                               |  $$$$$/
                                \______/
 
Author: The_Red_Serpent  
Timestamp: 20250530_220300

--------------------------------------------------
Script Started
--------------------------------------------------
Low-Privilege Enumeration started at 20250530_220300

--------------------------------------------------
System Info
--------------------------------------------------
ComputerName    OSCaption                    KernelVersion Architecture TotalPhysicalMemoryMB
------------    ---------                    ------------- ------------ -------------------
DESKTOP-7ABCD   Microsoft Windows 11 Pro    22631         64-bit       16384

--------------------------------------------------
Sysmon Status
--------------------------------------------------
SysmonProcessRunning SysmonServiceStatus SysmonStatus FileExists RegistryExists
------------------- ------------------- ------------- ---------- --------------
False               Not Installed       Not Installed False      False
```

---

## 📬 Contributions

We welcome contributions to improve Envy! To contribute:

1. **Fork** the repo.
2. **Create** a feature branch:
   ```bash
   git checkout -b feature/add-task
   ```
3. **Commit** your changes:
   ```bash
   git commit -m 'Added new feature'
   ```
4. **Push** to your fork:
   ```bash
   git push origin feature/add-task
   ```
5. **Open** a pull request.

⚠️ Focus on stealth, low-privilege enumeration, and in-memory operation.

---

## 🐞 Issues

Having trouble? For Office or Sysmon detection failures or any other issues:

- Check console output for errors.
- Verify PowerShell version and domain context.
- File an issue with:
  - Description of the problem
  - Console output
  - OS and PowerShell version

---

## 📄 License

**MIT License** — see `LICENSE` for full text.

---

## 🙏 Acknowledgments

- **Yokai Whispers**: For Dragging me into AD.
- **PowerShell Developers**: For empowering robust enumeration using native tools.

---

## 🕵️ Pentester Tip

> **Use Envy’s outputs to identify weak policies or unpatched software. Correlate findings with the [NIST NVD](https://nvd.nist.gov/) or [Exploit-DB](https://www.exploit-db.com/) to uncover privilege escalation vectors. Stay sneaky!**

