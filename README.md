<p align="center">
  <img src="assets/header-lsap.png" alt="Linux Security Audit Project" width="75%" />
</p>

---

# Linux Security Audit Project

<div align="center">
  
<!-- ============================================================================ -->
<!-- DYNAMIC BADGES - reflect live GitHub Actions workflow status and repo state -->
<!-- ============================================================================ -->

[![License: MIT](https://img.shields.io/badge/license-MIT-yellow?logo=opensourceinitiative&logoColor=white)](https://github.com/Sandler73/Linux-Security-Audit-Project/blob/main/LICENSE.md)
[![Python 3.7+](https://img.shields.io/badge/Python-3.7+-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Maintained: Yes](https://img.shields.io/badge/maintained-yes-green?logo=github&logoColor=white)](https://github.com/Sandler73/Linux-Security-Audit-Project/commits/main)

[![Platform: Linux](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)](https://www.kernel.org/)
[![Shell: Bash/Python](https://img.shields.io/badge/shell-Python-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?logo=github&logoColor=white)](https://github.com/Sandler73/Linux-Security-Audit-Project/blob/main/CONTRIBUTING.md)

[![Lines of Code: 45,000+](https://img.shields.io/badge/lines%20of%20code-45%2C000%2B-blue)](https://github.com/Sandler73/Linux-Security-Audit-Project)
[![Dependencies: 0](https://img.shields.io/badge/dependencies-0%20external-brightgreen)](https://github.com/Sandler73/Linux-Security-Audit-Project)
[![Wiki: 16 Pages](https://img.shields.io/badge/wiki-16%20pages-blue?logo=readthedocs&logoColor=white)](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki)
[![Checks](https://img.shields.io/badge/checks-2%2C319-brightgreen)](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki/Module-Documentation)
[![Frameworks](https://img.shields.io/badge/frameworks-16-orange)](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki/Framework-Reference)

[![Ubuntu 24.04](https://img.shields.io/badge/Ubuntu-24.04%20%7C%2022.04%20%7C%2020.04-E95420?logo=ubuntu&logoColor=white)](https://ubuntu.com/)
[![Debian 12](https://img.shields.io/badge/Debian-12%20%7C%2011-A81D33?logo=debian&logoColor=white)](https://www.debian.org/)
[![RHEL 9](https://img.shields.io/badge/RHEL-9%20%7C%208-EE0000?logo=redhat&logoColor=white)](https://www.redhat.com/)
[![Fedora](https://img.shields.io/badge/Fedora-41%20%7C%2040-51A2DA?logo=fedora&logoColor=white)](https://fedoraproject.org/)
[![Rocky/Alma](https://img.shields.io/badge/Rocky%20%7C%20Alma-9%20%7C%208-10B981?logo=rockylinux&logoColor=white)](https://rockylinux.org/)

<!-- ============================================================================ -->
<!-- STATIC BADGES - informational metadata that doesn't change without a release -->
<!-- ============================================================================ -->

**Module-Based Multi-Framework Linux Security Assessment, Auditing, and Remediation Tool**

[Overview](#-overview) * [Key Features](#-key-features) * [Quick Start](#-quick-start) * [Documentation](#-documentation) * [Remediation](#-remediation-capabilities) * [Contributing](#-contributing)

</div>

---

## Supported Operating Systems

| Distribution Family | Versions | Package Manager | MAC Framework | Status |
|---------------------|----------|-----------------|---------------|--------|
| **Ubuntu** | 24.04, 22.04, 20.04 | APT | AppArmor | [x] Tested |
| **Debian** | 12 (Bookworm), 11 (Bullseye) | APT | AppArmor | [x] Tested |
| **Linux Mint** | 21.x, 22.x | APT | AppArmor | [x] Compatible |
| **RHEL** | 9, 8 | DNF/YUM | SELinux | [x] Tested |
| **Fedora** | 41, 40, 39 | DNF | SELinux | [x] Tested |
| **Rocky Linux** | 9, 8 | DNF/YUM | SELinux | [x] Compatible |
| **AlmaLinux** | 9, 8 | DNF/YUM | SELinux | [x] Compatible |
| **CentOS Stream** | 9, 8 | DNF/YUM | SELinux | [x] Compatible |
| **openSUSE** | Leap 15.x, Tumbleweed | Zypper | AppArmor | [x] Compatible |
| **SLES** | 15 SP5+ | Zypper | AppArmor | [x] Compatible |
| **Arch Linux** | Rolling | Pacman | AppArmor | [x] Compatible |
| **Manjaro** | Rolling | Pacman | AppArmor | [x] Compatible |
| **Kali Linux** | 2024.x+ | APT | AppArmor | [x] Compatible |

**Requirements:** Root/sudo privileges - Python 3.7+ - 50 MB free disk space - No internet access required

---

## Overview

The **Linux Security Audit Project** is a Python-based security compliance auditing tool that evaluates Linux systems against multiple industry-standard security frameworks. The current release performs **2,297 automated security checks** across **16 compliance frameworks**, generating interactive reports in HTML, JSON, CSV, XML, and Console formats with actionable remediation guidance.

Every check includes a severity rating (Critical/High/Medium/Low/Informational) and categorization by security domain, enabling compliance scoring from a single audit run. The tool is fully self-contained - zero external dependencies, pure Python stdlib - and supports parallel execution, intelligent caching, compliance scoring with configurable thresholds, and OS-aware checks across Debian, Red Hat, SUSE, and Arch distribution families.

Whether you're conducting compliance audits, hardening systems, maintaining security baselines, or generating evidence for assessors, this tool provides the depth and automation you need.

## Key Features

### **Security Assessment**

* [x] **2,297 Security Checks** across 16 compliance frameworks
* [x] **Multi-Framework Coverage** - Core Baseline, CIS Benchmarks, CISA Best Practices, ENISA Cybersecurity, ISO 27001:2022, NIST SP 800-53/CSF 2.0/800-171, NSA Cybersecurity, DISA STIG
* [x] **Modular Architecture** - run all frameworks or select specific modules
* [x] **Severity Classification** - every check rated Critical/High/Medium/Low/Informational
* [x] **OS-Aware Checks** - distribution-specific optimizations for Debian, Red Hat, SUSE, and Arch families
* [x] **Standalone Module Execution** - any module can run independently without the orchestrator
* [x] **No External Dependencies** - pure Python 3.7+ stdlib; zero pip/conda/external network calls

### **Performance Architecture**

* [x] **Shared Components Library** - multi-module caching and utility infrastructure
* [x] **Intelligent Caching** - ~50% cache hit rate across modules via shared data
* [x] **Parallel Execution** - `--parallel` with configurable `--workers` count
* [x] **Direct /proc Reads** - kernel parameter reads without subprocess overhead
* [x] **Dynamic Module Discovery** - automatic detection and validation from `modules/` directory
* [x] **Performance Profiling** - `--perf-profile` flag for execution timing analysis (renamed from `--profile` in v3.7)
* [x] **Helper Caching Layer (v3.6)** - per-process cache on `command_available`, `systemd_active`, `run_command`, `read_sysctl`, `read_file_safe`, `file_exists`, `directory_exists` for 5-30x speedup on multi-module runs
* [x] **Cross-Module Correlation (v3.7)** - `HostFacts` registry computes ~80 derived host facts (FIM presence, FIPS state, MAC enforcement, firewall tool, container runtime, K8s indicators, tool inventories) once at audit start; modules consume from `shared_data["host_facts"]` instead of re-deriving

### **Per-Framework Split Reports**

* [x] **`--split-reports`** - one focused report per framework in `reports/by-framework/`, alongside the combined report
* [x] **`--split-only`** - generate only the per-framework reports
* [x] **Audience-targeted** - the PCI team gets a PCI report, the HIPAA team a HIPAA report, each with its own dashboard and score
* [x] **All formats** - HTML, CSV, JSON, XML

### **Attack Surface Assessment**

The `--attack-surface` flag generates a dedicated assessment report that
re-frames findings around *exposure* rather than pass/fail compliance. It is
produced from the same audit run and the host-facts registry, so it introduces
no duplicate checks.

* [x] **`--attack-surface`** - generate the attack-surface report (HTML + JSON)
* [x] **Ten exposure domains** - Network Exposure, Authentication, Privilege
  Escalation, Filesystem, Service Exposure, Kernel, Container, Credentials,
  Cryptography, and Detection Coverage
* [x] **Severity-weighted scoring** - each domain and the host receive an
  exposure score (0-100) with a Minimal / Low / Moderate / High rating
* [x] **Host summary panel** - distribution, firewall posture (each installed
  tool with its active/inactive state), external TCP listener count, MAC
  framework, auditd state, FIM tool, and container runtime
* [x] **Interactive HTML** - dark/light theme, collapsible domains, per-column
  filters, global search, sortable/resizable columns, and CSV/JSON/XML export
* [x] **CORE attack-surface checks** (`CORE - Attack Surface`):
  * External TCP/UDP listeners and exposed services
  * Legacy/insecure services (telnet, rsh, ftp, and similar)
  * SUID/SGID inventory and world-writable files
  * Container socket exposure (Docker/Podman) and kernel module-loading lockdown
  * **AS-008 Firewall posture** - installed vs active vs configured across
    ufw / firewalld / nftables / iptables (a host with a firewall package that
    is installed but disabled is reported distinctly from one with none)
  * **AS-009 Executable PATH** - world-writable or insecure directories on the
    executable search path
  * **AS-010 Shared objects / linker** - insecure `ld.so` configuration and
    writable library paths

### **Distribution Profiles**

* [x] **Eight Built-in Profiles** - `generic`, `rhel9`, `rhel8`, `ubuntu24`, `ubuntu22`, `debian12`, `alpine`, `suse15`
* [x] **Subtractive-Only Filtering** - profiles exclude inapplicable categories; never add or modify checks
* [x] **Strict Input Validation** - profile names validated against `^[a-z][a-z0-9_-]{0,30}$`; injection attempts rejected
* [x] **Hardcoded Profile Data** - no external file loads, no `eval`, no JSON/YAML parsing; profiles are auditable Python source
* [x] **CLI Integration** - `--profile NAME` and `--list-profiles`; `--list-profiles` shows applicable distros and excluded category prefixes per profile

### **Advanced Reporting**

* [x] **Interactive HTML Reports** with:
  + Dark/Light theme toggle
  + SVG donut chart executive dashboard with clickable segments
  + **Module Summary tiles** (v3.7) - color-banded grid (green/yellow/orange/red by health) with score, pass/fail/warn/info/error counts, top severity badge, and anchor links to module sections
  + **Top Priority Findings** (v3.7) - top 10 non-Pass results sorted by severity then status, displayed above the per-module tables
  + In-column filtering and global search (include/exclude)
  + Column resizing and column visibility toggles
  + Multi-format export (CSV, Excel, JSON, XML, TXT)
  + Checkbox-based row selection for targeted export
  + Per-module and global export options
  + Compliance matrix and remediation priority ranking
  + Print CSS and Table of Contents
  + Garamond typography, full-width header
* [x] **Compliance Scoring** - simple, weighted, severity-adjusted methods with configurable pass/fail thresholds
* [x] **Host Identification** - hostname, IP addresses, OS in every report format
* [x] **Multiple Output Formats** - HTML, JSON, CSV, XML, Console, plus companion JSON metadata
* [x] **Structured Logging** - dual console/file output, configurable levels, JSON format for SIEMs

### **Intelligent Remediation**

* [x] **Interactive Remediation** - review and apply fixes individually
* [x] **Automated Remediation** - batch fix with safety confirmations
* [x] **Selective Remediation** - target specific status types (Fail, Warning, Info)
* [x] **Targeted Remediation** - fix only selected issues from JSON export
* [x] **Remediation Logging** - full audit trail of all changes
* [x] **Safety Mechanisms** - double-confirmation and countdown timers


### v3.0 Foundation Capabilities (April 2026)

* [x] **Cross-Framework Correlation Registry** - 135 mapped controls bridging CIS, NIST, STIG, ISO 27001, NSA, CISA, ENISA, PCI DSS, HIPAA, GDPR, CMMC, ACSC. Each finding automatically enriched with equivalents in every applicable framework.
* [x] **Risk Priority Scoring (1-100)** - Combines severity, exploitability, exposure, and asset criticality into a single ranked score for prioritised remediation queues.
* [x] **Baseline Drift Detection** - `--baseline` compares against previous audit JSON to identify new failures, resolved findings, regressions, and improvements with compliance-score delta.
* [x] **Remediation Bundles** - 8 production bundles (HardenSSH, HardenKernel, EnableAuditLogging, HardenAuthentication, LockDownNetwork, SecureBootChain, HardenSystemd, DisableLegacyProtocols) with documented impact profiles.
* [x] **Rollback Script Generation** - Capture-before-modify pattern produces atomic bash rollback scripts for every remediation operation.
* [x] **OS Detection** - 30+ Linux distributions across Debian, Red Hat, SUSE, Arch, Alpine, Gentoo, Slackware, Void, NixOS families. Detects kernel version, init system, MAC framework, firewall, container runtime, and cloud provider.
* [x] **Three-Method Compliance Scoring** - Simple, weighted, and severity-adjusted methods for different reporting contexts.

### v3.4-v3.5 Quality & Correctness Hardening (April 2026)

* [x] **Distro-Aware Remediation Library** (`shared_components/remediation_library.py`) - 49 registered tools with per-family install commands, supporting packages, post-install configuration steps, service enable/start commands, and verification commands. AIDE on Debian correctly includes `aide-common`; ClamAV service name routes per family (`clamav-daemon` on Debian vs `clamd` on RHEL); chrony service is `chrony` on Debian, `chronyd` elsewhere.
* [x] **`OSInfo.pretty_name`** - accurate human-readable distribution display (e.g. "Ubuntu 24.04.4 LTS", "Rocky Linux 9.3 (Blue Onyx)") with multi-tier fallback chain. Replaces the `Linux X.Y.Z-generic` string previously rendered by `platform.system()`/`platform.release()`.
* [x] **Mock-based test suite** (`tests/test_os_detection.py`, `tests/test_remediation_library.py`) - 25 OS-detection tests covering Ubuntu 22.04/24.04/26.04, Debian 12, Mint, Pop!_OS, Kali, Parrot, RHEL 9, CentOS Stream, Rocky, AlmaLinux, Fedora 40, Oracle 9, Amazon 2023, openSUSE Leap/Tumbleweed, SLES, Arch, Manjaro, EndeavourOS, Alpine 3.19, Gentoo + universal invariants. 12 remediation library tests verify per-family parity, correct package manager syntax, and registered references.
* [x] **Mermaid architecture diagrams** in `wiki/Architecture-and-Design.md` - 6 rendered diagrams: system architecture, module execution lifecycle (sequence), cache hierarchy, remediation library flow, OS detection decision tree, audit pipeline phases.
* [x] **Runtime error fixes** - DistBaseline `int(mode, 8)` corrected (file_mode returns int, not string); NIST AU-9(2) `audisp_set` coerced to bool to prevent `TypeError("unsupported operand type(s) for +: 'int' and 'str'")`.

### **Quality Assurance**

* [x] **Status Normalization** - consistent categorization (Pass/Fail/Warning/Info/Error)
* [x] **Execution Metadata** - complete audit trail preservation
* [x] **Error Handling** - graceful degradation on check failures
* [x] **Privilege-Aware** - works with or without root (graceful degradation)
* [x] **Mock-based regression tests** - `tests/` directory with stdlib-only test runner; no pytest required

## Supported Frameworks

| Module | Framework | Checks | Focus Areas |
|--------|-----------|--------|-------------|
| **Core** | Linux foundational baseline | 185 | sudo/user/mount/cron/GRUB/PAM hygiene, service and listener inventory, secure boot chain, kernel lockdown, and attack-surface enumeration |
| **CIS** | CIS Benchmarks + Controls v8 IG3 | 258 | Sections 1-6: initial setup, services, network, logging/auditing, access/auth, system maintenance; Docker/Kubernetes hardening |
| **CISA** | CISA CPGs + ZTMM + KEV + Stop Ransomware + Secure by Design | 196 | BOD 22-01/23-01, KEV catalog, zero-trust maturity, cross-sector CPGs, supply chain, incident response |
| **ENISA** | ENISA + NIS2 Art 21 + Cyber Resilience Act + DORA | 142 | EU baseline security, network security, data protection, incident handling, business continuity, supply-chain risk |
| **ISO27001** | ISO/IEC 27001:2022 Annex A + 27017/27018/27701 | 147 | Organizational, people, physical, and technological controls; cloud (27017), PII (27018/27701) |
| **NIST** | NIST 800-53 R5 / CSF 2.0 / 800-171 / 800-207 / 800-161 / SSDF 800-218 | 234 | Control families (AC/AU/CM/IA/IR/SC/SI/CP/MA/MP/PE/RA/SA), CSF 2.0 functions, CUI protection, zero trust |
| **NSA** | NSA Guidance + CNSA 2.0 + K8s Hardening + Encrypted DNS + eBPF | 193 | SELinux/MAC, kernel hardening, network security, cryptographic standards, FIPS, CSfC |
| **STIG** | DISA STIGs (V-numbers) + SRG-APP families | 205 | CAT I/II/III findings, V-number mapping, RHEL/Ubuntu OS STIG, GPOS SRG, application SRGs |
| **ACSC** | ACSC Essential Eight (ML1-ML3) + ISM | 69 | E8.1-E8.8 (app control, patching, MFA, backups, admin restriction), ISM server/network/crypto/logging controls |
| **CMMC** | CMMC 2.0 + NIST 800-171/800-172 + DFARS | 94 | L1/L2/L3 practices, 14 NIST 800-171 control families, L3 800-172 enhancements, DFARS 7012/7019/7020 SPRS |
| **DistBaseline** | Per-distribution hardening | 90 | Ubuntu USG, RHEL/SUSE/Arch baselines, kernel features, systemd unit hardening, mount options, crypto policies, IMA/EVM, module signing |
| **EDR** | Linux EDR + MITRE ATT&CK + Sigma/YARA | 87 | Persistence (T1543/T1547/T1053/T1546), process injection (T1055/T1574), anti-forensics (T1070/T1562), memory protection, eBPF/LSM, IR readiness |
| **GDPR** | GDPR Art 32 technical measures + breach notification | 75 | Art.5 minimization, Art.17 erasure, Art.25 by-design, Art.30 ROPA, Art.32 security, Art.33 breach, Art.44 transfers |
| **HIPAA** | HIPAA Security Rule + 405(d) HICP | 114 | 164.308 administrative, 164.310 physical, 164.312 technical safeguards, 164.316 documentation, Subpart D breach notification |
| **PCI-DSS** | PCI DSS v4.0.1 (Requirements 1-12) | 110 | Network controls, secure configuration, data-at-rest/transit encryption, malware, secure development, access control, MFA, logging, testing, policy |
| **SOC2** | AICPA SOC 2 Trust Services Criteria | 98 | Common Criteria CC1-CC9, Availability (A1), Confidentiality (C1), Processing Integrity (PI1), Privacy (P) |

**Total Coverage**: 2,297 security checks across 16 frameworks with severity classification, MITRE ATT&CK mappings, and cross-framework correlation. Coverage spans access control, authentication, auditing/logging, network security, data protection, malware defense, system hardening, kernel security, mandatory access control, cryptographic standards, container runtime security, persistence/injection detection, and compliance scoring.

## Quick Start

### Prerequisites

* **Operating System**: Any supported Linux distribution (see table above)
* **Python**: Version 3.7 or later (for dataclasses support)
* **Privileges**: Root/sudo required for complete results
* **Privileges for Remediation**: Root/sudo **mandatory** for applying fixes

### Installation

1. **Clone the repository:**

```bash
git clone https://github.com/Sandler73/Linux-Security-Audit-Project.git
cd Linux-Security-Audit-Project
```

2. **Verify prerequisites:**

```bash
# Check Python version (must be 3.7+)
python3 --version

# Verify directory structure
ls modules/ shared_components/

# Check available modules
python3 linux_security_audit.py --list-modules
```

3. **Alternative - download release:**

```bash
# Download latest release
wget https://github.com/Sandler73/Linux-Security-Audit-Project/releases/latest/download/Linux-Security-Audit.zip
unzip Linux-Security-Audit.zip
cd Linux-Security-Audit-Project
```

### Basic Usage

**Run full audit with default HTML report:**

```bash
sudo python3 linux_security_audit.py
```

**Run specific frameworks:**

```bash
sudo python3 linux_security_audit.py -m Core,NIST,STIG
```

**Run with parallel execution and profiling:**

```bash
sudo python3 linux_security_audit.py --parallel --workers 4 --perf-profile
```

**Generate CSV output:**

```bash
sudo python3 linux_security_audit.py -f CSV
```

**Run a single module standalone (no orchestrator needed):**

```bash
sudo python3 modules/module_core.py
```

## Remediation Capabilities

### Remediation Modes

#### 1. **Interactive Remediation** (Safest)

Review and approve each fix individually:

```bash
sudo python3 linux_security_audit.py --remediate
```

* Prompts for each remediation
* Full visibility into changes
* Skip option (Y/N/S)
* Recommended for production systems

#### 2. **Status-Based Remediation**

Target specific severity levels:

```bash
# Fix only critical failures
sudo python3 linux_security_audit.py --remediate-fail

# Fix warnings interactively
sudo python3 linux_security_audit.py --remediate-warning

# Address informational items
sudo python3 linux_security_audit.py --remediate-info
```

#### 3. **Automated Remediation** (Advanced)

Batch remediation with safety confirmations:

```bash
sudo python3 linux_security_audit.py --remediate-fail --auto-remediate
```

**Safety Features:**
* Displays all changes before execution
* Requires typing "YES" to confirm
* Secondary confirmation with countdown
* Remediation logging

#### 4. **Targeted Remediation** (Precision)

Fix only specific issues selected from HTML report:

```bash
# Step 1: Run audit and review findings
sudo python3 linux_security_audit.py

# Step 2: In HTML report, select specific issues and export as JSON

# Step 3: Run targeted remediation
sudo python3 linux_security_audit.py --auto-remediate --remediation-file "Selected-Report.json"
```

## Command-Line Parameters

```
python3 linux_security_audit.py
    [-m, --modules <String>]           # Frameworks to run (default: All)
    [-f, --output-format <String>]     # Output: HTML, CSV, JSON, XML, Console
    [-o, --output-path <String>]       # Custom output path
    [--list-modules]                   # List available modules and exit
    [--parallel]                       # Execute modules in parallel
    [--workers <N>]                    # Number of parallel workers
    [--no-cache]                       # Disable shared data caching
    [--perf-profile]                   # Display performance statistics (renamed in v3.7)
    [--profile NAME]                   # NEW v3.7: per-distribution audit profile (rhel9, ubuntu24, ...)
    [--list-profiles]                  # NEW v3.7: list available distribution profiles
    [--log-level <LEVEL>]              # DEBUG/INFO/WARNING/ERROR/CRITICAL
    [--log-file <PATH>]                # Custom log file path
    [--json-log]                       # JSON-structured log output
    [-v, --verbose]                    # Verbose console output
    [-q, --quiet]                      # Suppress non-essential output
    [--remediate]                      # Interactive remediation (all statuses)
    [--remediate-fail]                 # Remediate FAIL status only
    [--remediate-warning]              # Remediate WARNING status only
    [--remediate-info]                 # Remediate INFO status only
    [--auto-remediate]                 # Automated with confirmations
    [--remediation-file <PATH>]        # JSON file with selected issues
```

### Parameter Examples

**Framework Selection:**

```bash
# Run all frameworks (default)
sudo python3 linux_security_audit.py

# Run specific frameworks
sudo python3 linux_security_audit.py -m Core,NIST,CISA

# Run single framework with profiling
sudo python3 linux_security_audit.py -m STIG --perf-profile
```

**Output Control:**

```bash
# HTML report (default) with verbose logging
sudo python3 linux_security_audit.py --verbose --log-level DEBUG

# JSON for automation
sudo python3 linux_security_audit.py -f JSON -o "/opt/audits/report.json"

# XML for SIEM integration
sudo python3 linux_security_audit.py -f XML -o "/var/log/audit-report.xml"

# Console output only with quiet mode
sudo python3 linux_security_audit.py -f Console --quiet
```

## Use Cases

### 1. Compliance Auditing

**Scenario**: Annual NIST, STIG, or CIS compliance audit

```bash
# Generate the compliance report
sudo python3 linux_security_audit.py -m NIST,STIG,CIS -f HTML --perf-profile
```

### 2. System Hardening

**Scenario**: Harden new Linux servers before production deployment

```bash
# Step 1: Baseline audit
sudo python3 linux_security_audit.py -m Core,CIS

# Step 2: Review and auto-fix critical issues
sudo python3 linux_security_audit.py --remediate-fail --auto-remediate

# Step 3: Verify remediation
sudo python3 linux_security_audit.py -m Core,CIS
```

### 3. Configuration Drift Detection

**Scenario**: Monthly security posture checks

```bash
# Generate baseline
sudo python3 linux_security_audit.py -f JSON -o "baseline-$(date +%Y%m).json"

# Compare JSON files programmatically
diff <(jq '.Results[] | .Status' baseline-202603.json | sort) \
     <(jq '.Results[] | .Status' baseline-202604.json | sort)
```

### 4. Incident Response

**Scenario**: Validate system security after suspected compromise

```bash
# Quick core security validation
sudo python3 linux_security_audit.py -m Core -f JSON --verbose

# Full validation
sudo python3 linux_security_audit.py --parallel --perf-profile
```

### 5. SIEM Integration

**Scenario**: Automated compliance monitoring pipeline

```bash
# Cron job to generate XML for SIEM
0 2 * * 0 sudo python3 /opt/audit/linux_security_audit.py -f XML \
  -o "/var/log/siem/audit-$(hostname)-$(date +\%Y\%m\%d).xml" --quiet
```

### 6. EU/GDPR Compliance

**Scenario**: European regulatory requirements

```bash
# ENISA + ISO 27001 for EU compliance evidence
sudo python3 linux_security_audit.py -m ENISA,ISO27001 -f HTML
```

## Documentation

Documentation is available in the [Project Wiki](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki):

### Getting Started

* **[Quick Start Guide](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki/Quick-Start-Guide)** - Get up and running in 5 minutes
* **[Usage Guide](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki/Usage-Guide)** - Detailed command-line options and workflows

### Reference Documentation

* **[Framework Reference](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki/Framework-Reference)** - Detailed framework mappings and control IDs
* **[Module Documentation](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki/Module-Documentation)** - Individual module specifications
* **[Output Reference](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki/Output-Reference)** - Report format specifications
* **[Examples](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki/Examples)** - Real-world console output and HTML report previews

### Advanced Topics

* **[Development Guide](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki/Development-Guide)** - Contributing and extending modules
* **[Troubleshooting Guide](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki/Troubleshooting-Guide)** - Common issues and solutions
* **[FAQ](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki/Frequently-Asked-Questions-(FAQ))** - Frequently asked questions

## What Gets Audited?

### Security Domains

| Domain | Checks | Examples |
|--------|--------|---------|
| **Access Control** | 150+ | User/group management, sudo configuration, PAM, file permissions, umask |
| **Authentication** | 120+ | Password policies (length, history, aging), SSH key auth, PAM modules, account lockout |
| **Audit & Logging** | 100+ | auditd rules (25+ event types), syslog, log rotation, log permissions, remote logging |
| **System Hardening** | 200+ | sysctl parameters, GRUB security, core dumps, ASLR, ptrace, SysRq, mount options |
| **Network Security** | 130+ | Firewall (iptables/nftables), IP forwarding, ICMP, source routing, TCP SYN cookies, IPv6 |
| **Data Protection** | 80+ | Encryption at rest, TLS configuration, cipher suites, crypto policies, FIPS mode |
| **Malware Defense** | 40+ | ClamAV, file integrity (AIDE/OSSEC/Tripwire), rootkit detection |
| **Service Hardening** | 80+ | SSH daemon, NTP/chrony, unnecessary services, systemd security directives |
| **Kernel Security** | 60+ | Module loading, unprivileged BPF/userns, Yama LSM, kptr_restrict, dmesg restrict |
| **MAC/SELinux** | 50+ | SELinux mode/policy/booleans (Red Hat), AppArmor profiles/enforcement (Debian) |

## Project Structure

```
Linux-Security-Audit-Project/
+-- linux_security_audit.py           # Main orchestrator (3,486 lines)
|   +-- Dynamic module discovery and validation
|   +-- Shared data cache initialization
|   +-- Parallel/sequential module execution
|   +-- Compliance scoring (3 methods)
|   +-- IP address detection
|   +-- Multi-format report generation
|   `-- Intelligent remediation system
|
+-- modules/                          # Security framework modules
|   +-- module_core.py                # Core baseline (153 checks)
|   +-- module_cis.py                 # CIS Benchmarks (212 checks)
|   +-- module_cisa.py                # CISA guidance (147 checks)
|   +-- module_enisa.py               # ENISA guidelines (97 checks)
|   +-- module_iso27001.py            # ISO 27001 controls (115 checks)
|   +-- module_nist.py                # NIST frameworks (172 checks)
|   +-- module_nsa.py                 # NSA hardening (144 checks)
|   `-- module_stig.py                # DISA STIGs (167 checks)
|
+-- shared_components/                # Shared library
|   `-- audit_common.py              # Caching, parallel, /proc reads (2,195 lines)
|
+-- logs/                             # Structured log files (auto-created)
+-- reports/                          # Generated reports (auto-created)
|
+-- README.md                         # This file
+-- LICENSE.md                        # MIT License + supplementary terms
+-- CHANGELOG.md                      # Version history
+-- SECURITY.md                       # Security policy
+-- CONTRIBUTING.md                   # Contribution guidelines
`-- .gitignore                        # Git ignore rules
```

## [!] Important Considerations

### Administrative Privileges

**Audit Mode:**
* Many checks require root/sudo privileges
* Non-root execution shows warnings but continues with available checks
* Some checks will return "Unable to verify" without elevation

**Remediation Mode:**
* Root/sudo privileges **MANDATORY**
* Script validates privileges before remediation
* Exits gracefully if running without elevation

### Performance & Impact

**Execution Time:**
* Full audit (sequential, all 16 modules): 90-180 seconds
* Full audit (parallel, 4 workers): 30-60 seconds
* Single module: 5-15 seconds
* Factors: System speed, number of services, module selection

**System Impact:**
* **Read-only operations** during audit (no changes)
* Minimal CPU/memory usage
* No network traffic (fully offline)
* Safe to run on production systems

### Security & Privacy

[x] **What the script does:**
* Reads system configuration files and /proc filesystem
* Queries systemd, sysctl, auditd, PAM, SSH configurations
* Checks file/directory permissions
* Generates local reports in `reports/` with 600 permissions

[ ] **What the script does NOT do:**
* Transmit data externally
* Install software or packages
* Create network connections
* Access user personal data or files
* Modify system during audit (only with remediation flags)

### Limitations

* **Local assessment only** - does not audit remote systems
* **Point-in-time** - results represent configuration at execution time
* **Platform-specific** - Linux distributions only (see OS table)
* **No active scanning** - does not test for exploitable vulnerabilities
* **No container-internal auditing** - audits the host, not container guests

### Disclaimer

This tool is provided for **security assessment and compliance auditing purposes**. Results should be reviewed by qualified security professionals and validated in the context of your environment. The tool identifies potential security issues but does not guarantee complete security coverage. Always test in non-production environments before applying remediations to production systems.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](https://github.com/Sandler73/Linux-Security-Audit-Project/blob/main/CONTRIBUTING.md) for details.

### Ways to Contribute

***Report bugs** - Found an issue? Open a GitHub issue
***Suggest features** - Have an idea? Start a discussion
***Improve documentation** - Enhance wiki pages and examples
***Submit bug fixes** - Fix issues and submit PRs
***Add checks** - Contribute new security checks or modules
* **Test** - Validate on different Linux distributions
***Translate** - Help with internationalization

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/NewSecurityCheck`)
3. Follow coding standards (see [Development Guide](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki/Development-Guide))
4. Test on multiple distributions
5. Update documentation
6. Commit changes (`git commit -m 'Add: New SSH key rotation check'`)
7. Push to branch (`git push origin feature/NewSecurityCheck`)
8. Open a Pull Request with detailed description

## License

This project is licensed under the **MIT License** - see [LICENSE.md](https://github.com/Sandler73/Linux-Security-Audit-Project/blob/main/LICENSE.md) for details (429 lines including 10 supplementary sections covering warranty disclaimer, limitation of liability, indemnification, user responsibility, authorized use, zero dependencies, and more).

### What This Means

[x] **You can:** Use commercially - Modify and distribute - Use privately - Sublicense

[ ] **You cannot:** Hold authors liable - Use trademarks

 **You must:** Include license and copyright notice - State changes made

## Acknowledgments

### Security Frameworks

* **[DISA](https://public.cyber.mil/stigs/)** - Defense Information Systems Agency STIGs
* **[NIST](https://csrc.nist.gov/)** - National Institute of Standards and Technology
* **[CIS](https://www.cisecurity.org/)** - Center for Internet Security Benchmarks
* **[NSA](https://www.nsa.gov/Cybersecurity/)** - National Security Agency Cybersecurity Guidance
* **[CISA](https://www.cisa.gov/cybersecurity)** - Cybersecurity and Infrastructure Security Agency
* **[ENISA](https://www.enisa.europa.eu/)** - European Union Agency for Cybersecurity
* **[ISO](https://www.iso.org/)** - International Organization for Standardization

## Support & Resources

### Get Help

* ** Documentation** - [Project Wiki](https://github.com/Sandler73/Linux-Security-Audit-Project/wiki)
* ** Questions** - [GitHub Discussions](https://github.com/Sandler73/Linux-Security-Audit-Project/discussions)
* ** Bug Reports** - [GitHub Issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)

### Security Issues

* Review [SECURITY.md](https://github.com/Sandler73/Linux-Security-Audit-Project/blob/main/SECURITY.md) for vulnerability reporting
* Report security issues privately via GitHub Security Advisories
* Expected response time: 48-72 hours

## Project Statistics

| Metric | Value |
|--------|-------|
| **Current Version** | 3.9 (Remediation Consistency + PCI-DSS + Scoring Fix) |
| **Total Security Checks** | 2,297 (runtime-verified: 16 modules, 0 errors, 0 aborts) |
| **Frameworks Covered** | 16 |
| **Code Base** | ~45,000+ lines of Python (16 modules + orchestrator + shared lib + foundation library) |
| **Modules** | 16 specialized compliance modules |
| **Foundation Library** | production modules including correlation registry, OS detection (30+ distros), risk scoring, baseline diff, remediation bundles, rollback generator, pipeline, module helpers, shared assessments, and the canonical remediation registry |
| **Output Formats** | 5 native (HTML, JSON, CSV, XML, Console) + companion JSON |
| **Scoring Methods** | 3 (simple, weighted, severity-adjusted) |
| **MITRE ATT&CK Mappings** | EDR module covers T1037, T1053, T1055, T1070, T1071, T1098, T1543, T1546, T1547, T1562, T1571, T1574, T1610 |
| **Distribution Profiles** | 18 built-in (`--profile`): generic, alpine, debian12, ubuntu22, ubuntu24, rhel8, rhel9, suse15, kali, mxlinux, mint, zorin, elementary, almalinux, rocky, centos, centosstream, fedora |
| **Regression Tests** | 46 tests across 6 files |
| **Python Version** | 3.7+ (zero external dependencies) |
| **Active Development** | [x] Yes |

## Version History

### Version 3.9 (Current) - June 2026 - Remediation Consistency + PCI-DSS + Scoring Fix

* Cross-framework remediation consistency: new canonical remediation registry (`shared_components/canonical_remediations.py`) unifies the guidance for the same underlying fix across all 16 frameworks while preserving each framework's control IDs and intent; 37 topics indexed (27 value-independent, force-normalized), documented in `docs/Remediation-Cross-Map.md`
* Fixed a latent compliance-scoring bug: module discovery now reads each module's declared `MODULE_NAME`, so all 16 modules score correctly (9 previously reported a vacuous 100% on 0 matched checks)
* PCI module renamed to **PCI-DSS** (report name, banners, `--list-modules`); `--modules PCIDSS`, `PCI`, and `pci-dss` all select it
* Split-report compliance scoring fixed (was 0.0% / Threshold N/A)
* Canonical shared assessments (`shared_components/shared_assessments.py`) for world-writable files, SUID/SGID, unowned files, and firewall posture - identical count, actual offending items, status, and remediation across every framework
* Attack-surface report rebuilt to full feature parity (dark/light theme, collapsible sections, per-column filters, global search, sortable/resizable columns, CSV/JSON/XML export) with deeper firewall (installed vs active vs configured), executable-PATH, and shared-object/linker checks
* Distribution profiles expanded 8 -> 18
* Fixed status/severity confusions and an OSInfo variant divergence; orchestrator now runs with 0 errors
* All non-ASCII characters removed from source and documentation for cross-platform portability
* Regression suite expanded to 46 tests across 6 files

### Version 3.8 - June 2026 - Attack Surface + Split Reports

*Attack Surface Assessment report (`--attack-surface`): 10 exposure domains, severity-weighted scoring, HTML + JSON
*Per-framework split reports (`--split-reports` / `--split-only`)
*New CORE attack-surface enumeration checks (`CORE - Attack Surface`)
*Regression test suite (28 tests across 4 files)

### Version 3.7.1 - June 2026 - Remediation Consistency + OSInfo Fixes

*Fixed two divergent OSInfo classes causing silent audit truncation (ISO27001 ran 9/147, ENISA 0) - all 16 modules now run end-to-end with 0 aborts
*OS-aware package-removal (`removal_for`) and security-patch (`patch_for`) helpers with per-distro package-name resolution
*Migrated inline remediations to the OS-aware library (135 -> 320 centralized calls)

### Version 3.7 - May 2026 - Correlation, Profiles, Rollup Metrics

*Cross-module correlation: `HostFacts` registry (~80 derived facts)
*Per-distribution profiles (`--profile rhel9`, etc.; 18 built-in, strict input validation)
*HTML Module Summary tiles + Top Priority Findings
*Renamed perf-timing `--profile` to `--perf-profile`

### Version 3.6 - May 2026 - Performance

*Helper caching layer (5-30x speedup on multi-module runs)

### Version 3.5 - April 2026 - Deeper Expansion & Hardening

*All 16 modules expanded to v3.5 finals (2,297 checks total)
*Quality and correctness hardening across all modules

### Version 3.3 - April 2026 - Phase 2 Expansion

*+171 checks across 8 new modules (Phase 2 expansion v3.3)
*Deep MITRE ATT&CK coverage in EDR module (13 technique IDs)
*Container runtime security checks (Docker/Podman/K8s + Falco/Tetragon)
*Anti-forensics detection (auditd immutable mode, history monitoring)
*Memory protection checks (NX/SMEP/SMAP/ASLR/KASLR/KPTI)
*Crypto policy depth (update-crypto-policies, FIPS provider, TLS minimums)
*Boot security depth (GRUB password, initramfs, kdump, UEFI)
*PAM stack analysis (faillock, pwhistory, pwquality, MFA modules)
*Fixed PCI helper-naming compatibility, SOC2/GDPR missing return statements

### Version 3.0 - April 2026 - 16-module Multi-Framework Coverage

*8 new framework modules: PCI DSS, ACSC, CMMC, GDPR, HIPAA, SOC2, DistBaseline, EDR
*Foundation library: correlation registry (158 topics), risk scoring, baseline diff, remediation bundles, rollback generator
*30+ Linux distribution detection
*Cross-framework correlation across all 16 modules
*Phase 3 baselines totaling the v3.x baseline (~1,358); v3.x expansion reaches 1,762

### Version 2.0 - March 2026 - Architecture & Reporting Rewrite

*Shared components library with intelligent caching (~50% hit rate)
*Parallel module execution (`--parallel`, `--workers`)
*Complete HTML report rewrite (18+ interactive features)
*Compliance scoring (simple, weighted, severity-adjusted)
*Structured logging with JSON output
*IP address identification for host attribution
*OS-aware checks across 4 distribution families
*Project restructure: `modules/` + `shared_components/` + `logs/` + `reports/`
*Python 3.6 -> 3.7 (dataclasses)

### Version 1.1 - January 2025

*8 compliance framework modules
*Interactive HTML reports with dark/light themes
*Multi-format output (HTML, CSV, JSON, XML, Console)
*Intelligent remediation with safety mechanisms

See [CHANGELOG.md](https://github.com/Sandler73/Linux-Security-Audit-Project/blob/main/CHANGELOG.md) for complete version history.

---

*** If this project helps you secure Linux systems, please consider giving it a star! ***

**[ Back to Top](#linux-security-audit-project)**

Made with  for the cybersecurity community
