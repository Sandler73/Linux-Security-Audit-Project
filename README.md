# Linux Security Audit and Remediation Script

# Linux Security Audit Script v3.1

## Multi-Framework Edition

[![Version](https://img.shields.io/badge/version-3.1.0-blue.svg)]()
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)]()
[![License](https://img.shields.io/badge/license-MIT-orange.svg)]()
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)]()

**The definitive comprehensive Linux security audit and hardening tool with multi-framework compliance support.**

Audit a Linux system against **CIS Benchmark, NIST 800-53, DISA STIG, NSA Hardening Guide, and CISA Cybersecurity Best Practices** with a single command. Includes automated remediation for 95%+ of findings.

---

## 🎯 Overview

`linux_security_audit.py` is an attempt at a comprehensive security auditing tool that evaluates the Linux system against multiple compliance frameworks simultaneously. Whether the intent is hardening a new server, maintaining compliance for government contracts, or conducting routine security assessments, this tool provides:

- **136+ security checks** across 20+ categories
- **Multi-framework compliance mapping** (every check mapped to applicable standards)
- **95%+ automated remediation** with interactive fix application
- **Framework-specific filtering** to target exactly what you need
- **Professionalized reports** in Text, HTML, JSON, and CSV formats
- **Per-framework compliance scoring** to track your progress

**Potentially useful for:**
- 🏛️ Government contractors (DISA STIG compliance)
- 🏢 Federal agencies (NIST 800-53 compliance)
- 🏥 Healthcare (HIPAA technical safeguards)
- 💳 Financial services (PCI DSS requirements)
- 🔒 Critical infrastructure (CISA best practices)
- 🖥️ General Linux hardening (CIS Benchmark)

---

## ✨ Key Features

### 🔍 Comprehensive Security Checks (136+)
- **File Permissions** - System files, SSH configs, bootloader
- **User Account Security** - Empty passwords, UID 0 accounts, password policies
- **SSH Hardening** - 15+ SSH configuration checks (CAT I critical findings)
- **Firewall** - UFW status, default policies, automated configuration
- **Kernel Parameters** - Network security, ASLR, SYN cookies
- **Filesystem Security** - Mount options, sticky bits, partitioning
- **Logging & Auditing** - auditd, rsyslog, log permissions
- **System Hardening** - AppArmor/SELinux, core dumps, AIDE
- **Network Security** - TCP wrappers, hosts.allow/deny
- **Password Complexity** - PAM configuration, lockout policies
- **Time Synchronization** - chrony/NTP/timesyncd
- **And much more...**

### 🎯 Multi-Framework Compliance

Every check is mapped to applicable frameworks:

```
[CIS 5.2.7 | NIST AC-6,IA-2 | STIG RHEL-07-040370 | NSA ✓ | CISA ✓]
SSH PermitRootLogin
Category: CAT I | Status: FAIL | Severity: Critical
```

**Supported Frameworks:**
- **CIS Benchmark** - Center for Internet Security (Levels 1 & 2)
- **NIST 800-53** - National Institute of Standards & Technology
- **DISA STIG** - Defense Information Systems Agency Security Technical Implementation Guide
- **NSA Hardening Guide** - National Security Agency
- **CISA Best Practices** - Cybersecurity & Infrastructure Security Agency

### 🛠️ Automated Remediation (95%+)

```bash
# Interactive remediation with y/n/q prompts
sudo ./linux_security_audit.py --remediate

# Fix only critical STIG CAT I issues
sudo ./linux_security_audit.py --cat "CAT I" --remediate
```

### 📊 Framework-Specific Filtering

```bash
# NIST 800-53 controls only
sudo ./linux_security_audit.py --framework nist

# STIG Category I (Critical) only
sudo ./linux_security_audit.py --cat "CAT I"

# CIS Level 1 (essential) only
sudo ./linux_security_audit.py --level 1
```

### 📈 Compliance Scoring

```
FRAMEWORK COMPLIANCE SUMMARY
--------------------------------------------------------------------------------
CIS   :  85/97 checks passed (87.6%)
NIST  :  78/85 checks passed (91.8%)
STIG  :  82/97 checks passed (84.5%)
NSA   :  86/92 checks passed (93.5%)
CISA  :  61/68 checks passed (89.7%)
```

---

## 💻 Requirements

- **OS:** Ubuntu 24.04/22.04/20.04 LTS, Debian 11+, RHEL/CentOS compatible
- **Python:** 3.8 or higher
- **Privileges:** Root//SUDO required for complete audit and remediation
- **Dependencies:** Standard library only (no external packages)

---

## 📥 Installation

```bash
# Download the script
wget https://your-repo/linux_security_audit.py

# Make executable
chmod +x linux_security_audit.py

# Run
sudo ./linux_security_audit.py --help
```

---

## 🚀 Quick Start

### Basic Audit
```bash
# Run comprehensive audit
sudo ./linux_security_audit.py

# Auto-save results
sudo ./linux_security_audit.py --auto-save

# CSV export
sudo ./linux_security_audit.py -f csv -o audit.csv
```

### Fix Critical Issues
```bash
# Interactive remediation
sudo ./linux_security_audit.py --remediate

# Fix STIG CAT I (Critical) only
sudo ./linux_security_audit.py --cat "CAT I" --remediate
```

### Framework-Specific
```bash
# NIST 800-53 compliance
sudo ./linux_security_audit.py --framework nist

# DISA STIG compliance
sudo ./linux_security_audit.py --framework stig

# CIS Benchmark Level 1
sudo ./linux_security_audit.py --level 1
```

---

## 📋 Command-Line Options

```
usage: linux_security_audit.py [-h] [-f {text,html,json,csv}]
                                             [-o OUTPUT] [--auto-save]
                                             [--no-console]
                                             [--framework {cis,nist,stig,nsa,cisa}]
                                             [--level {1,2}]
                                             [--cat {CAT I,CAT II,CAT III}]
                                             [--scored-only] [--remediate]
                                             [--remediate-info]
                                             [--remediate-all]

Output Options:
  -f {text,html,json,csv}  Output format (default: text)
  -o OUTPUT                Output file path
  --auto-save              Auto-save report with timestamp
  --no-console             Suppress console output

Framework Filtering:
  --framework {cis,nist,stig,nsa,cisa}
                          Filter by compliance framework
  --level {1,2}           CIS Level (1=essential, 2=comprehensive)
  --cat {CAT I,CAT II,CAT III}
                          STIG Category (CAT I=Critical)
  --scored-only           Only run scored CIS checks

Remediation:
  --remediate             Fix FAIL items interactively
  --remediate-info        Fix INFO items interactively
  --remediate-all         Fix FAIL + INFO items
```

---

## 📄 Output Formats

### Text (Default)
- Human-readable console output
- Framework compliance summary
- Detailed check results with recommendations

### CSV
- Spreadsheet import
- All framework IDs in separate columns
- Perfect for compliance tracking

### JSON
- Programmatic integration
- Structured data format
- Framework compliance metrics

### HTML
- Web-viewable reports
- Professional formatting
- Color-coded results

---

## 🔧 Remediation

Interactive remediation process:

1. **Analysis** - Identifies failed checks with automated fixes
2. **Grouping** - Organizes by severity (CAT I → CAT II → CAT III)
3. **Presentation** - Shows framework IDs, current state, commands
4. **User Decision** - Prompts: `y` (apply), `n` (skip), `q` (quit)
5. **Execution** - Runs commands and reports results

**Example:**
```
1. [CIS 5.2.7 | NIST AC-6,IA-2 | STIG RHEL-07-040370 | NSA ✓ | CISA ✓]
   SSH PermitRootLogin
   Category: CAT I | Severity: Critical
   Current: yes | Expected: no
   Fix commands:
      sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
      systemctl reload sshd

   Apply fix? (y/n/q): y
   ✓ Done
```

**Safety Features:**
- ✅ Confirmation required
- ✅ Command preview
- ✅ Quit anytime
- ✅ Root check
- ✅ Backup recommendations

---

## 📚 Use Case Examples

### Initial Server Hardening
```bash
sudo ./linux_security_audit.py --auto-save
sudo ./linux_security_audit.py --cat "CAT I" --remediate
sudo ./linux_security_audit.py --level 1 --remediate
sudo ./linux_security_audit.py --auto-save
```

### DISA STIG Compliance
```bash
sudo ./linux_security_audit.py --framework stig -f csv -o stig_baseline.csv
sudo ./linux_security_audit.py --cat "CAT I" --remediate
sudo ./linux_security_audit.py --cat "CAT II" --remediate
sudo ./linux_security_audit.py --framework stig -f csv -o stig_final.csv
```

### NIST 800-53 Compliance
```bash
sudo ./linux_security_audit.py --framework nist --remediate
sudo ./linux_security_audit.py --framework nist -f json -o nist_ato.json
```

### Monthly Security Audits
```bash
#!/bin/bash
DATE=$(date +%Y%m%d)
sudo ./linux_security_audit.py \
    -f csv \
    -o /var/log/security/audit_$DATE.csv \
    --no-console
```

---

## 🔍 Security Checks Overview

- **File Permissions** (8 checks)
- **User Account Security** (7 checks)
- **SSH Configuration** (15 checks) - CAT I critical
- **Firewall** (3 checks) - CAT I critical
- **Kernel Parameters** (9 checks)
- **Filesystem** (7 checks)
- **Logging & Auditing** (5 checks)
- **System Hardening** (6 checks)
- **Network Security** (3 checks)
- **Cron & Access** (2 checks)
- **Bootloader** (2 checks)
- **System Updates** (2 checks)
- **Sudo Configuration** (2 checks)
- **Banners** (2 checks)
- **File Auditing** (5 checks)
- **Home Directory Security** (5 checks)
- **Password Complexity** (5 checks)
- **Account Lockout** (2 checks)
- **Time Synchronization** (2 checks)
- **Additional Checks** (10+ checks)

**Total: 136+ comprehensive security checks**

---

## 🔧 Troubleshooting

### Permission Denied
```bash
sudo ./linux_security_audit.py
```

### Python Version Too Old
```bash
python3 --version  # Must be 3.8+
```

### Script Won't Execute
```bash
chmod +x linux_security_auditE.py
```

### Remediation Fails
```bash
sudo apt-get install -y ufw auditd aide
```

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test thoroughly
4. Document changes
5. Submit pull request

---

## 📜 License

MIT License - See LICENSE file for details

---

## 🙏 Acknowledgments

- **CIS** - CIS Benchmarks
- **NIST** - NIST 800-53
- **DISA** - Security Technical Implementation Guides
- **NSA** - System Hardening Guides
- **CISA** - Cybersecurity Best Practices
- Security professionals and auditors worldwide

---

## 📊 Statistics

- **Lines of Code:** 2,290
- **Security Checks:** 136+
- **Framework Mappings:** 97
- **Check Categories:** 20+
- **Automated Fixes:** 95%+
- **Supported Frameworks:** 5
- **Output Formats:** 4

---

## ⚠️ Disclaimer

This tool is provided "as is" without warranty. Always test in non-production environments first, create backups before applying fixes, and have security professionals review your configuration.

**Use at your own risk.**

---

**Last Updated:** December 21, 2025  
**Version:** 3.1.0-COMPLETE  
**License:** MIT

---

<div align="center">

**⭐ Star this repository if it helped you! ⭐**

[Report Bug](https://github.com/Sandler73/Linux-Security-Audit-and-Remediation-Script/issues) · [Request Feature](https://github.com/Sandler73/Linux-Security-Audit-and-Remediation-Script/issues)

</div>
