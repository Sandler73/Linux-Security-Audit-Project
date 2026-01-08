# Linux Security Audit Project

[![Version](https://img.shields.io/badge/version-1.1-blue.svg)](https://github.com/Sandler73/Linux-Security-Audit-Project)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.kernel.org/)

A comprehensive, modular security audit framework for Linux systems supporting multiple compliance frameworks with automated remediation capabilities.

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Sandler73/Linux-Security-Audit-Project.git
cd Linux-Security-Audit-Project

# Run a complete security audit (requires sudo)
sudo python3 linux_security_audit.py

# View the interactive HTML report
# Opens automatically in your default browser
```

**That's it!** The tool will audit your system against all 8 security frameworks and generate a comprehensive report.

## 📋 Table of Contents

- [Features](#-features)
- [Security Frameworks](#-security-frameworks)
- [System Requirements](#-system-requirements)
- [Installation](#-installation)
- [Basic Usage](#-basic-usage)
- [Documentation](#-documentation)
- [Output Formats](#-output-formats)
- [Remediation](#-remediation)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [License](#-license)
- [Support](#-support)

## ✨ Features

### Core Capabilities

- **🔍 Comprehensive Security Assessment**: 1000+ individual security checks across 8 frameworks
- **📊 Multiple Framework Support**: CIS, NIST, STIG, NSA, CISA, ENISA, ISO27001, and Core baseline
- **🎨 Interactive HTML Reports**: Rich, filterable reports with dark/light themes
- **🔧 Automated Remediation**: Fix security issues with single commands or selective batch operations
- **📁 Multi-Format Output**: HTML, CSV, JSON, XML, and Console formats
- **🔐 Privilege-Aware**: Works with or without root (graceful degradation)
- **🎯 Selective Remediation**: Export specific issues from HTML and fix only those
- **📈 Trend Analysis**: Track security posture over time with JSON/CSV exports

### Advanced Features

- **Dynamic Module Discovery**: Automatically detects and validates security modules
- **OS-Aware Checks**: Distribution-specific optimizations (Debian, Ubuntu, RHEL, CentOS, Fedora, etc.)
- **Smart Privilege Detection**: Identifies what can/can't be checked without root
- **Comprehensive Error Handling**: Graceful failures with detailed error reporting
- **Zero Dependencies**: Uses only Python standard library (no pip install needed)
- **Completely Offline**: No internet connection required, no data transmitted

## 🛡️ Security Frameworks

The project includes 8 specialized security modules:

| Module | Checks | Description | Best For |
|--------|--------|-------------|----------|
| **[Core](../../wiki/Module-Documentation#core-module)** | 150+ | Industry best practices, OS-specific security | Everyone |
| **[CIS](../../wiki/Module-Documentation#cis-module)** | 200+ | CIS Benchmarks compliance | General hardening, compliance |
| **[CISA](../../wiki/Module-Documentation#cisa-module)** | 140+ | Critical infrastructure protection | Government, critical sectors |
| **[ENISA](../../wiki/Module-Documentation#enisa-module)** | 135+ | EU cybersecurity guidelines | European organizations |
| **[ISO27001](../../wiki/Module-Documentation#iso27001-module)** | 145+ | Information security management | ISMS certification |
| **[NIST](../../wiki/Module-Documentation#nist-module)** | 160+ | NIST 800-53, CSF 2.0, 800-171 | Federal, contractors |
| **[NSA](../../wiki/Module-Documentation#nsa-module)** | 155+ | Advanced security hardening | High-security environments |
| **[STIG](../../wiki/Module-Documentation#stig-module)** | 180+ | DoD security requirements | Defense, contractors |

**Total**: 1,100+ comprehensive security checks

### Framework Selection Guidance

**General Organizations**: Start with `Core + CIS`  
**Financial/Healthcare**: Use `ISO27001 + NIST + CIS`  
**Government/Federal**: Use `NIST + STIG + CISA`  
**EU Organizations**: Use `ISO27001 + ENISA + CIS`  
**Defense Contractors**: Use `STIG + NIST + NSA`

📖 **[Complete Framework Reference →](../../wiki/Framework-Reference)**

## 💻 System Requirements

### Minimum Requirements

- **Operating System**: Linux (any modern distribution)
- **Python**: Version 3.6 or higher
- **Disk Space**: 100 MB free
- **Memory**: 512 MB RAM (1 GB recommended)
- **Privileges**: Root/sudo recommended for complete results

### Supported Distributions

#### Fully Tested
- Ubuntu 18.04+, 20.04 LTS, 22.04 LTS, 24.04 LTS
- Debian 9+, 10, 11, 12
- RHEL 7, 8, 9
- CentOS 7, 8 Stream
- Fedora 28+, 35+, 38+
- Rocky Linux 8, 9
- AlmaLinux 8, 9

#### Also Supported
- Linux Mint 19+
- Kali Linux 2020+
- SUSE/openSUSE Leap 15+
- Arch Linux (rolling release)

### Prerequisites

**No installation required!** All dependencies are part of Python's standard library:
- `os`, `sys`, `json`, `csv`, `argparse`, `subprocess`
- `platform`, `socket`, `datetime`, `pathlib`, `typing`
- `xml.etree.ElementTree`, `html`, `dataclasses`

## 📦 Installation

### Option 1: Git Clone (Recommended)

```bash
# Clone the repository
git clone https://github.com/Sandler73/Linux-Security-Audit-Project.git

# Navigate to directory
cd Linux-Security-Audit-Project

# Verify installation
python3 linux_security_audit.py --list-modules
```

### Option 2: Download ZIP

```bash
# Download latest release
wget https://github.com/Sandler73/Linux-Security-Audit-Project/archive/refs/heads/main.zip

# Extract
unzip main.zip
cd Linux-Security-Audit-Project-main

# Make executable
chmod +x linux_security_audit.py
```

### Option 3: Direct Download

Download individual files from the repository and place in the same directory:
- `linux_security_audit.py` (main script)
- `module_*.py` (all 8 module files)

## 🎯 Basic Usage

### Simple Commands

```bash
# List available modules
python3 linux_security_audit.py --list-modules

# Run complete audit (all modules)
sudo python3 linux_security_audit.py

# Run specific modules
sudo python3 linux_security_audit.py -m Core,CIS,NIST

# Generate CSV report
sudo python3 linux_security_audit.py -f CSV -o security-audit.csv

# Quick console output
sudo python3 linux_security_audit.py -f Console
```

### Common Use Cases

#### Security Baseline Assessment
```bash
# Establish initial security baseline
sudo python3 linux_security_audit.py -m Core,CIS -o baseline-$(date +%Y%m%d).html
```

#### Compliance Auditing
```bash
# Generate compliance report
sudo python3 linux_security_audit.py -m ISO27001,NIST,CIS -f HTML -o compliance-report.html
```

#### Automated Monitoring
```bash
# Daily automated audit (add to crontab)
0 2 * * * /usr/bin/python3 /opt/audit/linux_security_audit.py -f JSON -o /var/log/audit-$(date +\%Y\%m\%d).json
```

#### SIEM Integration
```bash
# Generate XML for SIEM ingestion
sudo python3 linux_security_audit.py -f XML -o siem-feed.xml
```

### Command-Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-m, --modules` | Specify modules to run | `-m Core,CIS,NIST` |
| `-f, --output-format` | Output format | `-f HTML` |
| `-o, --output-path` | Output file path | `-o report.html` |
| `--list-modules` | List available modules | |
| `--remediate` | Interactive remediation | |
| `--remediate-fail` | Fix only FAIL status | |
| `--auto-remediate` | Automatic remediation | |
| `--remediation-file` | Fix specific issues from JSON | |

📖 **[Complete Usage Guide →](../../wiki/Usage-Guide)**

## 📚 Documentation

### Quick Links

- **[🏠 Wiki Home](../../wiki/Home)** - Complete documentation hub
- **[⚡ Quick Start](../../wiki/Quick-Start-Guide)** - Get started in minutes
- **[📖 Usage Guide](../../wiki/Usage-Guide)** - Comprehensive usage instructions
- **[🔍 Module Documentation](../../wiki/Module-Documentation)** - Detailed module capabilities
- **[📊 Output Reference](../../wiki/Output-Reference)** - Understanding reports and formats
- **[🛡️ Framework Reference](../../wiki/Framework-Reference)** - Security standards details
- **[💻 Development Guide](../../wiki/Development-Guide)** - Contributing and extending
- **[🔧 Troubleshooting](../../wiki/Troubleshooting-Guide)** - Common issues and solutions
- **[❓ FAQ](../../wiki/Frequently-Asked-Questions-(FAQ))** - Frequently asked questions

### Documentation Highlights

#### For Users
- **Installation**: [Quick Start Guide](../../wiki/Quick-Start-Guide#installation)
- **First Run**: [Quick Start Guide](../../wiki/Quick-Start-Guide#first-run)
- **Understanding Results**: [Output Reference](../../wiki/Output-Reference#data-field-definitions)
- **Remediation**: [Usage Guide](../../wiki/Usage-Guide#remediation-options)
- **Common Issues**: [Troubleshooting Guide](../../wiki/Troubleshooting-Guide)

#### For Developers
- **Architecture**: [Development Guide](../../wiki/Development-Guide#project-architecture)
- **Creating Modules**: [Development Guide](../../wiki/Development-Guide#creating-security-modules)
- **Code Standards**: [Development Guide](../../wiki/Development-Guide#code-standards)
- **Contributing**: [Development Guide](../../wiki/Development-Guide#contributing)

#### For Compliance
- **Framework Details**: [Framework Reference](../../wiki/Framework-Reference)
- **Module Coverage**: [Module Documentation](../../wiki/Module-Documentation)
- **Compliance Mapping**: [Framework Reference](../../wiki/Framework-Reference#compliance-mapping)

## 📁 Output Formats

### HTML (Default)

Interactive, browser-based report with:
- ✅ Sortable and filterable tables
- ✅ Full-text search across all fields
- ✅ Dark/Light theme toggle
- ✅ Export selected issues to JSON
- ✅ Inline remediation commands
- ✅ Summary statistics dashboard

```bash
sudo python3 linux_security_audit.py -f HTML
```

### CSV

Spreadsheet-compatible format for:
- ✅ Excel/Google Sheets analysis
- ✅ Custom reporting and graphing
- ✅ Historical trend analysis
- ✅ Data manipulation

```bash
sudo python3 linux_security_audit.py -f CSV -o audit.csv
```

### JSON

Structured data for:
- ✅ API integration
- ✅ SIEM ingestion
- ✅ Automation workflows
- ✅ Selective remediation
- ✅ Custom scripting

```bash
sudo python3 linux_security_audit.py -f JSON -o audit.json
```

### XML

Enterprise tool integration:
- ✅ SIEM systems (Splunk, QRadar)
- ✅ GRC platforms
- ✅ Configuration management
- ✅ Legacy system compatibility

```bash
sudo python3 linux_security_audit.py -f XML -o audit.xml
```

### Console

Real-time terminal output:
- ✅ Color-coded status
- ✅ No file creation
- ✅ SSH-friendly
- ✅ Quick validation

```bash
sudo python3 linux_security_audit.py -f Console
```

📖 **[Complete Output Reference →](../../wiki/Output-Reference)**

## 🔧 Remediation

The tool provides multiple remediation approaches for fixing security issues:

### Interactive Remediation

Review and approve each fix individually:

```bash
sudo python3 linux_security_audit.py --remediate
```

**Workflow**:
1. Shows each issue with details
2. Displays remediation command
3. Prompts for confirmation
4. Executes if approved
5. Reports results

### Filtered Remediation

Fix only specific severity levels:

```bash
# Fix only critical FAIL issues
sudo python3 linux_security_audit.py --remediate-fail

# Fix WARNING level issues
sudo python3 linux_security_audit.py --remediate-warning

# Combine with auto-remediation
sudo python3 linux_security_audit.py --remediate-fail --auto-remediate
```

### Selective Remediation

**Most precise approach** - fix only specific issues:

1. Run audit and generate HTML report
2. Review findings in browser
3. Select specific issues using checkboxes
4. Click "Export Selected" button
5. Run remediation with exported file:

```bash
sudo python3 linux_security_audit.py --auto-remediate --remediation-file Selected-Report.json
```

### Automated Remediation

Batch fix all issues with confirmation:

```bash
sudo python3 linux_security_audit.py --auto-remediate
```

⚠️ **Safety Notes**:
- Always test in non-production first
- Review remediation commands before executing
- Backup critical configurations
- Have console access in case SSH breaks
- Schedule during maintenance windows

📖 **[Remediation Guide →](../../wiki/Usage-Guide#remediation-options)**

## 📂 Project Structure

```
Linux-Security-Audit-Project/
├── linux_security_audit.py      # Main orchestrator script
├── module_core.py                # Core security baseline (150+ checks)
├── module_cis.py                 # CIS Benchmarks (200+ checks)
├── module_cisa.py                # CISA guidance (140+ checks)
├── module_enisa.py               # ENISA guidelines (135+ checks)
├── module_iso27001.py            # ISO 27001 controls (145+ checks)
├── module_nist.py                # NIST frameworks (160+ checks)
├── module_nsa.py                 # NSA hardening (155+ checks)
├── module_stig.py                # DISA STIGs (180+ checks)
├── README.md                     # This file
├── LICENSE                       # MIT License
├── CHANGELOG.md                  # Version history
├── SECURITY.md                   # Security policy
└── .gitignore                    # Git ignore rules
```

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Ways to Contribute

1. **🐛 Report Bugs**: [Open an issue](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)
2. **💡 Suggest Features**: [Request enhancements](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)
3. **📝 Improve Documentation**: Fix errors, add examples
4. **💻 Write Code**: Implement features, fix bugs
5. **🛡️ Add Checks**: Create new security checks
6. **🔍 Review PRs**: Help review pull requests

### Contribution Process

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Make** your changes
4. **Test** thoroughly (root and non-root)
5. **Commit** with clear messages (`git commit -m 'Add amazing feature'`)
6. **Push** to your fork (`git push origin feature/amazing-feature`)
7. **Open** a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Linux-Security-Audit-Project.git
cd Linux-Security-Audit-Project

# Create development branch
git checkout -b feature/your-feature

# Make changes and test
python3 linux_security_audit.py --list-modules
sudo python3 linux_security_audit.py -m YourModule

# Run tests (if available)
python3 -m pytest tests/
```

### Coding Standards

- Follow PEP 8 style guide
- Use type hints where applicable
- Write comprehensive docstrings
- Add inline comments for complex logic
- Include error handling
- Test both root and non-root execution

📖 **[Complete Development Guide →](../../wiki/Development-Guide)**

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### MIT License Summary

✅ **Permissions**:
- Commercial use
- Modification
- Distribution
- Private use

✅ **Conditions**:
- License and copyright notice

✅ **Limitations**:
- No liability
- No warranty

## 🆘 Support

### Getting Help

1. **📖 Check Documentation**: Start with [Wiki](../../wiki/Home)
2. **🔍 Search Issues**: Look for [existing issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)
3. **❓ Read FAQ**: Check [Frequently Asked Questions](../../wiki/Frequently-Asked-Questions-(FAQ))
4. **🔧 Troubleshooting**: Review [Troubleshooting Guide](../../wiki/Troubleshooting-Guide)
5. **💬 Open Issue**: [Create new issue](https://github.com/Sandler73/Linux-Security-Audit-Project/issues/new)

### Issue Guidelines

When opening an issue, please include:

**For Bug Reports**:
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version)
- Error messages and logs
- Screenshots (if applicable)

**For Feature Requests**:
- Use case description
- Why it's needed
- Proposed implementation
- Benefit to other users

### Community

- **GitHub Issues**: Bug reports and feature requests
- **Pull Requests**: Code contributions
- **Discussions**: Questions and ideas (if enabled)
- **Wiki**: Comprehensive documentation

## 🌟 Acknowledgments

### Standards Organizations

This project implements guidance from:

- **[CIS](https://www.cisecurity.org/)** - Center for Internet Security
- **[NIST](https://www.nist.gov/cyberframework)** - National Institute of Standards and Technology
- **[DISA](https://public.cyber.mil/stigs/)** - Defense Information Systems Agency
- **[NSA](https://www.nsa.gov/What-We-Do/Cybersecurity/)** - National Security Agency
- **[CISA](https://www.cisa.gov/)** - Cybersecurity and Infrastructure Security Agency
- **[ENISA](https://www.enisa.europa.eu/)** - European Union Agency for Cybersecurity
- **[ISO](https://www.iso.org/)** - International Organization for Standardization

### Security Community

Thanks to the open-source security community for:
- Security research and vulnerability disclosure
- Framework development and maintenance
- Best practices documentation
- Tool development and testing

## 📊 Project Stats

- **Version**: 1.1
- **Release Date**: January 2026
- **Total Checks**: 1,100+
- **Modules**: 8
- **Output Formats**: 5
- **Python Version**: 3.6+
- **License**: MIT
- **Status**: Active Development

## 🔗 Quick Links

### Documentation
- [Wiki Home](../../wiki/Home)
- [Quick Start](../../wiki/Quick-Start-Guide)
- [Usage Guide](../../wiki/Usage-Guide)
- [Module Docs](../../wiki/Module-Documentation)
- [Framework Reference](../../wiki/Framework-Reference)

### Project
- [GitHub Repository](https://github.com/Sandler73/Linux-Security-Audit-Project)
- [Issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)
- [Pull Requests](https://github.com/Sandler73/Linux-Security-Audit-Project/pulls)
- [Releases](https://github.com/Sandler73/Linux-Security-Audit-Project/releases)

### Standards
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [DISA STIGs](https://public.cyber.mil/stigs/)
- [NSA Cybersecurity](https://www.nsa.gov/What-We-Do/Cybersecurity/)
- [CISA Resources](https://www.cisa.gov/)

---

<div align="center">

**[⬆ Back to Top](#linux-security-audit-project)**

Made with ❤️ for the Linux security community

**[📖 Documentation](../../wiki/Home)** • **[🐛 Report Bug](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)** • **[✨ Request Feature](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)**

</div>
