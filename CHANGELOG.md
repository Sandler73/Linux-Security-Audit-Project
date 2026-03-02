# Changelog

All notable changes to the Linux Security Audit Project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned Features
- Additional output formats (PDF, Markdown, SARIF, SCAP)
- SQLite audit trail database
- Delta reporting and baseline comparison
- Syslog/CEF output for SIEM integration
- Container and Kubernetes security modules

## [2.2] - 2026-03-02

### Added

- **Performance Architecture**:
  - Shared components library (`shared_components/audit_common.py`, 2,174 lines) with caching, parallel execution, and /proc filesystem reads
  - Intelligent file and command caching with ~50% hit rate across modules
  - Parallel module execution via `--parallel` flag with configurable `--workers` count
  - Direct /proc filesystem reads replacing subprocess calls for performance
  - Dynamic module discovery from `modules/` directory with validation
  - OS-aware functionality supporting Debian, Red Hat, SUSE, and Arch families with respective package managers (apt, yum/dnf, zypper, pacman)
  - Performance profiling via `--profile` flag with cache statistics and module timing

- **Structured Logging**:
  - Dedicated `logs/` directory with hostname-stamped filenames
  - Configurable log levels via `--log-level` (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  - Custom log file path via `--log-file`
  - JSON-structured logging via `--json-log` for SIEM ingestion
  - Hybrid `log_and_print()` for simultaneous console and file output
  - Verbose mode (`--verbose`) and quiet mode (`--quiet`)
  - Per-module execution timing in performance profile

- **Interactive HTML Report Rewrite**:
  - Executive dashboard with SVG donut chart visualization
  - Cross-framework compliance matrix with weighted scores
  - Remediation priority ranking table
  - Column resizing via drag handles
  - In-column filtering per table column
  - Column visibility toggles
  - Global search with include/exclude modes
  - Per-module and global export (CSV, Excel, JSON, XML, TXT formats)
  - Row selection via checkboxes with selection-based export
  - Print-friendly CSS with `@media print` support
  - Table of Contents with smooth-scroll navigation
  - Full-width header with dark blue gradient
  - Garamond typography throughout
  - Dark/light theme toggle with CSS custom properties

- **Compliance Scoring System**:
  - `ComplianceScore` dataclass with three scoring methods
  - Simple pass percentage (Pass / Applicable, Info excluded)
  - Weighted scoring (Pass=1.0, Warning=0.5, Fail=0, Error=0)
  - Severity-weighted compliance (Critical=5x, High=3x, Medium=1.5x, Low=0.5x penalty factors)
  - Configurable pass/fail threshold (default 70%)
  - Per-module and overall compliance scores in HTML, console, JSON, and XML

- **Interactive Dashboard Filtering**:
  - Clickable donut chart segments filter by status
  - Clickable summary cards filter by status (Pass/Fail/Warning/Info/Error)
  - Clickable severity cards filter by severity level
  - Toggle behavior (click again to deselect)
  - Filter notification bar with clear button
  - Filters apply across ALL module tables simultaneously

- **IP Address Identification**:
  - `get_system_ip_addresses()` with four detection methods
  - Three paired identification points (hostname + OS + IPs) for SIEM attribution
  - Displayed in HTML info cards, console summary, JSON, and XML exports

- **STIG DISA V-Number Mapping**: 65 checks mapped to official V-numbers (38.9% coverage)
- **ISO27001 Secure Development Checks**: A.8.25 and A.8.26 controls (7 new checks)

### Changed

- **Project Structure**: Reorganized from flat layout to `modules/` + `shared_components/` + `logs/` + `reports/`
- **Python Requirement**: Minimum version raised from 3.6 to 3.7 (dataclasses dependency)
- **Module Architecture**: All 8 modules use shared_components caching and /proc reads
- **Check Count**: Validated at 1,207 total checks (was ~1,100 approximate)
- **Report Directory**: Reports saved to `reports/` directory by default
- **JSON Export**: Companion JSON auto-generated alongside all report formats
- **XML Export**: Enhanced metadata including IP addresses and compliance scores
- **Console Summary**: Now displays hostname, IP addresses, OS, and compliance scores
- **HTML Report**: Complete rewrite with 18+ interactive features

### Fixed
- Emoji corruption in module banners resolved via Unicode codepoint encoding
- Results Summary format standardized across all 8 modules
- CSV export properly handles special characters and multi-line content

### Security
- Report files created with 600 permissions in dedicated `reports/` directory
- Log files created with 644 permissions in dedicated `logs/` directory

## [1.1] - 2025-01-07

### Added
- **Module System Enhancements**:
  - Complete CISA module (140+ checks) with BOD compliance
  - Complete ENISA module (135+ checks) with EU cybersecurity standards
  - Complete ISO27001 module (145+ checks) with Annex A controls
  - Complete NSA module (155+ checks) with advanced hardening
  - Complete STIG module (180+ checks) with DoD requirements
  
- **Core Functionality**:
  - Dynamic module discovery system
  - Privilege-aware execution with graceful degradation
  - Intelligent OS detection and distribution-specific optimizations
  - Comprehensive error handling and validation
  
- **Reporting Features**:
  - Interactive HTML reports with filtering and search
  - Dark/Light theme toggle for HTML reports
  - Export selected issues to JSON for selective remediation
  - Multi-format output (HTML, CSV, JSON, XML, Console)
  - Real-time console output with color coding
  
- **Remediation System**:
  - Interactive remediation with issue-by-issue approval
  - Automated remediation with safety confirmations
  - Filtered remediation by status level (FAIL, WARNING, INFO)
  - Selective remediation from exported JSON files
  - Remediation command preview and validation
  
- **Documentation**:
  - Complete Wiki documentation (9 comprehensive pages)
  - Quick Start Guide
  - Comprehensive Usage Guide
  - Output Reference with format details
  - Module Documentation with check descriptions
  - Framework Reference with standards details
  - Development Guide for contributors
  - Troubleshooting Guide
  - Frequently Asked Questions (FAQ)

### Changed
- **Enhanced Module Coverage**:
  - Core module updated to 150+ checks
  - CIS module expanded to 200+ checks (v2.1)
  - NIST module enhanced to 160+ checks (v2.1)
  
- **Improved Performance**:
  - Optimized check execution
  - Reduced memory footprint
  - Faster filesystem operations
  - Efficient module loading
  
- **Better Error Messages**:
  - Clear, actionable error descriptions
  - Contextual help suggestions
  - Detailed troubleshooting information
  
- **Code Quality**:
  - Type hints throughout codebase
  - Comprehensive docstrings
  - PEP 8 compliance
  - Improved modularity and maintainability

### Fixed
- File permission checks now correctly handle octal notation
- Module import paths resolved for all execution contexts
- HTML report JavaScript compatibility across browsers
- CSV export handling of special characters
- JSON serialization of datetime objects
- XML entity escaping for remediation commands

### Security
- Input validation for all user-provided parameters
- Safe command execution with timeout protection
- Secure file permissions on generated reports (600)
- No external network calls or data transmission
- Privilege checks before sensitive operations

## [1.0] - 2024-12-15

### Added
- **Initial Release**:
  - Core security baseline module
  - CIS Benchmarks module
  - NIST Cybersecurity Framework module
  - Basic HTML report generation
  - CSV and JSON export capabilities
  - Command-line interface
  
- **Core Features**:
  - Multi-framework security auditing
  - Root and non-root execution support
  - Basic remediation functionality
  - Console output mode
  
- **Module System**:
  - Modular architecture with plugin support
  - Shared data structure between modules
  - Standardized AuditResult format
  
- **Documentation**:
  - README with basic usage
  - MIT License
  - Security policy

### Known Issues
- Limited error handling in some edge cases
- HTML reports lack advanced filtering
- No selective remediation capability
- Module discovery requires manual registration

## Version History Summary

| Version | Release Date | Modules | Checks | Key Features |
|---------|--------------|---------|--------|--------------|
| 2.0 | 2026-03-02 | 8 | 1,207 | Performance architecture, compliance scoring, interactive HTML, logging |
| 1.1 | 2025-01-07 | 8 | ~1,100 | Full framework coverage, advanced remediation, interactive reports |
| 1.0 | 2024-12-15 | 3 | 500+ | Initial release, basic functionality |

## Upgrade Guide

### Upgrading from 1.1 to 2.2

**Directory Structure Change** - Version 2.2 reorganizes the project layout.

**New Structure**: `modules/` + `shared_components/` + `logs/` + `reports/`

**Python Requirement**: 3.7+ (was 3.6+) due to dataclasses dependency.

**Migration Steps**:
```bash
cp -r Linux-Security-Audit-Project Linux-Security-Audit-Project-1.1-backup
cd Linux-Security-Audit-Project && git pull origin main
ls modules/ shared_components/
python3 linux_security_audit.py --list-modules
sudo python3 linux_security_audit.py -m Core --profile
```

**New CLI Flags**: `--parallel`, `--workers`, `--profile`, `--log-level`, `--log-file`, `--json-log`, `--verbose`, `--quiet`

### Upgrading from 1.0 to 1.1

**No Breaking Changes** - Version 1.1 is fully backward compatible.

**New Module Files Required**:
- Download 5 new module files: `module_cisa.py`, `module_enisa.py`, `module_iso27001.py`, `module_nsa.py`, `module_stig.py`
- Place in same directory as `linux_security_audit.py`
- No configuration changes needed

**Enhanced Features**:
- Existing HTML/CSV/JSON reports work as before
- New interactive features in HTML reports
- New remediation options available
- All previous functionality preserved

**Migration Steps**:
```bash
# Backup your 1.0 installation
cp -r Linux-Security-Audit-Project Linux-Security-Audit-Project-1.0-backup

# Pull latest changes
cd Linux-Security-Audit-Project
git pull origin main

# Verify new modules
python3 linux_security_audit.py --list-modules

# Run audit to test
sudo python3 linux_security_audit.py -m Core
```

## Development Roadmap

### Version 2.1 (Planned)

**Target Features**:
- [ ] PDF report generation
- [ ] Markdown report format
- [ ] SARIF / SCAP / XCCDF / Syslog / CEF output formats
- [ ] SQLite audit trail database
- [ ] Historical result tracking per host
- [ ] Delta reporting (new/resolved/regressed)
- [ ] Baseline comparison via `--compare` and `--baseline`

### Version 3.0 (Planned)

**Target Features**:
- [ ] Web-based dashboard interface
- [ ] Multi-system management
- [ ] Container and Kubernetes security modules
- [ ] Cloud security posture management
- [ ] Advanced analytics and ML-based risk scoring

## Contributing

We welcome contributions! Please see:
- **[Development Guide](../../wiki/Development-Guide)** - How to contribute
- **[GitHub Issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)** - Report bugs or request features
- **[Pull Requests](https://github.com/Sandler73/Linux-Security-Audit-Project/pulls)** - Submit code changes

### Contribution Guidelines

When submitting changes:
1. Update CHANGELOG.md with your changes under `[Unreleased]`
2. Follow semantic versioning
3. Include tests for new features
4. Update documentation as needed
5. Use clear commit messages

### Changelog Entry Format

```markdown
### Added
- New feature description with details

### Changed
- Modified feature description with rationale

### Deprecated
- Features marked for removal with timeline

### Removed
- Removed features with migration notes

### Fixed
- Bug fixes with issue numbers

### Security
- Security updates with CVE numbers if applicable
```

## Release Process

1. Update CHANGELOG.md with release version and date
2. Update version number in `linux_security_audit.py`
3. Create release tag: `git tag -a v1.1 -m "Release version 1.1"`
4. Push tag: `git push origin v1.1`
5. Create GitHub release with changelog notes
6. Update documentation with version references

## Support and Feedback

- **Bug Reports**: [GitHub Issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)
- **Feature Requests**: [GitHub Issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)
- **Questions**: [FAQ](../../wiki/Frequently-Asked-Questions-(FAQ)) or [GitHub Issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)
- **Security Issues**: See [SECURITY.md](SECURITY.md)

---

**Legend:**
- `Added` - New features
- `Changed` - Changes to existing functionality
- `Deprecated` - Soon-to-be removed features
- `Removed` - Removed features
- `Fixed` - Bug fixes
- `Security` - Security updates

[Unreleased]: https://github.com/Sandler73/Linux-Security-Audit-Project/compare/v2.0...HEAD
[2.0]: https://github.com/Sandler73/Linux-Security-Audit-Project/compare/v1.1...v2.0
[1.1]: https://github.com/Sandler73/Linux-Security-Audit-Project/compare/v1.0...v1.1
[1.0]: https://github.com/Sandler73/Linux-Security-Audit-Project/releases/tag/v1.0
