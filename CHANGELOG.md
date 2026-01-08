# Changelog

All notable changes to the Linux Security Audit Project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned Features
- Additional output formats (PDF, Markdown)
- Web-based dashboard interface
- Container image support
- Remote execution capabilities
- Integration with popular CI/CD platforms
- Enhanced trend analysis and reporting
- Module-specific configuration files
- Custom check framework

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
| 1.1 | 2025-01-07 | 8 | 1,100+ | Full framework coverage, advanced remediation, interactive reports |
| 1.0 | 2024-12-15 | 3 | 500+ | Initial release, basic functionality |

## Upgrade Guide

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

### Version 1.2 (Planned - Q2 2025)

**Target Features**:
- [ ] PDF report generation
- [ ] Markdown report format
- [ ] Enhanced trend analysis
- [ ] Compliance scoring system
- [ ] Module configuration files
- [ ] Custom check templates
- [ ] Plugin system for third-party modules
- [ ] API for programmatic access

### Version 1.3 (Planned - Q3 2025)

**Target Features**:
- [ ] Web-based dashboard
- [ ] Real-time monitoring integration
- [ ] Agent-based deployment
- [ ] Centralized reporting server
- [ ] Role-based access control
- [ ] Email alert integration
- [ ] Slack/Teams notifications

### Version 2.0 (Planned - Q4 2025)

**Target Features**:
- [ ] Complete rewrite with improved architecture
- [ ] Database backend for historical data
- [ ] Multi-system management
- [ ] Advanced analytics and ML-based risk scoring
- [ ] Container and Kubernetes security modules
- [ ] Cloud security posture management
- [ ] Compliance workflow management

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

[Unreleased]: https://github.com/Sandler73/Linux-Security-Audit-Project/compare/v1.1...HEAD
[1.1]: https://github.com/Sandler73/Linux-Security-Audit-Project/compare/v1.0...v1.1
[1.0]: https://github.com/Sandler73/Linux-Security-Audit-Project/releases/tag/v1.0
