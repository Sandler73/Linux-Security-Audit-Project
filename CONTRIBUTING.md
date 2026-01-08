# Contributing to Linux Security Audit Project

First off, thank you for considering contributing to the Linux Security Audit Project! It's people like you that make this tool better for the entire Linux security community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Submitting Changes](#submitting-changes)
- [Issue Guidelines](#issue-guidelines)
- [Community](#community)

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. We pledge to make participation in our project a harassment-free experience for everyone, regardless of:

- Age
- Body size
- Disability
- Ethnicity
- Gender identity and expression
- Level of experience
- Nationality
- Personal appearance
- Race
- Religion
- Sexual identity and orientation

### Our Standards

**Positive behaviors include:**

- ✅ Using welcoming and inclusive language
- ✅ Being respectful of differing viewpoints and experiences
- ✅ Gracefully accepting constructive criticism
- ✅ Focusing on what is best for the community
- ✅ Showing empathy towards other community members
- ✅ Providing helpful and actionable feedback

**Unacceptable behaviors include:**

- ❌ Trolling, insulting/derogatory comments, and personal or political attacks
- ❌ Public or private harassment
- ❌ Publishing others' private information without explicit permission
- ❌ Other conduct which could reasonably be considered inappropriate

### Enforcement

Project maintainers have the right and responsibility to remove, edit, or reject comments, commits, code, wiki edits, issues, and other contributions that are not aligned with this Code of Conduct.

## How Can I Contribute?

There are many ways to contribute to this project:

### 🐛 Reporting Bugs

Found a bug? Help us fix it!

**Before submitting:**
- Check the [existing issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues) to avoid duplicates
- Try the latest version to see if the bug still exists
- Review the [Troubleshooting Guide](../../wiki/Troubleshooting-Guide)

**When submitting:**
- Use a clear, descriptive title
- Provide detailed steps to reproduce
- Include your environment (OS, Python version, module)
- Attach error messages and logs
- Describe expected vs actual behavior

**Template:**
```markdown
**Bug Description**
Clear description of what the bug is.

**To Reproduce**
Steps to reproduce:
1. Run command '...'
2. See error

**Expected Behavior**
What you expected to happen.

**Environment**
- OS: [e.g., Ubuntu 22.04]
- Python Version: [e.g., 3.10.12]
- Script Version: [e.g., 1.1]
- Module: [e.g., CIS]
- Running as: [root/non-root]

**Error Output**
```
Paste error messages here
```

**Additional Context**
Screenshots, logs, or other relevant information.
```

### 💡 Suggesting Features

Have an idea? We'd love to hear it!

**Before submitting:**
- Check [existing issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues) for similar suggestions
- Review the [Development Roadmap](CHANGELOG.md#development-roadmap)
- Consider if it benefits the broader community

**When submitting:**
- Use a clear, descriptive title prefixed with `[Feature Request]`
- Explain the problem this feature would solve
- Describe the proposed solution
- Consider alternative solutions
- Explain benefits to other users

**Template:**
```markdown
**Feature Request**
Clear description of the feature.

**Problem Statement**
What problem does this solve?

**Proposed Solution**
How should this feature work?

**Alternatives Considered**
Other approaches you've thought about.

**Benefits**
How does this help the community?

**Additional Context**
Mockups, examples, or related features.
```

### 📝 Improving Documentation

Documentation improvements are always welcome!

**Areas to contribute:**
- Fix typos or grammatical errors
- Clarify confusing instructions
- Add missing examples
- Update outdated information
- Translate documentation (future)
- Add diagrams or screenshots

**Process:**
1. Identify documentation to improve
2. Make changes in your fork
3. Submit pull request with clear description
4. Reference specific sections changed

### 💻 Writing Code

Contributing code? Awesome! Here's how:

#### Good First Issues

Look for issues labeled [`good first issue`](https://github.com/Sandler73/Linux-Security-Audit-Project/labels/good%20first%20issue) - these are great starting points for new contributors.

#### Areas Needing Help

- **New Security Checks**: Add checks to existing modules
- **New Modules**: Implement additional security frameworks
- **Bug Fixes**: Address reported issues
- **Performance**: Optimize slow operations
- **Testing**: Add unit or integration tests
- **Features**: Implement requested enhancements

### 🧪 Testing

Help us maintain quality by testing:

- **Manual Testing**: Try new features and report findings
- **OS Testing**: Test on different Linux distributions
- **Edge Cases**: Test with unusual configurations
- **Performance Testing**: Test on large systems
- **Security Testing**: Look for security issues

### 🌐 Community Support

Help others in the community:

- Answer questions in issues
- Help troubleshoot problems
- Share your use cases and experiences
- Write blog posts or tutorials
- Spread the word about the project

## Getting Started

### Prerequisites

1. **Required Knowledge**:
   - Python 3.6+ programming
   - Linux system administration
   - Security concepts
   - Git version control

2. **Development Tools**:
   ```bash
   # Python 3.6+
   python3 --version
   
   # Git
   git --version
   
   # Text editor (your choice)
   vim, nano, VS Code, PyCharm, etc.
   ```

### Fork and Clone

1. **Fork the repository** on GitHub (click Fork button)

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/Linux-Security-Audit-Project.git
   cd Linux-Security-Audit-Project
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/Sandler73/Linux-Security-Audit-Project.git
   ```

4. **Verify remotes**:
   ```bash
   git remote -v
   # Should show origin (your fork) and upstream (main repo)
   ```

### Development Environment

1. **Create virtual environment** (optional but recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/Mac
   ```

2. **Verify setup**:
   ```bash
   python3 linux_security_audit.py --list-modules
   ```

3. **Install development tools** (optional):
   ```bash
   pip install black pylint flake8 mypy pytest
   ```

## Development Workflow

### 1. Create a Branch

Always create a new branch for your work:

```bash
# For features
git checkout -b feature/description-of-feature

# For bug fixes
git checkout -b bugfix/description-of-bug

# For documentation
git checkout -b docs/description-of-changes
```

**Branch Naming**:
- `feature/` - New features
- `bugfix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring
- `test/` - Test additions
- `chore/` - Maintenance tasks

### 2. Make Changes

1. **Write your code** following our [coding standards](#coding-standards)
2. **Test thoroughly** with both root and non-root privileges
3. **Document changes** in code comments and docstrings
4. **Update documentation** if adding/changing features

### 3. Test Your Changes

#### Manual Testing

```bash
# Test standalone module
python3 module_name.py

# Test integration
python3 linux_security_audit.py --list-modules

# Test without root
python3 linux_security_audit.py -m YourModule -f Console

# Test with root
sudo python3 linux_security_audit.py -m YourModule
```

#### Automated Testing

```bash
# Run tests (if available)
python3 -m pytest tests/

# Check code style
pylint *.py
flake8 *.py

# Type checking
mypy linux_security_audit.py
```

### 4. Commit Changes

Follow our commit message conventions:

**Format**:
```
<type>: <subject>

<body>

<footer>
```

**Types**:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `test`: Test additions/changes
- `chore`: Maintenance tasks

**Examples**:

```bash
# Feature
git commit -m "feat: Add ISO27001 A.8.5 authentication checks

Implements secure authentication requirements from ISO27001:2022
including MFA checks and password policy validation.

Closes #123"

# Bug fix
git commit -m "fix: Correct file permission check in Core module

Changed from string comparison to octal for proper permission
validation. Fixes incorrect Pass/Fail on permission checks.

Fixes #456"

# Documentation
git commit -m "docs: Update Quick Start Guide with new examples

Added examples for:
- Multi-module execution
- Selective remediation
- SIEM integration

No code changes."
```

**Commit Best Practices**:
- Use present tense ("Add feature" not "Added feature")
- Be concise but descriptive
- Reference issues when applicable
- Keep commits atomic (one logical change per commit)

### 5. Keep Your Branch Updated

```bash
# Fetch latest changes from upstream
git fetch upstream

# Rebase your branch on upstream/main
git rebase upstream/main

# If there are conflicts, resolve them, then:
git rebase --continue

# Force push to your fork (only for feature branches)
git push --force-with-lease origin feature/your-feature
```

### 6. Submit Pull Request

See [Submitting Changes](#submitting-changes) section below.

## Coding Standards

### Python Style

**Follow PEP 8**: [https://peps.python.org/pep-0008/](https://peps.python.org/pep-0008/)

**Key Points**:

- **Indentation**: 4 spaces (no tabs)
- **Line Length**: 100 characters maximum
- **Imports**: Standard library, third-party, local (separated by blank lines)
- **Naming**:
  - Functions/variables: `lowercase_with_underscores`
  - Classes: `CapitalizedWords`
  - Constants: `UPPERCASE_WITH_UNDERSCORES`
  - Modules: `lowercase_no_underscores`

**Example**:
```python
import os
import sys

from typing import List, Dict

from linux_security_audit import AuditResult

# Constants
MODULE_NAME = "EXAMPLE"
MAX_RETRIES = 3

class SecurityChecker:
    """Security check implementation"""
    
    def __init__(self, config: Dict):
        self.config = config
    
    def check_setting(self, name: str) -> bool:
        """Check a specific setting"""
        return True

def run_security_check(param: str) -> List[AuditResult]:
    """Execute security check"""
    results = []
    return results
```

### Documentation

**Module Headers**:
```python
"""
module_name.py
Module Title
Version: X.X

SYNOPSIS:
    One-line description

DESCRIPTION:
    Multi-line detailed description

PARAMETERS:
    shared_data : Dictionary containing shared data

USAGE:
    python3 module_name.py

NOTES:
    Version, standards, references
"""
```

**Function Docstrings**:
```python
def function_name(param1: str, param2: int) -> List[AuditResult]:
    """
    Brief description of function purpose
    
    Args:
        param1: Description of first parameter
        param2: Description of second parameter
        
    Returns:
        Description of return value
        
    Raises:
        ExceptionType: When this exception is raised
    """
    pass
```

**Inline Comments**:
```python
# Good: Explains WHY
# CIS Benchmark 5.4.1 requires password expiration <= 365 days
max_days = 365

# Bad: Explains WHAT (code is obvious)
# Set max_days to 365
max_days = 365
```

### Error Handling

**Always use specific exceptions**:

```python
# Good
try:
    with open(config_file, 'r') as f:
        content = f.read()
except FileNotFoundError:
    # Handle missing file
    pass
except PermissionError:
    # Handle permission issue
    pass
except Exception as e:
    # Generic catch-all as last resort
    pass

# Bad - never use bare except
try:
    something()
except:  # Don't do this
    pass
```

### Type Hints

Use type hints for better code clarity:

```python
from typing import List, Dict, Any, Optional, Tuple

def check_function(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """Function with type hints"""
    results: List[AuditResult] = []
    # Implementation
    return results
```

### Security Practices

**Never use**:
- `eval()` or `exec()` on user input
- Shell=True with unsanitized input
- Hardcoded credentials
- Unsafe file operations

**Always**:
- Validate all inputs
- Use subprocess securely
- Handle exceptions properly
- Set secure file permissions

## Testing Guidelines

### Manual Testing Checklist

Before submitting, test your changes:

- [ ] Module runs standalone: `python3 module_name.py`
- [ ] Module discovered: `python3 linux_security_audit.py --list-modules`
- [ ] Module integrates: `python3 linux_security_audit.py -m NAME`
- [ ] Works without root (graceful degradation)
- [ ] Works with root (full functionality)
- [ ] All output formats work (HTML, CSV, JSON, XML, Console)
- [ ] Remediation commands are valid
- [ ] No hardcoded paths
- [ ] No security vulnerabilities
- [ ] Documentation updated

### Testing on Multiple Distributions

If possible, test on:
- Ubuntu/Debian
- RHEL/CentOS
- Fedora
- At least one non-systemd system (if relevant)

### Test Cases to Consider

1. **Normal Operation**: Expected inputs and conditions
2. **Edge Cases**: Empty files, missing directories, etc.
3. **Error Conditions**: Permission denied, file not found, etc.
4. **Large Scale**: Many users, large filesystems
5. **Privilege Levels**: Root vs non-root behavior

## Submitting Changes

### Pull Request Process

1. **Update your branch** with latest upstream changes
2. **Push to your fork**:
   ```bash
   git push origin feature/your-feature
   ```

3. **Create Pull Request** on GitHub:
   - Click "New Pull Request"
   - Select your fork and branch
   - Fill out PR template completely

### Pull Request Template

```markdown
## Description
Brief description of changes.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing Performed
- [ ] Tested standalone module execution
- [ ] Tested integration with main script
- [ ] Tested without root privileges
- [ ] Tested with root privileges
- [ ] Tested on [OS/distribution]
- [ ] All output formats verified
- [ ] Remediation tested (if applicable)

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review of code performed
- [ ] Comments added for complex code
- [ ] Documentation updated
- [ ] No new warnings generated
- [ ] Tests added (if applicable)
- [ ] All tests pass locally

## Related Issues
Closes #123
Related to #456

## Screenshots (if applicable)
Add screenshots for UI changes.

## Additional Notes
Any additional information reviewers should know.
```

### PR Title Format

Use the same format as commit messages:

```
feat: Add ISO27001 authentication checks
fix: Correct file permission validation
docs: Update troubleshooting guide
```

### What Happens Next?

1. **Automated Checks**: CI/CD runs (if configured)
2. **Code Review**: Maintainers review your code
3. **Feedback**: You may receive change requests
4. **Iteration**: Make requested changes, push updates
5. **Approval**: Once approved, maintainers merge
6. **Recognition**: You're added as a contributor! 🎉

### Responding to Feedback

- Be open to feedback and constructive criticism
- Ask questions if feedback is unclear
- Make requested changes promptly
- Explain your reasoning if you disagree respectfully
- Mark conversations as resolved after addressing
- Be patient - reviews take time

## Issue Guidelines

### Creating Issues

**Good Issue Characteristics**:
- Clear, descriptive title
- Detailed description
- Steps to reproduce (for bugs)
- Expected vs actual behavior
- Environment information
- Screenshots/logs when applicable
- Searched for duplicates first

### Issue Labels

Common labels:
- `bug` - Something isn't working
- `enhancement` - New feature or request
- `documentation` - Documentation improvements
- `good first issue` - Good for newcomers
- `help wanted` - Extra attention needed
- `question` - Further information requested
- `wontfix` - This will not be worked on
- `duplicate` - Duplicate of existing issue
- `invalid` - Doesn't seem right

### Issue Etiquette

**Do**:
- Be respectful and professional
- Provide complete information
- Follow up on questions
- Close issues when resolved
- Thank contributors

**Don't**:
- Bump issues repeatedly
- Demand immediate responses
- Open duplicate issues
- Use issues for support questions (use Q&A/discussions)
- Be rude or dismissive

## Community

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **Pull Requests**: Code contributions and reviews
- **GitHub Discussions**: General questions and ideas (if enabled)
- **Wiki**: Documentation and guides

### Getting Help

If you need help with contributing:

1. **Documentation**: Read the [Development Guide](../../wiki/Development-Guide)
2. **Examples**: Look at existing modules and PRs
3. **Ask**: Open a discussion or issue with "question" label
4. **Community**: Other contributors are happy to help!

### Recognition

Contributors are recognized in several ways:

- Listed in GitHub contributors
- Mentioned in release notes
- Credit in documentation (for major contributions)
- Community appreciation and thanks

### Staying Updated

- **Watch** the repository on GitHub for notifications
- **Star** the repository to show support
- Check [CHANGELOG.md](CHANGELOG.md) for updates
- Review closed issues and merged PRs to learn

## Additional Resources

### Documentation
- **[Development Guide](../../wiki/Development-Guide)**: Complete development documentation
- **[Module Documentation](../../wiki/Module-Documentation)**: Module API and structure
- **[Framework Reference](../../wiki/Framework-Reference)**: Security framework details
- **[Code of Conduct](#code-of-conduct)**: Community standards

### Learning Resources
- **[PEP 8](https://peps.python.org/pep-0008/)**: Python style guide
- **[Git Basics](https://git-scm.com/book/en/v2)**: Git documentation
- **[GitHub Flow](https://guides.github.com/introduction/flow/)**: GitHub workflow

### Security Standards
- **[CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)**
- **[NIST](https://www.nist.gov/cyberframework)**
- **[DISA STIGs](https://public.cyber.mil/stigs/)**

## Questions?

If you have questions about contributing:

1. Check the [FAQ](../../wiki/Frequently-Asked-Questions-(FAQ))
2. Read this guide thoroughly
3. Search [existing issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)
4. Open a new issue with the "question" label

---

## Thank You! 🙏

Your contributions make this project better for everyone. Whether you're fixing a typo, adding a feature, or helping others, your time and effort are greatly appreciated.

**Happy Contributing!** 🚀

---

**Last Updated**: January 7, 2026  
**Maintained By**: Sandler73
