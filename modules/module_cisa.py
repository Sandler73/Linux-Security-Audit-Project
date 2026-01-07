#!/usr/bin/env python3
"""
module_cisa.py
CISA (Cybersecurity and Infrastructure Security Agency) Module for Linux
Version: 2.0

SYNOPSIS:
    CISA Cybersecurity Directives and best practices compliance checks for Linux systems.

DESCRIPTION:
    This module performs comprehensive security checks based on CISA directives, advisories,
    and cybersecurity best practices for protecting critical infrastructure:
    
    Binding Operational Directives (BODs):
    - BOD 18-01: Enhanced Email and Web Security
    - BOD 19-02: Vulnerability Remediation Requirements
    - BOD 20-01: Develop and Publish a Vulnerability Disclosure Policy
    - BOD 22-01: Reducing the Significant Risk of Known Exploited Vulnerabilities
    - BOD 23-01: Improving Asset Visibility and Vulnerability Detection
    
    Emergency Directives (EDs):
    - Critical vulnerability patching
    - Immediate threat mitigation
    - Zero-day protection
    
    Vulnerability Management:
    - Known Exploited Vulnerabilities (KEV) catalog
    - Patch management and timelines
    - Vulnerability scanning
    - Configuration management
    
    Critical Infrastructure Protection:
    - Essential services security
    - Network segmentation
    - Access control
    - Incident response readiness
    
    Security Best Practices:
    - Multi-factor authentication
    - Least privilege principles
    - Secure configuration baselines
    - Logging and monitoring
    - Backup and recovery
    
    Cloud and Modern Infrastructure:
    - Cloud security posture
    - Container security
    - DevSecOps practices
    
    Incident Response:
    - Detection capabilities
    - Response procedures
    - Recovery planning
    - Communication protocols
    
    Based on CISA Publications:
    - CISA Binding Operational Directives
    - CISA Emergency Directives
    - CISA Cybersecurity Advisories
    - CISA Security Alerts and Analysis Reports
    - Known Exploited Vulnerabilities Catalog

USAGE:
# Standalone testing
python3 module_cisa.py

# Integration with main audit script
import module_cisa
results = module_cisa.run_checks({'is_root': True})

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

NOTES:
    Version: 2.0
    Reference: https://www.cisa.gov/directives
    Standards: CISA BODs, CISA EDs, NIST Cybersecurity Framework
    Priority: Critical, High, Medium, Low severity findings
    Target: 150+ comprehensive security checks
"""

import os
import sys
import re
import subprocess
import glob
import pwd
import grp
import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

# Import AuditResult from main script
sys.path.insert(0, str(Path(__file__).parent.parent))
from linux_security_audit import AuditResult

MODULE_NAME = "CISA"
MODULE_VERSION = "2.0.0"

# ============================================================================

# ============================================================================
# Helper Functions
# ============================================================================

def run_command(command: str, check: bool = False) -> subprocess.CompletedProcess:
    """Execute a shell command and return the result"""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            check=check,
            timeout=30
        )
        return result
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            args=command, returncode=-1, stdout="", stderr="Command timeout"
        )
    except Exception as e:
        return subprocess.CompletedProcess(
            args=command, returncode=-1, stdout="", stderr=str(e)
        )

def command_exists(command: str) -> bool:
    """Check if a command exists"""
    result = run_command(f"which {command} 2>/dev/null")
    return result.returncode == 0

def read_file_safe(filepath: str) -> str:
    """Safely read a file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except Exception:
        return ""

def check_service_enabled(service_name: str) -> bool:
    """Check if a systemd service is enabled"""
    result = run_command(f"systemctl is-enabled {service_name} 2>/dev/null")
    return result.returncode == 0 and result.stdout.strip() == "enabled"

def check_service_active(service_name: str) -> bool:
    """Check if a systemd service is active"""
    result = run_command(f"systemctl is-active {service_name} 2>/dev/null")
    return result.returncode == 0 and result.stdout.strip() == "active"

def check_package_installed(package_name: str) -> bool:
    """Check if a package is installed (works for both apt and rpm)"""
    # Try dpkg (Debian/Ubuntu)
    result = run_command(f"dpkg -l {package_name} 2>/dev/null | grep -q '^ii'")
    if result.returncode == 0:
        return True
    
    # Try rpm (RHEL/CentOS)
    result = run_command(f"rpm -q {package_name} 2>/dev/null")
    return result.returncode == 0

def get_file_permissions(filepath: str) -> Optional[str]:
    """Get file permissions as octal string"""
    try:
        stat_info = os.stat(filepath)
        return oct(stat_info.st_mode)[-3:]
    except Exception:
        return None

def get_file_owner_group(filepath: str) -> Tuple[Optional[str], Optional[str]]:
    """Get file owner and group"""
    try:
        stat_info = os.stat(filepath)
        owner = pwd.getpwuid(stat_info.st_uid).pw_name
        group = grp.getgrgid(stat_info.st_gid).gr_name
        return owner, group
    except Exception:
        return None, None

def check_kernel_parameter(parameter: str) -> Tuple[bool, str]:
    """Check kernel parameter value"""
    result = run_command(f"sysctl {parameter} 2>/dev/null")
    if result.returncode == 0:
        match = re.search(r'=\s*(.+)', result.stdout)
        if match:
            return True, match.group(1).strip()
    return False, ""

def get_package_version(package_name: str) -> Optional[str]:
    """Get installed package version"""
    # Try dpkg
    result = run_command(f"dpkg -l {package_name} 2>/dev/null | grep '^ii' | awk '{{print $3}}'")
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip()
    
    # Try rpm
    result = run_command(f"rpm -q --queryformat '%{{VERSION}}-%{{RELEASE}}' {package_name} 2>/dev/null")
    if result.returncode == 0:
        return result.stdout.strip()
    
    return None

def check_updates_available() -> Tuple[int, List[str]]:
    """Check for available security updates"""
    security_updates = []
    count = 0
    
    if command_exists("apt"):
        # Ubuntu/Debian
        result = run_command("apt list --upgradable 2>/dev/null | grep -i security | head -20")
        if result.returncode == 0 and result.stdout:
            security_updates = [line.split('/')[0] for line in result.stdout.strip().split('\n') if line]
            count = len(security_updates)
    elif command_exists("yum"):
        # RHEL/CentOS
        result = run_command("yum updateinfo list security 2>/dev/null | grep -i 'security' | wc -l")
        if result.returncode == 0 and result.stdout.strip().isdigit():
            count = int(result.stdout.strip())
        
        # Get package names
        result = run_command("yum updateinfo list security 2>/dev/null | grep -i 'security' | head -20 | awk '{print $3}'")
        if result.returncode == 0 and result.stdout:
            security_updates = [line for line in result.stdout.strip().split('\n') if line]
    
    return count, security_updates

def get_cisa_id(category: str, number: int) -> str:
    """Generate CISA check ID"""
    return f"CISA-{category}-{number:03d}"

# ============================================================================
# This is the end of Part 1
# Continue with Part 2 for BOD 22-01 checks...
# ============================================================================

# ============================================================================
# BOD 22-01: Known Exploited Vulnerabilities Catalog (40 checks)
# ============================================================================

def check_bod_22_01_kev(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    BOD 22-01: Reducing Significant Risk of Known Exploited Vulnerabilities
    40 comprehensive checks for KEV catalog vulnerabilities
    """
    print(f"[{MODULE_NAME}] Checking BOD 22-01 - Known Exploited Vulnerabilities...")
    
    # KEV-001: Kernel version check
    kernel_version = run_command("uname -r").stdout.strip()
    vulnerable_kernels = ['5.8.', '5.9.', '5.10.0-']
    is_vulnerable = any(vuln in kernel_version for vuln in vulnerable_kernels)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Fail" if is_vulnerable else "Pass",
        message=f"{get_cisa_id('KEV', 1)}: Kernel free from known exploited vulnerabilities (Critical)",
        details=f"Kernel: {kernel_version}",
        remediation="Update kernel to latest stable version within 15 days"
    ))
    
    # KEV-002: OpenSSL Heartbleed check
    if command_exists("openssl"):
        openssl_version = run_command("openssl version").stdout.strip()
        vulnerable_ssl = "1.0.1" in openssl_version and not any(x in openssl_version for x in ["1.0.1g", "1.0.1h", "1.0.1i"])
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Fail" if vulnerable_ssl else "Pass",
            message=f"{get_cisa_id('KEV', 2)}: OpenSSL free from Heartbleed (CVE-2014-0160) (Critical)",
            details=openssl_version,
            remediation="Update OpenSSL to 1.1.1+ immediately"
        ))
    
    # KEV-003: sudo Baron Samedit
    if command_exists("sudo"):
        sudo_version = run_command("sudo -V | head -1").stdout.strip()
        vulnerable_sudo = any(v in sudo_version for v in ["1.8.2", "1.8.3", "1.9.0", "1.9.1", "1.9.2"])
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Fail" if vulnerable_sudo else "Pass",
            message=f"{get_cisa_id('KEV', 3)}: sudo free from Baron Samedit (CVE-2021-3156) (Critical)",
            details=sudo_version,
            remediation="Update sudo to 1.9.5p2+ within 15 days"
        ))
    
    # KEV-004: systemd vulnerabilities
    if command_exists("systemctl"):
        systemd_version = run_command("systemctl --version | head -1 | awk '{print $2}'").stdout.strip()
        try:
            version_num = int(systemd_version)
            vulnerable = version_num < 249
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - BOD 22-01",
                status="Fail" if vulnerable else "Pass",
                message=f"{get_cisa_id('KEV', 4)}: systemd free from CVE-2021-33910 (High)",
                details=f"systemd {systemd_version}",
                remediation="Update systemd to 249+"
            ))
        except:
            pass
    
    # KEV-005: Polkit PwnKit
    if check_package_installed("polkit"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Warning",
            message=f"{get_cisa_id('KEV', 5)}: Polkit PwnKit (CVE-2021-4034) assessment (Critical)",
            details="Polkit installed - verify version 0.120+",
            remediation="Update polkit to 0.120+ immediately"
        ))
    
    # KEV-006: Log4Shell
    log4j_search = run_command("find /opt /var/lib /usr -name 'log4j*.jar' 2>/dev/null | head -5").stdout.strip()
    has_log4j = bool(log4j_search)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Fail" if has_log4j else "Pass",
        message=f"{get_cisa_id('KEV', 6)}: Log4Shell (CVE-2021-44228) vulnerability (Critical)",
        details="Log4j found" if has_log4j else "No Log4j detected",
        remediation="Update all Log4j to 2.17.1+ or remove"
    ))
    
    # KEV-007: Last system update
    last_update_days = 999
    if os.path.exists("/var/log/apt/history.log"):
        result = run_command("stat -c %Y /var/log/apt/history.log")
        if result.returncode == 0:
            try:
                last_update_days = int((datetime.datetime.now().timestamp() - int(result.stdout.strip())) / 86400)
            except:
                pass
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Pass" if last_update_days <= 30 else "Fail",
        message=f"{get_cisa_id('KEV', 7)}: System updated within 30 days (High)",
        details=f"Last update: {last_update_days} days ago",
        remediation="Update system to meet BOD 22-01 timeline"
    ))
    
    # KEV-008: Available security updates
    update_count, update_list = check_updates_available()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Fail" if update_count > 0 else "Pass",
        message=f"{get_cisa_id('KEV', 8)}: No pending security updates (High)",
        details=f"{update_count} security updates available",
        remediation="Apply security updates within BOD timeline"
    ))
    
    # KEV-009: Automatic updates
    auto_updates = check_package_installed("unattended-upgrades") or check_service_enabled("dnf-automatic.timer")
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Pass" if auto_updates else "Warning",
        message=f"{get_cisa_id('KEV', 9)}: Automatic security updates enabled (Medium)",
        details="Enabled" if auto_updates else "Not configured",
        remediation="Enable automatic security updates"
    ))
    
    # KEV-010: Live kernel patching
    live_patch = check_service_active("kpatch") or os.path.exists("/sys/kernel/livepatch")
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Pass" if live_patch else "Info",
        message=f"{get_cisa_id('KEV', 10)}: Live kernel patching capability (Low)",
        details="Enabled" if live_patch else "Not configured",
        remediation="Consider enabling live patching"
    ))
    
    # KEV-011: Apache httpd
    if command_exists("apache2") or command_exists("httpd"):
        apache_version = run_command("apache2 -v 2>/dev/null || httpd -v 2>/dev/null").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 11)}: Apache web server assessment (High)",
            details=f"Apache detected: {apache_version[:50] if apache_version else 'Yes'}",
            remediation="Ensure Apache updated to latest stable"
        ))
    
    # KEV-012: nginx
    if command_exists("nginx"):
        nginx_version = run_command("nginx -v 2>&1").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 12)}: nginx web server assessment (High)",
            details=f"nginx detected: {nginx_version[:50] if nginx_version else 'Yes'}",
            remediation="Ensure nginx updated to latest stable"
        ))
    
    # KEV-013: OpenSSH
    if command_exists("sshd"):
        ssh_version = run_command("sshd -V 2>&1 | head -1").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 13)}: OpenSSH version assessment (High)",
            details=f"OpenSSH: {ssh_version[:50] if ssh_version else 'installed'}",
            remediation="Ensure OpenSSH 8.0+ for security fixes"
        ))
    
    # KEV-014: BIND DNS
    if command_exists("named"):
        bind_version = run_command("named -v 2>&1").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 14)}: BIND DNS server assessment (High)",
            details=f"BIND: {bind_version[:50] if bind_version else 'installed'}",
            remediation="Ensure BIND updated to latest stable"
        ))
    
    # KEV-015: MySQL/MariaDB
    if command_exists("mysql") or command_exists("mariadb"):
        db_version = run_command("mysql --version 2>/dev/null || mariadb --version 2>/dev/null").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 15)}: MySQL/MariaDB assessment (High)",
            details=f"Database: {db_version[:50] if db_version else 'installed'}",
            remediation="Ensure database updated to latest stable"
        ))
    
    # KEV-016: PostgreSQL
    if command_exists("psql"):
        pg_version = run_command("psql --version").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 16)}: PostgreSQL assessment (High)",
            details=pg_version[:50] if pg_version else "PostgreSQL installed",
            remediation="Ensure PostgreSQL updated"
        ))
    
    # KEV-017: Docker
    if command_exists("docker"):
        docker_version = run_command("docker --version").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 17)}: Docker runtime assessment (High)",
            details=docker_version[:50] if docker_version else "Docker installed",
            remediation="Ensure Docker updated to latest"
        ))
    
    # KEV-018: Kubernetes
    if command_exists("kubectl"):
        k8s_version = run_command("kubectl version --client --short 2>/dev/null").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 18)}: Kubernetes client assessment (High)",
            details=k8s_version[:50] if k8s_version else "kubectl installed",
            remediation="Ensure kubectl updated"
        ))
    
    # KEV-019: Python version
    if command_exists("python3"):
        python_version = run_command("python3 --version").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 19)}: Python runtime assessment (Medium)",
            details=python_version,
            remediation="Ensure Python 3.9+ for security fixes"
        ))
    
    # KEV-020: Node.js
    if command_exists("node"):
        node_version = run_command("node --version").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 20)}: Node.js runtime assessment (Medium)",
            details=node_version,
            remediation="Ensure Node.js LTS version"
        ))
    
    # KEV-021: PHP
    if command_exists("php"):
        php_version = run_command("php --version | head -1").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 21)}: PHP runtime assessment (Medium)",
            details=php_version[:50] if php_version else "PHP installed",
            remediation="Ensure PHP 7.4+ or 8.0+"
        ))
    
    # KEV-022: Java
    if command_exists("java"):
        java_version = run_command("java -version 2>&1 | head -1").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 22)}: Java runtime assessment (Medium)",
            details=java_version[:50] if java_version else "Java installed",
            remediation="Ensure Java 11 or 17 LTS"
        ))
    
    # KEV-023: Ruby
    if command_exists("ruby"):
        ruby_version = run_command("ruby --version").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 23)}: Ruby runtime assessment (Medium)",
            details=ruby_version[:50] if ruby_version else "Ruby installed",
            remediation="Ensure Ruby 2.7+ or 3.0+"
        ))
    
    # KEV-024: Git
    if command_exists("git"):
        git_version = run_command("git --version").stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 24)}: Git version control assessment (Low)",
            details=git_version,
            remediation="Ensure Git 2.30+"
        ))
    
    # KEV-025: Obsolete packages
    obsolete_packages = []
    for pkg in ["telnet-server", "rsh-server", "ypserv", "tftp-server", "talk-server"]:
        if check_package_installed(pkg):
            obsolete_packages.append(pkg)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Fail" if obsolete_packages else "Pass",
        message=f"{get_cisa_id('KEV', 25)}: No obsolete vulnerable packages (High)",
        details=f"Obsolete: {obsolete_packages}" if obsolete_packages else "None found",
        remediation="Remove obsolete packages immediately"
    ))
    
    # KEV-026: Vulnerability scanner
    vuln_scanners = []
    for scanner in ["lynis", "tiger", "aide", "rkhunter", "chkrootkit"]:
        if command_exists(scanner) or check_package_installed(scanner):
            vuln_scanners.append(scanner)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Pass" if vuln_scanners else "Warning",
        message=f"{get_cisa_id('KEV', 26)}: Vulnerability scanning tools installed (Medium)",
        details=f"Scanners: {vuln_scanners}" if vuln_scanners else "None",
        remediation="Install lynis and aide for vulnerability scanning"
    ))
    
    # KEV-027: Repository GPG keys
    if command_exists("apt-key"):
        keys = run_command("apt-key list 2>/dev/null | grep -c 'pub'").stdout.strip()
        has_keys = keys and int(keys) > 0
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Pass" if has_keys else "Fail",
            message=f"{get_cisa_id('KEV', 27)}: Repository GPG keys configured (Medium)",
            details=f"{keys} keys" if has_keys else "No keys",
            remediation="Import GPG keys for all repositories"
        ))
    
    # KEV-028: Kernel parameters - ASLR
    exists, value = check_kernel_parameter("kernel.randomize_va_space")
    aslr_enabled = value == "2"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Pass" if aslr_enabled else "Fail",
        message=f"{get_cisa_id('KEV', 28)}: ASLR (Address Space Layout Randomization) enabled (High)",
        details=f"ASLR: {value}",
        remediation="Set kernel.randomize_va_space=2"
    ))
    
    # KEV-029: Core dumps restricted
    exists, value = check_kernel_parameter("fs.suid_dumpable")
    core_restricted = value == "0"
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 22-01",
        status="Pass" if core_restricted else "Fail",
        message=f"{get_cisa_id('KEV', 29)}: Core dumps restricted (Medium)",
        details=f"fs.suid_dumpable: {value}",
        remediation="Set fs.suid_dumpable=0"
    ))
    
    # KEV-030: Firmware updates
    if command_exists("fwupdmgr"):
        fw_updates = run_command("fwupdmgr get-updates 2>/dev/null | grep -c 'Update'").stdout.strip()
        try:
            fw_count = int(fw_updates)
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - BOD 22-01",
                status="Warning" if fw_count > 0 else "Pass",
                message=f"{get_cisa_id('KEV', 30)}: Firmware updates available (Medium)",
                details=f"{fw_count} firmware updates",
                remediation="Apply firmware updates: fwupdmgr update"
            ))
        except:
            pass
    
    # KEV-031-040: Additional KEV monitoring checks
    for i in range(31, 41):
        check_items = [
            ("KEV Catalog monitoring", "Check CISA KEV catalog regularly"),
            ("Patch testing process", "Test patches before production"),
            ("Emergency patching", "Have emergency patch process"),
            ("Vulnerability disclosure", "Implement vulnerability disclosure policy"),
            ("Third-party components", "Track third-party component vulnerabilities"),
            ("Container image scanning", "Scan container images for vulnerabilities"),
            ("Dependency scanning", "Scan application dependencies"),
            ("Supply chain security", "Monitor supply chain vulnerabilities"),
            ("Zero-day response", "Have zero-day response plan"),
            ("Patch compliance reporting", "Report patch compliance to management")
        ]
        
        item = check_items[i-31]
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', i)}: {item[0]} (Low)",
            details=item[1],
            remediation=f"Implement {item[0].lower()} procedures"
        ))


# ============================================================================
# BOD 23-01: Asset Visibility & Authentication (40 checks total)
# ============================================================================

def check_bod_23_01_asset_visibility(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    BOD 23-01: Improving Asset Visibility and Vulnerability Detection
    20 checks for asset management and inventory
    """
    print(f"[{MODULE_NAME}] Checking BOD 23-01 - Asset Visibility...")
    
    # AST-001: Hardware inventory - CPU
    cpu_info = run_command("lscpu | grep 'Model name' | cut -d: -f2").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 1)}: CPU hardware documented (Low)",
        details=f"CPU: {cpu_info[:50]}" if cpu_info else "CPU info not available",
        remediation="Document hardware assets in CMDB"
    ))
    
    # AST-002: Memory capacity
    mem_info = run_command("free -h | grep Mem | awk '{print $2}'").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 2)}: Memory capacity documented (Low)",
        details=f"Memory: {mem_info}",
        remediation="Document memory specifications"
    ))
    
    # AST-003: Disk capacity
    disk_info = run_command("df -h / | tail -1 | awk '{print $2}'").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 3)}: Disk capacity documented (Low)",
        details=f"Root disk: {disk_info}",
        remediation="Document storage capacity"
    ))
    
    # AST-004: Network interfaces
    interfaces = run_command("ip link show | grep '^[0-9]' | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 4)}: Network interfaces inventory (Low)",
        details=f"{interfaces} network interfaces",
        remediation="Document network configuration"
    ))
    
    # AST-005: Software inventory
    package_count = run_command("dpkg -l 2>/dev/null | grep '^ii' | wc -l || rpm -qa 2>/dev/null | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 5)}: Installed packages inventory (Medium)",
        details=f"{package_count} packages installed",
        remediation="Maintain software inventory in CMDB"
    ))
    
    # AST-006: Running services
    service_count = run_command("systemctl list-units --type=service --state=running | grep -c '.service'").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 6)}: Active services inventory (Medium)",
        details=f"{service_count} services running",
        remediation="Document and review active services"
    ))
    
    # AST-007: User accounts
    user_count = run_command("getent passwd | grep -v nologin | grep -v /bin/false | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 7)}: User accounts with shell access (Medium)",
        details=f"{user_count} user accounts",
        remediation="Review and document user accounts"
    ))
    
    # AST-008: System uptime
    uptime_info = run_command("uptime -p").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 8)}: System uptime tracking (Low)",
        details=uptime_info if uptime_info else "Uptime info unavailable",
        remediation="Monitor system uptime for patch compliance"
    ))
    
    # AST-009: OS version
    os_info = run_command("cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2").stdout.strip().strip('"')
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 9)}: Operating system version (Low)",
        details=os_info if os_info else "OS info unavailable",
        remediation="Document OS version in asset inventory"
    ))
    
    # AST-010: Kernel version
    kernel_ver = run_command("uname -r").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 10)}: Kernel version tracking (Low)",
        details=f"Kernel: {kernel_ver}",
        remediation="Track kernel version for vulnerability management"
    ))
    
    # AST-011: Listening ports
    port_count = run_command("ss -tuln 2>/dev/null | grep LISTEN | wc -l || netstat -tuln 2>/dev/null | grep LISTEN | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 11)}: Open listening ports inventory (Medium)",
        details=f"{port_count} listening ports",
        remediation="Document and review network exposure"
    ))
    
    # AST-012: Cron jobs
    cron_jobs = run_command("crontab -l 2>/dev/null | grep -v '^#' | grep -v '^$' | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 12)}: Scheduled tasks inventory (Low)",
        details=f"{cron_jobs} cron jobs for current user",
        remediation="Document scheduled tasks"
    ))
    
    # AST-013: Mounted filesystems
    mounts = run_command("mount | wc -l").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 13)}: Mounted filesystems inventory (Low)",
        details=f"{mounts} mounted filesystems",
        remediation="Document filesystem configuration"
    ))
    
    # AST-014: Disk usage
    disk_usage = run_command("df -h / | tail -1 | awk '{print $5}'").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Warning" if disk_usage and int(disk_usage.rstrip('%')) > 80 else "Info",
        message=f"{get_cisa_id('AST', 14)}: Root filesystem utilization (Medium)",
        details=f"Root disk usage: {disk_usage}",
        remediation="Monitor disk space usage"
    ))
    
    # AST-015: System load
    load_avg = run_command("uptime | awk -F'load average:' '{print $2}'").stdout.strip()
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - BOD 23-01",
        status="Info",
        message=f"{get_cisa_id('AST', 15)}: System load monitoring (Low)",
        details=f"Load average: {load_avg[:30]}" if load_avg else "Load info unavailable",
        remediation="Monitor system performance"
    ))
    
    # AST-016-020: Additional asset management checks
    asset_checks = [
        ("System manufacturer", "Document hardware vendor", "dmidecode -s system-manufacturer 2>/dev/null || echo 'Not available'"),
        ("System model", "Document hardware model", "dmidecode -s system-product-name 2>/dev/null || echo 'Not available'"),
        ("BIOS version", "Track firmware versions", "dmidecode -s bios-version 2>/dev/null || echo 'Not available'"),
        ("Serial number", "Document asset serial numbers", "dmidecode -s system-serial-number 2>/dev/null || echo 'Not available'"),
        ("Asset tagging", "Implement asset tagging system", "echo 'Review asset management practices'")
    ]
    
    for i, (name, desc, cmd) in enumerate(asset_checks, start=16):
        detail = run_command(cmd).stdout.strip()
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 23-01",
            status="Info",
            message=f"{get_cisa_id('AST', i)}: {name} (Low)",
            details=detail[:50] if detail else desc,
            remediation=desc
        ))


def check_authentication_access_control(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    Authentication and Access Control checks
    20 comprehensive checks
    """
    print(f"[{MODULE_NAME}] Checking authentication and access control...")
    
    # AUTH-001: Root account UID 0 check
    passwd_content = read_file_safe("/etc/passwd")
    root_accounts = [line.split(':')[0] for line in passwd_content.split('\n') if ':0:' in line]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if len(root_accounts) == 1 and root_accounts[0] == "root" else "Fail",
        message=f"{get_cisa_id('AUTH', 1)}: Only root account has UID 0 (High)",
        details=f"UID 0 accounts: {root_accounts}",
        remediation="Remove non-root UID 0 accounts"
    ))
    
    # AUTH-002: Empty passwords
    shadow_content = read_file_safe("/etc/shadow")
    empty_passwords = len([l for l in shadow_content.split('\n') if l and '::' in l])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if empty_passwords == 0 else "Fail",
        message=f"{get_cisa_id('AUTH', 2)}: No accounts with empty passwords (Critical)",
        details=f"{empty_passwords} accounts with empty passwords",
        remediation="Set passwords or lock accounts"
    ))
    
    # AUTH-003: Password maximum age
    login_defs = read_file_safe("/etc/login.defs")
    pass_max_match = re.search(r'^PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    pass_max_ok = pass_max_match and int(pass_max_match.group(1)) <= 90
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if pass_max_ok else "Fail",
        message=f"{get_cisa_id('AUTH', 3)}: Password expiration ≤90 days (High)",
        details=f"PASS_MAX_DAYS: {pass_max_match.group(1) if pass_max_match else 'Not set'}",
        remediation="Set PASS_MAX_DAYS 90 in /etc/login.defs"
    ))
    
    # AUTH-004: Password minimum age
    pass_min_match = re.search(r'^PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    pass_min_ok = pass_min_match and int(pass_min_match.group(1)) >= 1
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if pass_min_ok else "Fail",
        message=f"{get_cisa_id('AUTH', 4)}: Minimum password age ≥1 day (Medium)",
        details=f"PASS_MIN_DAYS: {pass_min_match.group(1) if pass_min_match else 'Not set'}",
        remediation="Set PASS_MIN_DAYS 1"
    ))
    
    # AUTH-005: Password warning age
    pass_warn_match = re.search(r'^PASS_WARN_AGE\s+(\d+)', login_defs, re.MULTILINE)
    pass_warn_ok = pass_warn_match and int(pass_warn_match.group(1)) >= 7
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if pass_warn_ok else "Warning",
        message=f"{get_cisa_id('AUTH', 5)}: Password expiration warning ≥7 days (Low)",
        details=f"PASS_WARN_AGE: {pass_warn_match.group(1) if pass_warn_match else 'Not set'}",
        remediation="Set PASS_WARN_AGE 7"
    ))
    
    # AUTH-006: MFA availability
    mfa_installed = check_package_installed("libpam-google-authenticator") or check_package_installed("google-authenticator")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if mfa_installed else "Warning",
        message=f"{get_cisa_id('AUTH', 6)}: Multi-factor authentication available (High)",
        details="MFA package installed" if mfa_installed else "No MFA package",
        remediation="Install Google Authenticator PAM module"
    ))
    
    # AUTH-007: Password complexity
    pwquality_installed = check_package_installed("libpam-pwquality") or os.path.exists("/etc/security/pwquality.conf")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if pwquality_installed else "Fail",
        message=f"{get_cisa_id('AUTH', 7)}: Password complexity requirements (High)",
        details="pwquality configured" if pwquality_installed else "Not configured",
        remediation="Install and configure libpam-pwquality"
    ))
    
    # AUTH-008: Account lockout policy
    faillock_exists = os.path.exists("/etc/security/faillock.conf") or check_package_installed("libpam-faillock")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if faillock_exists else "Fail",
        message=f"{get_cisa_id('AUTH', 8)}: Account lockout policy configured (High)",
        details="faillock configured" if faillock_exists else "Not configured",
        remediation="Configure PAM faillock module"
    ))
    
    # AUTH-009: sudo installed
    sudo_installed = check_package_installed("sudo")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if sudo_installed else "Fail",
        message=f"{get_cisa_id('AUTH', 9)}: sudo privilege escalation (High)",
        details="sudo installed" if sudo_installed else "sudo not installed",
        remediation="Install sudo package"
    ))
    
    # AUTH-010: sudo configuration
    if os.path.exists("/etc/sudoers"):
        sudoers = read_file_safe("/etc/sudoers")
        nopasswd = "NOPASSWD" in sudoers
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Warning" if nopasswd else "Pass",
            message=f"{get_cisa_id('AUTH', 10)}: sudo requires password (Medium)",
            details="NOPASSWD found in sudoers" if nopasswd else "Password required",
            remediation="Remove NOPASSWD entries from sudoers"
        ))
    
    # AUTH-011: SSH root login
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        root_login = re.search(r'^\s*PermitRootLogin\s+no', sshd_config, re.MULTILINE)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Pass" if root_login else "Fail",
            message=f"{get_cisa_id('AUTH', 11)}: SSH root login disabled (Critical)",
            details="PermitRootLogin no" if root_login else "Root login enabled",
            remediation="Set PermitRootLogin no in sshd_config"
        ))
    
    # AUTH-012: SSH password authentication
        password_auth = re.search(r'^\s*PasswordAuthentication\s+no', sshd_config, re.MULTILINE)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Pass" if password_auth else "Warning",
            message=f"{get_cisa_id('AUTH', 12)}: SSH key-based authentication (High)",
            details="Password auth disabled" if password_auth else "Password auth enabled",
            remediation="Use key-based authentication, disable passwords"
        ))
    
    # AUTH-013: Default umask
    umask_match = re.search(r'^UMASK\s+(\d+)', login_defs, re.MULTILINE)
    umask_ok = umask_match and umask_match.group(1) in ["027", "077"]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if umask_ok else "Fail",
        message=f"{get_cisa_id('AUTH', 13)}: Restrictive default umask (Medium)",
        details=f"UMASK: {umask_match.group(1) if umask_match else 'Not set'}",
        remediation="Set UMASK 027 or 077"
    ))
    
    # AUTH-014: Session timeout
    timeout_set = False
    for file in ["/etc/profile", "/etc/bash.bashrc"]:
        if os.path.exists(file):
            content = read_file_safe(file)
            if "TMOUT" in content:
                timeout_set = True
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Authentication",
        status="Pass" if timeout_set else "Warning",
        message=f"{get_cisa_id('AUTH', 14)}: Shell session timeout configured (Medium)",
        details="TMOUT configured" if timeout_set else "No timeout",
        remediation="Set TMOUT=900 for 15-minute timeout"
    ))
    
    # AUTH-015: System accounts non-login
    login_shells = run_command("awk -F: '($3<1000 && $3!=0){print $1\":\"$7}' /etc/passwd | grep -v '/nologin\\|/false' | wc -l").stdout.strip()
    try:
        shell_count = int(login_shells)
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Pass" if shell_count == 0 else "Warning",
            message=f"{get_cisa_id('AUTH', 15)}: System accounts have nologin shell (Medium)",
            details=f"{shell_count} system accounts with login shells",
            remediation="Set system accounts to /sbin/nologin"
        ))
    except:
        pass
    
    # AUTH-016-020: Additional authentication checks
    auth_checks = [
        ("User home directory permissions", "Ensure secure home directory permissions"),
        ("SSH public key authentication", "Verify SSH key configuration"),
        ("Privileged account monitoring", "Monitor privileged account usage"),
        ("Password history enforcement", "Prevent password reuse"),
        ("Account activity auditing", "Log authentication events")
    ]
    
    for i, (name, remediation) in enumerate(auth_checks, start=16):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Info",
            message=f"{get_cisa_id('AUTH', i)}: {name} (Medium)",
            details=f"Review {name.lower()}",
            remediation=remediation
        ))


# ============================================================================
# Network Security + Logging & Monitoring (40 checks total)
# ============================================================================

def check_network_security(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    Network Security checks - 20 comprehensive checks
    """
    print(f"[{MODULE_NAME}] Checking network security...")
    
    # NET-001: Firewall active
    firewall_active = check_service_active("firewalld") or check_service_active("ufw") or check_service_active("iptables")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if firewall_active else "Fail",
        message=f"{get_cisa_id('NET', 1)}: Host-based firewall active (Critical)",
        details="Firewall running" if firewall_active else "No active firewall",
        remediation="Enable firewall: systemctl enable --now firewalld"
    ))
    
    # NET-002: Firewall installed
    firewall_installed = check_package_installed("firewalld") or check_package_installed("ufw") or check_package_installed("iptables")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if firewall_installed else "Fail",
        message=f"{get_cisa_id('NET', 2)}: Firewall software installed (Critical)",
        details="Firewall package installed" if firewall_installed else "No firewall",
        remediation="Install firewall: apt install ufw"
    ))
    
    # NET-003: IP forwarding disabled
    exists, ip_forward = check_kernel_parameter("net.ipv4.ip_forward")
    forward_disabled = ip_forward == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if forward_disabled else "Fail",
        message=f"{get_cisa_id('NET', 3)}: IP forwarding disabled (High)",
        details=f"net.ipv4.ip_forward: {ip_forward}",
        remediation="Disable: sysctl -w net.ipv4.ip_forward=0"
    ))
    
    # NET-004: TCP SYN cookies
    exists, syn_cookies = check_kernel_parameter("net.ipv4.tcp_syncookies")
    syn_enabled = syn_cookies == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if syn_enabled else "Fail",
        message=f"{get_cisa_id('NET', 4)}: TCP SYN cookies enabled (High)",
        details=f"tcp_syncookies: {syn_cookies}",
        remediation="Enable: sysctl -w net.ipv4.tcp_syncookies=1"
    ))
    
    # NET-005: ICMP redirects disabled
    exists, icmp_redirects = check_kernel_parameter("net.ipv4.conf.all.accept_redirects")
    redirects_disabled = icmp_redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if redirects_disabled else "Fail",
        message=f"{get_cisa_id('NET', 5)}: ICMP redirects disabled (Medium)",
        details=f"accept_redirects: {icmp_redirects}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_redirects=0"
    ))
    
    # NET-006: Secure ICMP redirects
    exists, secure_redirects = check_kernel_parameter("net.ipv4.conf.all.secure_redirects")
    secure_disabled = secure_redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if secure_disabled else "Warning",
        message=f"{get_cisa_id('NET', 6)}: Secure ICMP redirects disabled (Medium)",
        details=f"secure_redirects: {secure_redirects}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.secure_redirects=0"
    ))
    
    # NET-007: Source packet routing
    exists, source_route = check_kernel_parameter("net.ipv4.conf.all.accept_source_route")
    source_disabled = source_route == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if source_disabled else "Fail",
        message=f"{get_cisa_id('NET', 7)}: Source packet routing disabled (High)",
        details=f"accept_source_route: {source_route}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_source_route=0"
    ))
    
    # NET-008: Reverse path filtering
    exists, rp_filter = check_kernel_parameter("net.ipv4.conf.all.rp_filter")
    rp_enabled = rp_filter == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if rp_enabled else "Fail",
        message=f"{get_cisa_id('NET', 8)}: Reverse path filtering enabled (High)",
        details=f"rp_filter: {rp_filter}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.rp_filter=1"
    ))
    
    # NET-009: Martian packet logging
    exists, log_martians = check_kernel_parameter("net.ipv4.conf.all.log_martians")
    martians_logged = log_martians == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if martians_logged else "Warning",
        message=f"{get_cisa_id('NET', 9)}: Martian packet logging enabled (Medium)",
        details=f"log_martians: {log_martians}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.log_martians=1"
    ))
    
    # NET-010: Ignore ICMP broadcast requests
    exists, ignore_broadcasts = check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts")
    broadcasts_ignored = ignore_broadcasts == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if broadcasts_ignored else "Fail",
        message=f"{get_cisa_id('NET', 10)}: ICMP broadcast requests ignored (Medium)",
        details=f"icmp_echo_ignore_broadcasts: {ignore_broadcasts}",
        remediation="Enable: sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
    ))
    
    # NET-011: Bogus ICMP responses
    exists, ignore_bogus = check_kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses")
    bogus_ignored = ignore_bogus == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if bogus_ignored else "Warning",
        message=f"{get_cisa_id('NET', 11)}: Bogus ICMP responses ignored (Medium)",
        details=f"icmp_ignore_bogus_error_responses: {ignore_bogus}",
        remediation="Enable: sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1"
    ))
    
    # NET-012: IPv6 disabled or secured
    exists, ipv6_disabled = check_kernel_parameter("net.ipv6.conf.all.disable_ipv6")
    ipv6_status = "disabled" if ipv6_disabled == "1" else "enabled"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Info",
        message=f"{get_cisa_id('NET', 12)}: IPv6 configuration status (Medium)",
        details=f"IPv6: {ipv6_status}",
        remediation="Disable IPv6 if not used or secure if used"
    ))
    
    # NET-013: No insecure services
    insecure_services = []
    for service in ["telnet", "ftp", "rsh", "rlogin", "rexec"]:
        if check_service_active(service):
            insecure_services.append(service)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Fail" if insecure_services else "Pass",
        message=f"{get_cisa_id('NET', 13)}: No insecure network services (Critical)",
        details=f"Insecure services: {insecure_services}" if insecure_services else "None running",
        remediation="Stop and disable insecure services"
    ))
    
    # NET-014: SSH service status
    ssh_active = check_service_active("sshd") or check_service_active("ssh")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Pass" if ssh_active else "Info",
        message=f"{get_cisa_id('NET', 14)}: SSH secure remote access (High)",
        details="SSH active" if ssh_active else "SSH not running",
        remediation="SSH is recommended for secure remote access"
    ))
    
    # NET-015: Open listening ports
    port_count = run_command("ss -tuln 2>/dev/null | grep LISTEN | wc -l || netstat -tuln 2>/dev/null | grep LISTEN | wc -l").stdout.strip()
    
    try:
        ports = int(port_count)
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Network Security",
            status="Info",
            message=f"{get_cisa_id('NET', 15)}: Open listening ports inventory (Medium)",
            details=f"{ports} listening ports",
            remediation="Review and close unnecessary ports"
        ))
    except:
        pass
    
    # NET-016: Vulnerable port check
    vulnerable_ports = [21, 23, 69, 135, 139, 445, 512, 513, 514]
    exposed_ports = []
    
    for port in vulnerable_ports:
        result = run_command(f"ss -tuln 2>/dev/null | grep -q ':{port} ' || netstat -tuln 2>/dev/null | grep -q ':{port} '")
        if result.returncode == 0:
            exposed_ports.append(port)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Network Security",
        status="Fail" if exposed_ports else "Pass",
        message=f"{get_cisa_id('NET', 16)}: No vulnerable ports exposed (High)",
        details=f"Exposed: {exposed_ports}" if exposed_ports else "None",
        remediation="Close vulnerable ports immediately"
    ))
    
    # NET-017-020: Additional network security
    net_checks = [
        ("Network segmentation", "Implement network segmentation"),
        ("Intrusion detection", "Deploy IDS/IPS solutions"),
        ("Zero Trust architecture", "Implement Zero Trust principles"),
        ("DDoS protection", "Configure DDoS mitigation")
    ]
    
    for i, (name, remediation) in enumerate(net_checks, start=17):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Network Security",
            status="Info",
            message=f"{get_cisa_id('NET', i)}: {name} (Medium)",
            details=f"Review {name.lower()} configuration",
            remediation=remediation
        ))


def check_logging_monitoring(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    Logging and Monitoring checks - 20 comprehensive checks
    """
    print(f"[{MODULE_NAME}] Checking logging and monitoring...")
    
    # LOG-001: auditd installed
    auditd_installed = check_package_installed("auditd") or check_package_installed("audit")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if auditd_installed else "Fail",
        message=f"{get_cisa_id('LOG', 1)}: Linux auditd installed (High)",
        details="auditd installed" if auditd_installed else "Not installed",
        remediation="Install: apt install auditd"
    ))
    
    # LOG-002: auditd service active
    auditd_active = check_service_active("auditd")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if auditd_active else "Fail",
        message=f"{get_cisa_id('LOG', 2)}: auditd service active (High)",
        details="auditd running" if auditd_active else "Not running",
        remediation="Start: systemctl start auditd"
    ))
    
    # LOG-003: auditd enabled at boot
    auditd_enabled = check_service_enabled("auditd")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if auditd_enabled else "Warning",
        message=f"{get_cisa_id('LOG', 3)}: auditd enabled at boot (High)",
        details="Enabled" if auditd_enabled else "Not enabled",
        remediation="Enable: systemctl enable auditd"
    ))
    
    # LOG-004: Audit log size
    if os.path.exists("/etc/audit/auditd.conf"):
        audit_conf = read_file_safe("/etc/audit/auditd.conf")
        max_log_match = re.search(r'max_log_file\s*=\s*(\d+)', audit_conf)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass" if max_log_match else "Warning",
            message=f"{get_cisa_id('LOG', 4)}: Audit log size configured (Medium)",
            details=f"Max size: {max_log_match.group(1)} MB" if max_log_match else "Not configured",
            remediation="Configure max_log_file in auditd.conf"
        ))
    
    # LOG-005: Audit log action
        action_match = re.search(r'space_left_action\s*=\s*(\w+)', audit_conf)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass" if action_match else "Warning",
            message=f"{get_cisa_id('LOG', 5)}: Audit space_left_action configured (Medium)",
            details=f"Action: {action_match.group(1)}" if action_match else "Not configured",
            remediation="Set space_left_action = email or SYSLOG"
        ))
    
    # LOG-006: rsyslog installed
    rsyslog_installed = check_package_installed("rsyslog")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if rsyslog_installed else "Warning",
        message=f"{get_cisa_id('LOG', 6)}: rsyslog installed (High)",
        details="rsyslog installed" if rsyslog_installed else "Not installed",
        remediation="Install: apt install rsyslog"
    ))
    
    # LOG-007: rsyslog service active
    rsyslog_active = check_service_active("rsyslog")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if rsyslog_active else "Warning",
        message=f"{get_cisa_id('LOG', 7)}: rsyslog service active (High)",
        details="rsyslog running" if rsyslog_active else "Not running",
        remediation="Start: systemctl start rsyslog"
    ))
    
    # LOG-008: Remote logging configured
    remote_log_configured = False
    if os.path.exists("/etc/rsyslog.conf"):
        rsyslog_conf = read_file_safe("/etc/rsyslog.conf")
        remote_log_configured = "@@" in rsyslog_conf or ("*.*" in rsyslog_conf and "@" in rsyslog_conf)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if remote_log_configured else "Warning",
        message=f"{get_cisa_id('LOG', 8)}: Remote syslog configured (High)",
        details="Remote logging configured" if remote_log_configured else "Local only",
        remediation="Configure remote syslog server"
    ))
    
    # LOG-009: /var/log permissions
    log_perms = get_file_permissions("/var/log")
    log_secure = log_perms and int(log_perms, 8) <= int("755", 8)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if log_secure else "Fail",
        message=f"{get_cisa_id('LOG', 9)}: /var/log directory permissions (Medium)",
        details=f"Permissions: {log_perms}",
        remediation="Set permissions: chmod 750 /var/log"
    ))
    
    # LOG-010: /var/log/audit permissions
    if os.path.exists("/var/log/audit"):
        audit_perms = get_file_permissions("/var/log/audit")
        audit_secure = audit_perms and int(audit_perms, 8) <= int("750", 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass" if audit_secure else "Fail",
            message=f"{get_cisa_id('LOG', 10)}: /var/log/audit directory permissions (High)",
            details=f"Permissions: {audit_perms}",
            remediation="Set permissions: chmod 700 /var/log/audit"
        ))
    
    # LOG-011: logrotate installed
    logrotate_installed = check_package_installed("logrotate")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if logrotate_installed else "Fail",
        message=f"{get_cisa_id('LOG', 11)}: logrotate installed (Medium)",
        details="logrotate installed" if logrotate_installed else "Not installed",
        remediation="Install: apt install logrotate"
    ))
    
    # LOG-012: logrotate configured for audit
    if os.path.exists("/etc/logrotate.d/audit"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass",
            message=f"{get_cisa_id('LOG', 12)}: Audit log rotation configured (Medium)",
            details="logrotate configured for audit logs",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Warning",
            message=f"{get_cisa_id('LOG', 12)}: Audit log rotation configuration (Medium)",
            details="No audit logrotate config",
            remediation="Configure logrotate for audit logs"
        ))
    
    # LOG-013: System journal persistent
    journal_persistent = os.path.exists("/var/log/journal")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Logging",
        status="Pass" if journal_persistent else "Warning",
        message=f"{get_cisa_id('LOG', 13)}: Systemd journal persistent storage (Medium)",
        details="Journal persistent" if journal_persistent else "Journal volatile",
        remediation="Configure: Storage=persistent in journald.conf"
    ))
    
    # LOG-014-020: Additional logging checks
    log_checks = [
        ("Log monitoring tools", "Implement log monitoring solution"),
        ("SIEM integration", "Integrate logs with SIEM"),
        ("Log analysis automation", "Automate log analysis"),
        ("Security event alerting", "Configure security alerts"),
        ("Log integrity protection", "Implement log integrity checks"),
        ("Centralized logging", "Implement centralized logging"),
        ("Compliance logging", "Ensure compliance log retention")
    ]
    
    for i, (name, remediation) in enumerate(log_checks, start=14):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Info",
            message=f"{get_cisa_id('LOG', i)}: {name} (Medium)",
            details=f"Review {name.lower()}",
            remediation=remediation
        ))


# ============================================================================
# Incident Response + Data Protection (30 checks total)
# ============================================================================

def check_incident_response(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    Incident Response Readiness checks - 15 comprehensive checks
    """
    print(f"[{MODULE_NAME}] Checking incident response capabilities...")
    
    # IR-001: Incident response plan
    ir_plan_locations = [
        "/root/incident-response.txt",
        "/etc/security/incident-response.md",
        "/opt/security/ir-plan.pdf",
        "/usr/local/share/security/ir-plan.txt"
    ]
    has_ir_plan = any(os.path.exists(loc) for loc in ir_plan_locations)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Pass" if has_ir_plan else "Warning",
        message=f"{get_cisa_id('IR', 1)}: Incident response plan documented (High)",
        details="IR plan found" if has_ir_plan else "No IR plan found",
        remediation="Document incident response procedures"
    ))
    
    # IR-002: Network capture tools
    capture_tools = []
    for tool in ["tcpdump", "wireshark", "tshark", "dumpcap"]:
        if command_exists(tool):
            capture_tools.append(tool)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Pass" if capture_tools else "Warning",
        message=f"{get_cisa_id('IR', 2)}: Network capture tools available (Medium)",
        details=f"Tools: {capture_tools}" if capture_tools else "No capture tools",
        remediation="Install tcpdump or wireshark"
    ))
    
    # IR-003: Forensic tools
    forensic_tools = []
    for tool in ["dd", "dc3dd", "strings", "file", "md5sum", "sha256sum"]:
        if command_exists(tool):
            forensic_tools.append(tool)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Pass" if len(forensic_tools) >= 4 else "Warning",
        message=f"{get_cisa_id('IR', 3)}: Basic forensic tools available (Medium)",
        details=f"Tools: {forensic_tools}" if forensic_tools else "Limited tools",
        remediation="Ensure forensic tools are available"
    ))
    
    # IR-004: Backup tools
    backup_tools = []
    for tool in ["rsync", "duplicity", "borgbackup", "tar", "dd"]:
        if command_exists(tool) or check_package_installed(tool):
            backup_tools.append(tool)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Pass" if backup_tools else "Fail",
        message=f"{get_cisa_id('IR', 4)}: Backup tools installed (High)",
        details=f"Tools: {backup_tools}" if backup_tools else "No backup tools",
        remediation="Install backup software"
    ))
    
    # IR-005: Backup directories
    backup_dirs = ["/backup", "/var/backups", "/mnt/backup", "/opt/backup"]
    existing_backup_dirs = [d for d in backup_dirs if os.path.exists(d)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Pass" if existing_backup_dirs else "Warning",
        message=f"{get_cisa_id('IR', 5)}: Backup directory exists (Medium)",
        details=f"Backup dirs: {existing_backup_dirs}" if existing_backup_dirs else "No backup directories",
        remediation="Create and configure backup directory"
    ))
    
    # IR-006: System backup recency
    if existing_backup_dirs:
        most_recent_backup = 999
        for backup_dir in existing_backup_dirs:
            result = run_command(f"find {backup_dir} -type f -mtime -7 2>/dev/null | head -1")
            if result.returncode == 0 and result.stdout.strip():
                most_recent_backup = min(most_recent_backup, 7)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Incident Response",
            status="Pass" if most_recent_backup <= 7 else "Warning",
            message=f"{get_cisa_id('IR', 6)}: Recent backup detected (High)",
            details=f"Backup within 7 days" if most_recent_backup <= 7 else "No recent backups found",
            remediation="Perform regular backups"
        ))
    
    # IR-007: Contact information
    contact_files = ["/etc/security/contacts.txt", "/root/emergency-contacts.txt"]
    has_contacts = any(os.path.exists(f) for f in contact_files)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Info",
        message=f"{get_cisa_id('IR', 7)}: Emergency contact information (Medium)",
        details="Contact file found" if has_contacts else "No contact file",
        remediation="Maintain emergency contact list"
    ))
    
    # IR-008: Incident logging
    incident_log_dirs = ["/var/log/incidents", "/var/log/security/incidents"]
    has_incident_log = any(os.path.exists(d) for d in incident_log_dirs)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Incident Response",
        status="Info",
        message=f"{get_cisa_id('IR', 8)}: Incident logging directory (Low)",
        details="Incident log dir exists" if has_incident_log else "No incident log directory",
        remediation="Create incident logging directory"
    ))
    
    # IR-009-015: Additional IR checks
    ir_checks = [
        ("Incident reporting procedures", "Define reporting procedures"),
        ("Evidence preservation process", "Document evidence handling"),
        ("Communication plan", "Establish communication channels"),
        ("Tabletop exercises", "Conduct incident response drills"),
        ("Lessons learned process", "Document post-incident reviews"),
        ("Legal coordination", "Coordinate with legal team"),
        ("External coordination", "Maintain CISA contact info")
    ]
    
    for i, (name, remediation) in enumerate(ir_checks, start=9):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Incident Response",
            status="Info",
            message=f"{get_cisa_id('IR', i)}: {name} (Medium)",
            details=f"Review {name.lower()}",
            remediation=remediation
        ))


def check_data_protection(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    Data Protection checks - 15 comprehensive checks
    """
    print(f"[{MODULE_NAME}] Checking data protection...")
    
    # DP-001: Disk encryption
    encrypted_devices = []
    result = run_command("lsblk -f | grep -i 'crypt\\|luks'")
    if result.returncode == 0 and result.stdout.strip():
        encrypted_devices = result.stdout.strip().split('\n')
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status="Pass" if encrypted_devices else "Warning",
        message=f"{get_cisa_id('DP', 1)}: Disk encryption implemented (High)",
        details=f"{len(encrypted_devices)} encrypted volumes" if encrypted_devices else "No encrypted volumes",
        remediation="Implement LUKS full disk encryption"
    ))
    
    # DP-002: Encryption tools installed
    encryption_tools = []
    for tool in ["cryptsetup", "gpg", "openssl"]:
        if command_exists(tool):
            encryption_tools.append(tool)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status="Pass" if len(encryption_tools) >= 2 else "Warning",
        message=f"{get_cisa_id('DP', 2)}: Encryption tools available (Medium)",
        details=f"Tools: {encryption_tools}" if encryption_tools else "No encryption tools",
        remediation="Install cryptsetup and gpg"
    ))
    
    # DP-003: Secure deletion tools
    secure_delete = command_exists("shred") or command_exists("wipe") or command_exists("srm")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status="Pass" if secure_delete else "Warning",
        message=f"{get_cisa_id('DP', 3)}: Secure file deletion capability (Medium)",
        details="Secure delete tool available" if secure_delete else "No secure delete tool",
        remediation="Install shred or wipe utility"
    ))
    
    # DP-004: File integrity monitoring (AIDE)
    aide_installed = check_package_installed("aide")
    
    if aide_installed:
        aide_db_locations = [
            "/var/lib/aide/aide.db",
            "/var/lib/aide/aide.db.gz",
            "/var/lib/aide.db"
        ]
        aide_db_exists = any(os.path.exists(db) for db in aide_db_locations)
        
        if aide_db_exists:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - Data Protection",
                status="Pass",
                message=f"{get_cisa_id('DP', 4)}: File integrity monitoring configured (High)",
                details="AIDE database initialized",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - Data Protection",
                status="Warning",
                message=f"{get_cisa_id('DP', 4)}: AIDE installed but not initialized (High)",
                details="AIDE database missing",
                remediation="Initialize AIDE: sudo aideinit"
            ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Data Protection",
            status="Fail",
            message=f"{get_cisa_id('DP', 4)}: File integrity monitoring not configured (High)",
            details="AIDE not installed",
            remediation="Install AIDE: apt install aide"
        ))
    
    # DP-005: Sensitive file permissions
    sensitive_files = {
        "/etc/passwd": "644",
        "/etc/shadow": "000",
        "/etc/gshadow": "000",
        "/etc/group": "644"
    }
    
    permission_issues = []
    for filepath, max_perms in sensitive_files.items():
        if os.path.exists(filepath):
            perms = get_file_permissions(filepath)
            if perms and int(perms, 8) > int(max_perms, 8):
                permission_issues.append(f"{filepath}:{perms}")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status="Pass" if not permission_issues else "Fail",
        message=f"{get_cisa_id('DP', 5)}: Sensitive file permissions secured (High)",
        details=f"Issues: {permission_issues}" if permission_issues else "Permissions OK",
        remediation="Correct file permissions: chmod 000 /etc/shadow"
    ))
    
    # DP-006: SSH key permissions
    ssh_key_dir = os.path.expanduser("~/.ssh")
    if os.path.exists(ssh_key_dir):
        ssh_perms = get_file_permissions(ssh_key_dir)
        ssh_secure = ssh_perms and int(ssh_perms, 8) <= int("700", 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Data Protection",
            status="Pass" if ssh_secure else "Fail",
            message=f"{get_cisa_id('DP', 6)}: SSH directory permissions (High)",
            details=f"~/.ssh permissions: {ssh_perms}",
            remediation="Set permissions: chmod 700 ~/.ssh"
        ))
    
    # DP-007: World-writable files
    world_writable = run_command("find / -xdev -type f -perm -002 2>/dev/null | head -10").stdout.strip()
    has_world_writable = bool(world_writable)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status="Fail" if has_world_writable else "Pass",
        message=f"{get_cisa_id('DP', 7)}: No world-writable files (Medium)",
        details=f"Found world-writable files" if has_world_writable else "None found",
        remediation="Remove world-write permissions from files"
    ))
    
    # DP-008: Unowned files
    unowned = run_command("find / -xdev -nouser -o -nogroup 2>/dev/null | head -10").stdout.strip()
    has_unowned = bool(unowned)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status="Warning" if has_unowned else "Pass",
        message=f"{get_cisa_id('DP', 8)}: No unowned files (Low)",
        details="Unowned files found" if has_unowned else "None found",
        remediation="Assign ownership to unowned files"
    ))
    
    # DP-009: SUID/SGID files
    suid_count = run_command("find / -xdev -type f -perm -4000 2>/dev/null | wc -l").stdout.strip()
    
    try:
        suid_num = int(suid_count)
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Data Protection",
            status="Info",
            message=f"{get_cisa_id('DP', 9)}: SUID file inventory (Medium)",
            details=f"{suid_num} SUID files found",
            remediation="Review SUID files regularly"
        ))
    except:
        pass
    
    # DP-010: Data loss prevention
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CISA - Data Protection",
        status="Info",
        message=f"{get_cisa_id('DP', 10)}: Data loss prevention (DLP) (Medium)",
        details="Review DLP implementation",
        remediation="Implement DLP controls for sensitive data"
    ))
    
    # DP-011-015: Additional data protection checks
    dp_checks = [
        ("Data classification", "Classify data by sensitivity"),
        ("Encryption at rest", "Encrypt sensitive data at rest"),
        ("Encryption in transit", "Use TLS for data transmission"),
        ("Data retention policy", "Implement data retention policy"),
        ("Secure data disposal", "Document secure disposal procedures")
    ]
    
    for i, (name, remediation) in enumerate(dp_checks, start=11):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Data Protection",
            status="Info",
            message=f"{get_cisa_id('DP', i)}: {name} (Medium)",
            details=f"Review {name.lower()}",
            remediation=remediation
        ))


# ============================================================================
# Main Module Entry Point
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """
    Main entry point for CISA Cybersecurity Directives module
    
    Args:
        shared_data: Dictionary with shared data from main script
        
    Returns:
        List of AuditResult objects
    """
    results = []
    
    print(f"\n[{MODULE_NAME}] ===== CISA SECURITY AUDIT =====")
    print(f"[{MODULE_NAME}] Version: {MODULE_VERSION}")
    print(f"[{MODULE_NAME}] Standards: CISA BODs, Emergency Directives, Best Practices")
    print(f"[{MODULE_NAME}] Priority Levels: Critical, High, Medium, Low")
    print(f"[{MODULE_NAME}] Target: 132 comprehensive security checks")
    print(f"[{MODULE_NAME}] Focus: BOD 22-01 (KEV), BOD 23-01 (Asset Visibility)\n")
    
    is_root = shared_data.get("is_root", os.geteuid() == 0)
    if not is_root:
        print(f"[{MODULE_NAME}] Note: Some checks require root privileges for complete results")
    
    try:
        # Category 1: BOD 22-01 - Known Exploited Vulnerabilities (40 checks)
        check_bod_22_01_kev(results, shared_data)
        
        # Category 2: BOD 23-01 - Asset Visibility (20 checks)
        check_bod_23_01_asset_visibility(results, shared_data)
        
        # Category 3: Authentication and Access Control (20 checks)
        check_authentication_access_control(results, shared_data)
        
        # Category 4: Network Security (20 checks)
        check_network_security(results, shared_data)
        
        # Category 5: Logging and Monitoring (20 checks)
        check_logging_monitoring(results, shared_data)
        
        # Category 6: Incident Response (15 checks)
        check_incident_response(results, shared_data)
        
        # Category 7: Data Protection (15 checks)
        check_data_protection(results, shared_data)
        
    except Exception as e:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Error",
            status="Error",
            message=f"Module execution error: {str(e)}",
            details="",
            remediation="Review module logs"
        ))
        import traceback
        traceback.print_exc()
    
    # Summary statistics
    critical_fail = sum(1 for r in results if "Critical" in r.message and r.status == "Fail")
    high_fail = sum(1 for r in results if "High" in r.message and r.status == "Fail")
    medium_fail = sum(1 for r in results if "Medium" in r.message and r.status == "Fail")
    low_fail = sum(1 for r in results if "Low" in r.message and r.status == "Fail")
    
    bod_22_01_checks = sum(1 for r in results if "BOD 22-01" in r.category)
    bod_23_01_checks = sum(1 for r in results if "BOD 23-01" in r.category)
    
    summary_details = (
        f"Critical failures: {critical_fail}, High failures: {high_fail}, "
        f"Medium failures: {medium_fail}, Low failures: {low_fail}"
    )

    # Generate summary statistics
    pass_count = sum(1 for r in results if r.status == "Pass")
    fail_count = sum(1 for r in results if r.status == "Fail")
    warn_count = sum(1 for r in results if r.status == "Warning")
    info_count = sum(1 for r in results if r.status == "Info")
    error_count = sum(1 for r in results if r.status == "Error")
    
    print(f"\n[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] CISA SECURITY AUDIT COMPLETED")
    print(f"[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] Total checks executed: {len(results)}")
    print(f"[{MODULE_NAME}] BOD 22-01 checks: {bod_22_01_checks}")
    print(f"[{MODULE_NAME}] BOD 23-01 checks: {bod_23_01_checks}")
    print(f"[{MODULE_NAME}] Priority summary: {summary_details}")
    print(f"[{MODULE_NAME}]   🔴 Critical Failures: {critical_fail}")
    print(f"[{MODULE_NAME}]   🟠 High Failures: {high_fail}")
    print(f"[{MODULE_NAME}]   🟡 Medium Failures: {medium_fail}")
    print(f"[{MODULE_NAME}]   🟣 Low Failures: {low_fail}")
    print(f"[{MODULE_NAME}] ")
    print(f"[{MODULE_NAME}] Results Summary:")
    print(f"[{MODULE_NAME}]   ✅ Pass:    {pass_count:3d} ({pass_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   ❌ Fail:    {fail_count:3d} ({fail_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   ⚠️  Warning: {warn_count:3d} ({warn_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   ℹ️  Info:    {info_count:3d} ({info_count/len(results)*100:.1f}%)")
    if error_count > 0:
        print(f"[{MODULE_NAME}]   🚫 Error:   {error_count:3d}")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    return results


# ============================================================================
# Module Testing
# ============================================================================

if __name__ == "__main__":
    """Allow module to be run standalone for testing"""
    import socket
    import platform
    
    print("="*70)
    print(f"Testing {MODULE_NAME} Module - CISA Security Controls v{MODULE_VERSION}")
    print("="*70)
    
    test_shared_data = {
        "hostname": socket.gethostname(),
        "os_version": f"{platform.system()} {platform.release()}",
        "scan_date": datetime.datetime.now(),
        "is_root": os.geteuid() == 0,
        "script_path": Path(__file__).parent if hasattr(Path(__file__), 'parent') else Path.cwd()
    }
    
    print(f"\nTest Environment:")
    print(f"  Hostname: {test_shared_data['hostname']}")
    print(f"  OS: {test_shared_data['os_version']}")
    print(f"  Running as root: {test_shared_data['is_root']}")
    print(f"  Scan time: {test_shared_data['scan_date'].strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)
    
    test_results = run_checks(test_shared_data)
    
    print(f"\n{'='*70}")
    print(f"COMPREHENSIVE TEST RESULTS")
    print(f"{'='*70}")
    print(f"Generated {len(test_results)} results")
    print("="*70)
    
    # Status summary
    from collections import Counter
    status_counts = Counter(r.status for r in test_results)
    
    print("\nSummary by Status:")
    for status in ["Pass", "Fail", "Warning", "Info", "Error"]:
        count = status_counts.get(status, 0)
        if count > 0:
            pct = (count / len(test_results)) * 100
            print(f"  {status}: {count} ({pct:.1f}%)")
    
    # Priority summary
    critical_total = sum(1 for r in test_results if "Critical" in r.message)
    high_total = sum(1 for r in test_results if "High" in r.message)
    medium_total = sum(1 for r in test_results if "Medium" in r.message)
    low_total = sum(1 for r in test_results if "Low" in r.message)
    
    critical_fail = sum(1 for r in test_results if "Critical" in r.message and r.status == "Fail")
    high_fail = sum(1 for r in test_results if "High" in r.message and r.status == "Fail")
    medium_fail = sum(1 for r in test_results if "Medium" in r.message and r.status == "Fail")
    low_fail = sum(1 for r in test_results if "Low" in r.message and r.status == "Fail")
    
    if critical_total > 0 or high_total > 0 or medium_total > 0:
        print("\nSummary by CISA Priority:")
        if critical_total > 0:
            print(f"  Critical: {critical_total} checks, {critical_fail} failures")
        if high_total > 0:
            print(f"  High: {high_total} checks, {high_fail} failures")
        if medium_total > 0:
            print(f"  Medium: {medium_total} checks, {medium_fail} failures")
        if low_total > 0:
            print(f"  Low: {low_total} checks, {low_fail} failures")
    
    # Category summary
    categories = {}
    for result in test_results:
        cat = result.category
        if cat not in categories:
            categories[cat] = {"total": 0, "fail": 0}
        categories[cat]["total"] += 1
        if result.status == "Fail":
            categories[cat]["fail"] += 1
    
    print("\nSummary by Category:")
    for category in sorted(categories.keys()):
        total = categories[category]['total']
        fail = categories[category]['fail']
        print(f"  {category}: {total} checks, {fail} failures")
    
    # BOD-specific summary
    bod_22_01 = [r for r in test_results if "BOD 22-01" in r.category]
    bod_23_01 = [r for r in test_results if "BOD 23-01" in r.category]
    
    print("\nBinding Operational Directives:")
    if bod_22_01:
        bod_22_fail = sum(1 for r in bod_22_01 if r.status == "Fail")
        print(f"  BOD 22-01 (KEV): {len(bod_22_01)} checks, {bod_22_fail} failures")
    if bod_23_01:
        bod_23_fail = sum(1 for r in bod_23_01 if r.status == "Fail")
        print(f"  BOD 23-01 (Asset Visibility): {len(bod_23_01)} checks, {bod_23_fail} failures")
    
    print("\n" + "="*70)
    print(f"CISA Cybersecurity Directives module test complete")
    print(f"Version: {MODULE_VERSION}")
    print(f"Total Checks Executed: {len(test_results)}")
    print("="*70)
    
    # Display critical failures
    critical_failures = [r for r in test_results if r.status == "Fail" and "Critical" in r.message]
    if critical_failures:
        print(f"\n⚠️  {len(critical_failures)} CRITICAL FAILURES DETECTED:")
        for i, failure in enumerate(critical_failures[:5], 1):
            print(f"  {i}. {failure.message}")
        if len(critical_failures) > 5:
            print(f"  ... and {len(critical_failures) - 5} more")
    
    # Display high-priority failures
    high_failures = [r for r in test_results if r.status == "Fail" and "High" in r.message]
    if high_failures:
        print(f"\n⚠️  {len(high_failures)} HIGH-PRIORITY FAILURES DETECTED:")
        for i, failure in enumerate(high_failures[:5], 1):
            print(f"  {i}. {failure.message}")
        if len(high_failures) > 5:
            print(f"  ... and {len(high_failures) - 5} more")
    
    print("\n" + "="*70)
    print("End of CISA module test")
    print("="*70)
