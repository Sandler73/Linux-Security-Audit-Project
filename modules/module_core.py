#!/usr/bin/env python3
"""
module_core.py
Core Security Baseline Module for Linux
Version: 1.1

SYNOPSIS:
    Comprehensive baseline security assessment for Linux systems based on
    industry best practices and OS-specific security guidance.

DESCRIPTION:
    This module performs thorough security checks with dynamic OS detection:
    
    Core Security Baseline:
    - OS Detection & Version Management
    - Package Management Security (OS-specific)
    - Service Management & Hardening
    - User & Group Security
    - Filesystem Security & Permissions
    - Network Configuration Baseline
    - Process & Memory Security
    - System Updates & Patch Management
    - Security Tools & Monitoring
    
    OS-Specific Coverage:
    - Debian-based: Ubuntu, Debian, Linux Mint, Kali Linux
      * Based on Debian Security Advisory (DSA)
      * Ubuntu Security Notices (USN)
      * APT security configuration
    
    - RedHat-based: RHEL, Fedora, CentOS, Rocky, AlmaLinux
      * Based on Red Hat Security Advisory (RHSA)
      * Red Hat Customer Portal security guidance
      * YUM/DNF security configuration
    
    Key Standards Referenced:
    - CIS Benchmarks (OS-specific sections)
    - Linux Foundation security best practices
    - Debian Security Manual
    - Red Hat Enterprise Linux Security Guide
    - Ubuntu Server Guide Security section

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

USAGE:
    Standalone testing
        python3 module_core.py

    Integration with main audit script
        python3 linux_security_audit.py --modules CORE
        python3 linux_security_audit.py -m CORE

NOTES:
    Version: 1.1
    Focus: Industry best practices with OS-specific optimizations
    Target: 150+ comprehensive, OS-aware security checks
    
    OS Detection Methods:
    - /etc/os-release parsing
    - Distribution-specific files
    - Package manager detection
    - Kernel and init system detection
"""

import os
import sys
import re
import subprocess
import pwd
import grp
import glob
import socket
import platform
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

# Import AuditResult from main script
sys.path.insert(0, str(Path(__file__).parent.parent))
from linux_security_audit import AuditResult

MODULE_NAME = "CORE"
MODULE_VERSION = "1.1"

# ============================================================================
# OS Detection and Classification
# ============================================================================

class OSInfo:
    """Store and manage OS information"""
    def __init__(self):
        self.family = "Unknown"  # debian, redhat, suse, arch, unknown
        self.distro = "Unknown"  # ubuntu, debian, rhel, centos, fedora, etc.
        self.version = "Unknown"
        self.version_id = "Unknown"
        self.codename = "Unknown"
        self.package_manager = "Unknown"  # apt, yum, dnf, zypper, pacman
        self.init_system = "Unknown"  # systemd, sysvinit, upstart
        self.architecture = platform.machine()
        self.kernel_version = platform.release()
        
    def __str__(self):
        return f"{self.distro} {self.version} ({self.family})"

def detect_os() -> OSInfo:
    """
    Comprehensive OS detection
    Returns OSInfo object with detailed system information
    """
    os_info = OSInfo()
    
    # Read /etc/os-release (standard location)
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release", 'r') as f:
            os_release = {}
            for line in f:
                if '=' in line:
                    key, value = line.strip().split('=', 1)
                    os_release[key] = value.strip('"')
        
        os_info.distro = os_release.get('ID', 'unknown').lower()
        os_info.version = os_release.get('VERSION', 'unknown')
        os_info.version_id = os_release.get('VERSION_ID', 'unknown')
        os_info.codename = os_release.get('VERSION_CODENAME', 'unknown')
        
        # Determine OS family
        id_like = os_release.get('ID_LIKE', '').lower()
        if os_info.distro in ['ubuntu', 'debian', 'linuxmint', 'kali'] or 'debian' in id_like:
            os_info.family = 'debian'
        elif os_info.distro in ['rhel', 'centos', 'fedora', 'rocky', 'almalinux'] or 'rhel' in id_like or 'fedora' in id_like:
            os_info.family = 'redhat'
        elif os_info.distro in ['sles', 'opensuse'] or 'suse' in id_like:
            os_info.family = 'suse'
        elif os_info.distro == 'arch':
            os_info.family = 'arch'
    
    # Fallback detection methods
    if os_info.family == "Unknown":
        if os.path.exists("/etc/debian_version"):
            os_info.family = 'debian'
            os_info.distro = 'debian'
        elif os.path.exists("/etc/redhat-release"):
            os_info.family = 'redhat'
            with open("/etc/redhat-release", 'r') as f:
                content = f.read().lower()
                if 'centos' in content:
                    os_info.distro = 'centos'
                elif 'red hat' in content or 'rhel' in content:
                    os_info.distro = 'rhel'
                elif 'fedora' in content:
                    os_info.distro = 'fedora'
    
    # Detect package manager
    if command_exists('apt-get'):
        os_info.package_manager = 'apt'
    elif command_exists('dnf'):
        os_info.package_manager = 'dnf'
    elif command_exists('yum'):
        os_info.package_manager = 'yum'
    elif command_exists('zypper'):
        os_info.package_manager = 'zypper'
    elif command_exists('pacman'):
        os_info.package_manager = 'pacman'
    
    # Detect init system
    if os.path.exists("/run/systemd/system"):
        os_info.init_system = 'systemd'
    elif os.path.exists("/sbin/init") and os.path.islink("/sbin/init"):
        link = os.readlink("/sbin/init")
        if 'systemd' in link:
            os_info.init_system = 'systemd'
        elif 'upstart' in link:
            os_info.init_system = 'upstart'
    else:
        os_info.init_system = 'sysvinit'
    
    return os_info

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

def check_package_installed(package_name: str, os_info: OSInfo) -> bool:
    """Check if a package is installed (OS-aware)"""
    if os_info.package_manager == 'apt':
        result = run_command(f"dpkg -l {package_name} 2>/dev/null | grep -q '^ii'")
        return result.returncode == 0
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command(f"rpm -q {package_name} 2>/dev/null")
        return result.returncode == 0
    elif os_info.package_manager == 'zypper':
        result = run_command(f"rpm -q {package_name} 2>/dev/null")
        return result.returncode == 0
    elif os_info.package_manager == 'pacman':
        result = run_command(f"pacman -Q {package_name} 2>/dev/null")
        return result.returncode == 0
    return False

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

def get_core_id(category: str, number: int) -> str:
    """Generate CORE control ID"""
    return f"CORE-{category}-{number:03d}"

def safe_int_parse(value: str, default: int = 0) -> int:
    """
    Safely parse a string to integer
    """
    try:
        if not value:
            return default
        clean_value = value.strip().split('\n')[0].strip()
        if clean_value and clean_value.isdigit():
            return int(clean_value)
        # Handle negative numbers
        if clean_value.startswith('-') and clean_value[1:].isdigit():
            return int(clean_value)
        return default
    except (ValueError, AttributeError):
        return default

def get_available_updates(os_info: OSInfo) -> int:
    """Get count of available updates (OS-specific)"""
    if os_info.package_manager == 'apt':
        # Update cache first
        run_command("apt-get update 2>/dev/null", check=False)
        result = run_command("apt list --upgradable 2>/dev/null | grep -c upgradable")
        return max(0, safe_int_parse(result.stdout.strip()) - 1)  # Subtract header line
    elif os_info.package_manager == 'dnf':
        result = run_command("dnf check-update --quiet 2>/dev/null | grep -v '^$' | wc -l")
        return safe_int_parse(result.stdout.strip())
    elif os_info.package_manager == 'yum':
        result = run_command("yum check-update --quiet 2>/dev/null | grep -v '^$' | wc -l")
        return safe_int_parse(result.stdout.strip())
    return 0

def get_security_updates(os_info: OSInfo) -> int:
    """Get count of security updates (OS-specific)"""
    if os_info.package_manager == 'apt':
        result = run_command("apt list --upgradable 2>/dev/null | grep -ci security")
        return safe_int_parse(result.stdout.strip())
    elif os_info.package_manager in ['dnf', 'yum']:
        cmd = os_info.package_manager
        result = run_command(f"{cmd} updateinfo list security 2>/dev/null | wc -l")
        return safe_int_parse(result.stdout.strip())
    return 0

def get_last_update_time(os_info: OSInfo) -> Optional[int]:
    """Get days since last update (OS-specific)"""
    import time
    
    if os_info.package_manager == 'apt':
        log_files = [
            "/var/log/apt/history.log",
            "/var/log/dpkg.log"
        ]
    elif os_info.package_manager in ['yum', 'dnf']:
        log_files = [
            "/var/log/yum.log",
            "/var/log/dnf.log"
        ]
    else:
        return None
    
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                mtime = os.path.getmtime(log_file)
                days = int((time.time() - mtime) / 86400)
                return days
            except:
                continue
    
    return None

def get_repositories(os_info: OSInfo) -> List[str]:
    """Get configured repositories (OS-specific)"""
    repos = []
    
    if os_info.package_manager == 'apt':
        # Check sources.list
        if os.path.exists("/etc/apt/sources.list"):
            content = read_file_safe("/etc/apt/sources.list")
            for line in content.split('\n'):
                if line.strip() and not line.strip().startswith('#'):
                    if line.startswith('deb'):
                        repos.append(line.split()[1])
        
        # Check sources.list.d
        for source_file in glob.glob("/etc/apt/sources.list.d/*.list"):
            content = read_file_safe(source_file)
            for line in content.split('\n'):
                if line.strip() and not line.strip().startswith('#'):
                    if line.startswith('deb'):
                        repos.append(line.split()[1])
    
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command(f"{os_info.package_manager} repolist 2>/dev/null | grep -v '^repo id' | awk '{{print $1}}'")
        if result.returncode == 0:
            repos = [r.strip() for r in result.stdout.split('\n') if r.strip()]
    
    return repos

def check_selinux_status() -> Dict[str, Any]:
    """Get SELinux status (relevant for RedHat-based systems)"""
    status = {
        'installed': False,
        'enabled': False,
        'enforcing': False,
        'mode': 'disabled'
    }
    
    if os.path.exists("/etc/selinux/config") or command_exists("getenforce"):
        status['installed'] = True
    
    if command_exists("getenforce"):
        result = run_command("getenforce")
        if result.returncode == 0:
            mode = result.stdout.strip().lower()
            status['mode'] = mode
            status['enabled'] = mode in ['enforcing', 'permissive']
            status['enforcing'] = mode == 'enforcing'
    
    return status

def check_apparmor_status() -> Dict[str, Any]:
    """Get AppArmor status (relevant for Debian-based systems)"""
    status = {
        'installed': False,
        'enabled': False,
        'profiles_loaded': 0,
        'profiles_enforcing': 0
    }
    
    if check_service_active("apparmor"):
        status['installed'] = True
        status['enabled'] = True
        
        if command_exists("apparmor_status"):
            result = run_command("apparmor_status 2>/dev/null")
            if result.returncode == 0:
                loaded = re.search(r'(\d+) profiles are loaded', result.stdout)
                enforcing = re.search(r'(\d+) profiles are in enforce mode', result.stdout)
                
                if loaded:
                    status['profiles_loaded'] = int(loaded.group(1))
                if enforcing:
                    status['profiles_enforcing'] = int(enforcing.group(1))
    
    return status

def get_running_services(os_info: OSInfo) -> List[str]:
    """Get list of running services"""
    services = []
    
    if os_info.init_system == 'systemd':
        result = run_command("systemctl list-units --type=service --state=running --no-pager --no-legend | awk '{print $1}'")
        if result.returncode == 0:
            services = [s.strip().replace('.service', '') for s in result.stdout.split('\n') if s.strip()]
    
    return services

def get_enabled_services(os_info: OSInfo) -> List[str]:
    """Get list of enabled services"""
    services = []
    
    if os_info.init_system == 'systemd':
        result = run_command("systemctl list-unit-files --type=service --state=enabled --no-pager --no-legend | awk '{print $1}'")
        if result.returncode == 0:
            services = [s.strip().replace('.service', '') for s in result.stdout.split('\n') if s.strip()]
    
    return services

# ============================================================================
# OS & PACKAGE MANAGEMENT
# Dynamic Checks Based on OS Family with Specific Guidance
# ============================================================================

def check_os_package_management(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    OS Detection and Package Management Security Audit Checks
    """
    print(f"[{MODULE_NAME}] Checking OS & OS-Specfic Package Management...")
    
    # OS-001: Operating System Identified
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Pass" if os_info.family != "Unknown" else "Warning",
        message=f"{get_core_id('OS', 1)}: Operating system identified",
        details=f"{os_info.distro} {os_info.version} ({os_info.family})",
        remediation="OS detection successful"
    ))
    
    # OS-002: OS Version Current
    version_current = True
    version_details = f"{os_info.distro} {os_info.version}"
    
    # Check for EOL versions
    if os_info.distro == 'ubuntu':
        try:
            major = os_info.version_id.split('.')[0]
            if int(major) < 20:
                version_current = False
                version_details += " (Consider upgrading to LTS version)"
        except:
            pass
    elif os_info.distro == 'debian':
        # Debian 10 (Buster) and older are getting old
        if os_info.version_id and int(os_info.version_id) < 11:
            version_current = False
            version_details += " (Consider upgrading)"
    elif os_info.distro in ['centos', 'rhel']:
        try:
            major = os_info.version_id.split('.')[0]
            if int(major) < 8:
                version_current = False
                version_details += " (Consider upgrading)"
        except:
            pass
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Pass" if version_current else "Warning",
        message=f"{get_core_id('OS', 2)}: OS version supported",
        details=version_details,
        remediation="Keep OS version current with vendor support"
    ))
    
    # OS-003: Package manager identified
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if os_info.package_manager != "Unknown" else "Fail",
        message=f"{get_core_id('PKG', 1)}: Package manager identified",
        details=f"Package manager: {os_info.package_manager}",
        remediation="Ensure package manager is functional"
    ))
    
    # PKG-002: Package database integrity (OS-specific)
    if os_info.package_manager == 'apt':
        result = run_command("dpkg --audit 2>&1 | wc -l")
        issues = safe_int_parse(result.stdout.strip())
        pkg_ok = issues == 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if pkg_ok else "Warning",
            message=f"{get_core_id('PKG', 2)}: Package database integrity (dpkg)",
            details=f"{issues} package issues",
            remediation="Run: dpkg --configure -a && apt-get install -f"
        ))
    
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command("rpm -Va 2>&1 | wc -l")
        issues = safe_int_parse(result.stdout.strip())
        pkg_ok = issues < 50  # Some variation is normal
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if pkg_ok else "Info",
            message=f"{get_core_id('PKG', 2)}: Package database integrity (RPM)",
            details=f"{issues} package verification messages",
            remediation="Review: rpm -Va"
        ))
    
    # PKG-003: Repository configuration (OS-specific)
    repos = get_repositories(os_info)
    repos_configured = len(repos) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if repos_configured else "Warning",
        message=f"{get_core_id('PKG', 3)}: Repositories configured",
        details=f"{len(repos)} repositories configured",
        remediation="Configure official distribution repositories"
    ))
    
    # PKG-004: Official repositories used (OS-specific)
    official_repos = 0
    unofficial_repos = []
    
    if os_info.family == 'debian':
        official_domains = ['debian.org', 'ubuntu.com', 'canonical.com']
        for repo in repos:
            if any(domain in repo for domain in official_domains):
                official_repos += 1
            else:
                unofficial_repos.append(repo)
    elif os_info.family == 'redhat':
        official_domains = ['redhat.com', 'fedoraproject.org', 'centos.org']
        for repo in repos:
            if any(domain in repo for domain in official_domains):
                official_repos += 1
            else:
                unofficial_repos.append(repo)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if official_repos > 0 else "Warning",
        message=f"{get_core_id('PKG', 4)}: Official repositories in use",
        details=f"{official_repos} official, {len(unofficial_repos)} unofficial",
        remediation="Use official distribution repositories when possible"
    ))
    
    # PKG-005: HTTPS repositories (Debian-specific best practice)
    if os_info.family == 'debian':
        https_repos = sum(1 for r in repos if r.startswith('https://'))
        http_repos = sum(1 for r in repos if r.startswith('http://') and not r.startswith('https://'))
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if http_repos == 0 else "Warning",
            message=f"{get_core_id('PKG', 5)}: Repositories use HTTPS",
            details=f"HTTPS: {https_repos}, HTTP: {http_repos}",
            remediation="Use HTTPS repositories in /etc/apt/sources.list"
        ))
    
    # PKG-006: GPG key verification (OS-specific)
    if os_info.package_manager == 'apt':
        if command_exists('apt-key'):
            result = run_command("apt-key list 2>/dev/null | grep -c 'pub'")
            keys = safe_int_parse(result.stdout.strip())
        else:
            # Modern Debian/Ubuntu use /etc/apt/trusted.gpg.d/
            keys = len(glob.glob("/etc/apt/trusted.gpg.d/*.gpg"))
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if keys > 0 else "Warning",
            message=f"{get_core_id('PKG', 6)}: GPG keys configured (APT)",
            details=f"{keys} GPG keys",
            remediation="Import repository GPG keys"
        ))
    
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command("rpm -q gpg-pubkey 2>/dev/null | wc -l")
        keys = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if keys > 0 else "Warning",
            message=f"{get_core_id('PKG', 6)}: GPG keys configured (RPM)",
            details=f"{keys} GPG keys",
            remediation="Import repository GPG keys: rpm --import <key>"
        ))
    
    # PKG-007: Automatic updates configured (OS-specific)
    if os_info.family == 'debian':
        auto_updates = check_package_installed("unattended-upgrades", os_info)
        auto_enabled = False
        
        if auto_updates and os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades"):
            content = read_file_safe("/etc/apt/apt.conf.d/20auto-upgrades")
            auto_enabled = 'APT::Periodic::Unattended-Upgrade "1"' in content
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if auto_enabled else "Warning",
            message=f"{get_core_id('PKG', 7)}: Automatic security updates (Debian/Ubuntu)",
            details="Enabled" if auto_enabled else "Not configured",
            remediation="Configure: dpkg-reconfigure -plow unattended-upgrades"
        ))
    
    elif os_info.family == 'redhat':
        auto_updates = check_package_installed("yum-cron", os_info) or check_package_installed("dnf-automatic", os_info)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if auto_updates else "Warning",
            message=f"{get_core_id('PKG', 7)}: Automatic security updates (RedHat)",
            details="Installed" if auto_updates else "Not installed",
            remediation="Install: yum install yum-cron || dnf install dnf-automatic"
        ))
    
    # PKG-008: Available updates count
    available_updates = get_available_updates(os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if available_updates < 10 else "Warning" if available_updates < 50 else "Fail",
        message=f"{get_core_id('PKG', 8)}: System updates current",
        details=f"{available_updates} updates available",
        remediation=f"Update: {os_info.package_manager} upgrade"
    ))
    
    # PKG-009: Security updates available
    security_updates = get_security_updates(os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if security_updates == 0 else "Fail",
        message=f"{get_core_id('PKG', 9)}: Security updates applied",
        details=f"{security_updates} security updates pending",
        remediation=f"Apply security updates immediately"
    ))
    
    # PKG-010: Last update time
    last_update = get_last_update_time(os_info)
    update_recent = last_update is not None and last_update < 30
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if update_recent else "Warning",
        message=f"{get_core_id('PKG', 10)}: Recent system updates",
        details=f"Last update: {last_update} days ago" if last_update else "Cannot determine",
        remediation="Update system regularly (at least monthly)"
    ))
    
    # PKG-011: Essential packages installed (OS-specific)
    if os_info.family == 'debian':
        essential_packages = ['apt-transport-https', 'ca-certificates', 'gnupg']
    elif os_info.family == 'redhat':
        essential_packages = ['ca-certificates', 'gnupg2']
    else:
        essential_packages = []
    
    missing_essential = [pkg for pkg in essential_packages if not check_package_installed(pkg, os_info)]
    
    if essential_packages:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if not missing_essential else "Warning",
            message=f"{get_core_id('PKG', 11)}: Essential security packages installed",
            details=f"Missing: {', '.join(missing_essential)}" if missing_essential else "All present",
            remediation=f"Install missing packages"
        ))
    
    # PKG-012: Package hold/pin status (prevents unexpected updates)
    if os_info.package_manager == 'apt':
        result = run_command("apt-mark showhold 2>/dev/null | wc -l")
        held_packages = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Info",
            message=f"{get_core_id('PKG', 12)}: Package hold status (APT)",
            details=f"{held_packages} packages on hold",
            remediation="Review held packages: apt-mark showhold"
        ))
    
    # PKG-013: Kernel packages installed count
    if os_info.package_manager == 'apt':
        result = run_command("dpkg -l | grep -c '^ii.*linux-image'")
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command("rpm -qa | grep -c '^kernel-'")
    else:
        result = None
    
    kernel_count = safe_int_parse(result.stdout.strip()) if result else 0
    
    if kernel_count > 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Info",
            message=f"{get_core_id('PKG', 13)}: Kernel packages installed",
            details=f"{kernel_count} kernel packages",
            remediation="Remove old kernels to save space"
        ))
    
    # PKG-014: Running kernel vs available (security critical)
    running_kernel = platform.release()
    
    if os_info.package_manager == 'apt':
        result = run_command("dpkg -l | grep '^ii.*linux-image' | awk '{print $3}' | sort -V | tail -1")
        latest_kernel = result.stdout.strip()
        kernel_current = running_kernel in latest_kernel or latest_kernel in running_kernel
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command("rpm -q kernel | sort -V | tail -1")
        latest_kernel = result.stdout.strip()
        kernel_current = running_kernel in latest_kernel
    else:
        kernel_current = True
        latest_kernel = "unknown"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if kernel_current else "Warning",
        message=f"{get_core_id('PKG', 14)}: Running latest installed kernel",
        details=f"Running: {running_kernel}, Latest: {latest_kernel}"[:80],
        remediation="Reboot to use updated kernel"
    ))
    
    # PKG-015: Package manager locks (indicates ongoing operations)
    lock_files = []
    if os_info.package_manager == 'apt':
        if os.path.exists("/var/lib/dpkg/lock"):
            lock_files.append("dpkg")
        if os.path.exists("/var/lib/apt/lists/lock"):
            lock_files.append("apt")
    elif os_info.package_manager in ['yum', 'dnf']:
        if os.path.exists("/var/run/yum.pid"):
            lock_files.append("yum")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Pass" if not lock_files else "Warning",
        message=f"{get_core_id('PKG', 15)}: Package manager not locked",
        details=f"Locks: {', '.join(lock_files)}" if lock_files else "No locks",
        remediation="Wait for package operations to complete or remove stale locks"
    ))
    
    # PKG-016: Development tools installed (security consideration)
    dev_tools = ['gcc', 'g++', 'make', 'gdb']
    installed_dev = [tool for tool in dev_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Warning" if installed_dev else "Pass",
        message=f"{get_core_id('PKG', 16)}: Development tools on production system",
        details=f"Installed: {', '.join(installed_dev)}" if installed_dev else "None",
        remediation="Remove development tools from production systems"
    ))
    
    # PKG-017: System architecture
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Info",
        message=f"{get_core_id('OS', 3)}: System architecture",
        details=f"Architecture: {os_info.architecture}",
        remediation="Informational"
    ))
    
    # PKG-018: Kernel version
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Info",
        message=f"{get_core_id('OS', 4)}: Kernel version",
        details=f"Kernel: {os_info.kernel_version}",
        remediation="Keep kernel updated"
    ))
    
    # PKG-019: Init system
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Info",
        message=f"{get_core_id('OS', 5)}: Init system",
        details=f"Init: {os_info.init_system}",
        remediation="Informational"
    ))
    
    # PKG-020: Distribution codename
    if os_info.codename != "Unknown":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - OS Detection",
            status="Info",
            message=f"{get_core_id('OS', 6)}: Distribution release name",
            details=f"Codename: {os_info.codename}",
            remediation="Informational"
        ))
    
    # PKG-021: Third-party repositories (security risk assessment)
    if os_info.family == 'debian':
        ppa_count = len(glob.glob("/etc/apt/sources.list.d/*ppa*.list"))
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if ppa_count == 0 else "Info",
            message=f"{get_core_id('PKG', 17)}: Third-party repositories (PPAs)",
            details=f"{ppa_count} PPAs configured",
            remediation="Minimize use of third-party repositories"
        ))
    
    # PKG-022: Package verification (Debian-specific)
    if os_info.package_manager == 'apt' and command_exists('debsums'):
        result = run_command("debsums -c 2>&1 | wc -l")
        checksum_errors = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if checksum_errors < 10 else "Warning",
            message=f"{get_core_id('PKG', 18)}: Package file integrity (debsums)",
            details=f"{checksum_errors} checksum mismatches",
            remediation="Reinstall packages with errors: apt-get install --reinstall <pkg>"
        ))
    
    # PKG-023: Orphaned packages (Debian-specific)
    if os_info.package_manager == 'apt':
        result = run_command("apt-get autoremove --dry-run 2>/dev/null | grep -c '^Remv'")
        orphaned = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Package Management",
            status="Pass" if orphaned < 5 else "Info",
            message=f"{get_core_id('PKG', 19)}: Orphaned packages",
            details=f"{orphaned} packages can be auto-removed",
            remediation="Remove: apt-get autoremove"
        ))
    
    # PKG-024: SELinux status (RedHat-specific)
    if os_info.family == 'redhat':
        selinux_status = check_selinux_status()
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - OS Security (RedHat)",
            status="Pass" if selinux_status['enforcing'] else "Warning",
            message=f"{get_core_id('OS', 7)}: SELinux enforcing mode",
            details=f"Mode: {selinux_status['mode']}",
            remediation="Enable SELinux: setenforce 1"
        ))
    
    # PKG-025: AppArmor status (Debian-specific)
    if os_info.family == 'debian':
        apparmor_status = check_apparmor_status()
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - OS Security (Debian)",
            status="Pass" if apparmor_status['enabled'] else "Warning",
            message=f"{get_core_id('OS', 8)}: AppArmor enabled",
            details=f"{apparmor_status['profiles_enforcing']} profiles enforcing",
            remediation="Enable AppArmor profiles"
        ))
    
    # PKG-026: System timezone configured
    result = run_command("timedatectl status 2>/dev/null | grep 'Time zone'")
    tz_set = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Pass" if tz_set else "Info",
        message=f"{get_core_id('OS', 9)}: System timezone configured",
        details="Configured" if tz_set else "Check timezone",
        remediation="Set timezone: timedatectl set-timezone <zone>"
    ))
    
    # PKG-027: System hostname configured
    hostname = socket.gethostname()
    hostname_ok = hostname and hostname != "localhost" and len(hostname) > 3
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Pass" if hostname_ok else "Warning",
        message=f"{get_core_id('OS', 10)}: System hostname configured",
        details=f"Hostname: {hostname}",
        remediation="Set hostname: hostnamectl set-hostname <name>"
    ))
    
    # PKG-028: Package cache size (maintenance consideration)
    if os_info.package_manager == 'apt':
        cache_dir = "/var/cache/apt/archives"
        if os.path.exists(cache_dir):
            result = run_command(f"du -sh {cache_dir} 2>/dev/null | awk '{{print $1}}'")
            cache_size = result.stdout.strip()
            
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CORE - Package Management",
                status="Info",
                message=f"{get_core_id('PKG', 20)}: Package cache size",
                details=f"Cache: {cache_size}",
                remediation="Clean cache: apt-get clean"
            ))
    
    # PKG-029: Installed package count
    if os_info.package_manager == 'apt':
        result = run_command("dpkg -l | grep -c '^ii'")
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command("rpm -qa | wc -l")
    else:
        result = None
    
    pkg_count = safe_int_parse(result.stdout.strip()) if result else 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Package Management",
        status="Info",
        message=f"{get_core_id('PKG', 21)}: Installed packages",
        details=f"{pkg_count} packages installed",
        remediation="Maintain package inventory"
    ))
    
    # PKG-030: System uptime
    result = run_command("uptime -p 2>/dev/null || uptime")
    uptime = result.stdout.strip()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - OS Detection",
        status="Info",
        message=f"{get_core_id('OS', 11)}: System uptime",
        details=uptime,
        remediation="Reboot after kernel updates"
    ))


# ============================================================================
# SERVICE & USER MANAGEMENT
# OS-Aware Service and User Security Validation
# ============================================================================

def check_service_user_management(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Service and User Management OS-Aware Security Audit Checks
    """
    print(f"[{MODULE_NAME}] Checking Service & User Management...")
    
    # Get service information
    running_services = get_running_services(os_info)
    enabled_services = get_enabled_services(os_info)
    
    # SVC-001: Service count
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Info",
        message=f"{get_core_id('SVC', 1)}: Running services inventory",
        details=f"{len(running_services)} services running",
        remediation="Review and minimize running services"
    ))
    
    # SVC-002: Unnecessary services check
    unnecessary = ['telnet', 'ftp', 'rsh', 'rlogin', 'rexec', 'tftp', 'talk', 'finger']
    found_unnecessary = [svc for svc in unnecessary if svc in running_services]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if not found_unnecessary else "Fail",
        message=f"{get_core_id('SVC', 2)}: Insecure services disabled",
        details=f"Found: {', '.join(found_unnecessary)}" if found_unnecessary else "None",
        remediation="Disable insecure services: systemctl disable <service>"
    ))
    
    # SVC-003: SSH service
    ssh_running = any('ssh' in svc for svc in running_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if ssh_running else "Info",
        message=f"{get_core_id('SVC', 3)}: SSH service status",
        details="Running" if ssh_running else "Not running",
        remediation="Configure SSH for remote access"
    ))
    
    # SVC-004: Firewall service
    firewall_services = ['ufw', 'firewalld', 'iptables']
    firewall_active = any(svc in running_services for svc in firewall_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if firewall_active else "Fail",
        message=f"{get_core_id('SVC', 4)}: Firewall service active",
        details="Active" if firewall_active else "Not active",
        remediation="Enable firewall: ufw enable || firewall-cmd --reload"
    ))
    
    # SVC-005: Logging service
    logging_services = ['rsyslog', 'syslog-ng', 'systemd-journald']
    logging_active = any(svc in running_services for svc in logging_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if logging_active else "Fail",
        message=f"{get_core_id('SVC', 5)}: System logging active",
        details="Active" if logging_active else "Not active",
        remediation="Enable logging: systemctl enable rsyslog"
    ))
    
    # SVC-006: Time sync service
    time_services = ['chronyd', 'ntpd', 'systemd-timesyncd']
    time_active = any(svc in running_services for svc in time_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if time_active else "Warning",
        message=f"{get_core_id('SVC', 6)}: Time synchronization active",
        details="Active" if time_active else "Not active",
        remediation="Enable: systemctl enable chronyd"
    ))
    
    # SVC-007: Cron service
    cron_active = any('cron' in svc for svc in running_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if cron_active else "Info",
        message=f"{get_core_id('SVC', 7)}: Cron daemon active",
        details="Active" if cron_active else "Not active",
        remediation="Enable cron: systemctl enable cron"
    ))
    
    # SVC-008: Audit daemon (auditd)
    audit_active = 'auditd' in running_services
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if audit_active else "Warning",
        message=f"{get_core_id('SVC', 8)}: Audit daemon (auditd) active",
        details="Active" if audit_active else "Not active",
        remediation="Enable: systemctl enable auditd"
    ))
    
    # User Management Checks
    
    # USR-001: User account inventory
    result = run_command("getent passwd | wc -l")
    user_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Info",
        message=f"{get_core_id('USR', 1)}: User account inventory",
        details=f"{user_count} user accounts",
        remediation="Review user accounts regularly"
    ))
    
    # USR-002: Root account check
    result = run_command("getent passwd root")
    root_exists = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Pass" if root_exists else "Fail",
        message=f"{get_core_id('USR', 2)}: Root account exists",
        details="Exists" if root_exists else "Missing",
        remediation="Root account must exist"
    ))
    
    # USR-003: Only root has UID 0
    result = run_command("awk -F: '$3 == 0 {print $1}' /etc/passwd")
    uid0_accounts = [u.strip() for u in result.stdout.strip().split('\n') if u.strip()]
    only_root = len(uid0_accounts) == 1 and uid0_accounts[0] == 'root'
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Pass" if only_root else "Fail",
        message=f"{get_core_id('USR', 3)}: Only root has UID 0",
        details=f"UID 0: {', '.join(uid0_accounts)}",
        remediation="Remove UID 0 from non-root accounts"
    ))
    
    # USR-004: System accounts have nologin shell
    result = run_command("awk -F: '$3 < 1000 && $3 != 0 && $7 !~ /nologin|false/ {print $1}' /etc/passwd | wc -l")
    system_with_shell = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Pass" if system_with_shell == 0 else "Warning",
        message=f"{get_core_id('USR', 4)}: System accounts have nologin shell",
        details=f"{system_with_shell} system accounts with login shell",
        remediation="Set nologin shell: usermod -s /sbin/nologin <user>"
    ))
    
    # USR-005: No accounts with empty passwords
    if os.path.exists("/etc/shadow"):
        result = run_command("awk -F: '$2 == \"\" {print $1}' /etc/shadow | wc -l")
        empty_passwords = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - User Management",
            status="Pass" if empty_passwords == 0 else "Fail",
            message=f"{get_core_id('USR', 5)}: No accounts with empty passwords",
            details=f"{empty_passwords} accounts",
            remediation="Set passwords or lock accounts"
        ))
    
    # USR-006: Users with home directories
    result = run_command("awk -F: '$3 >= 1000 && $6 !~ /\\/home/ {print $1}' /etc/passwd | wc -l")
    no_home = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Pass" if no_home <= 1 else "Info",  # nobody is ok
        message=f"{get_core_id('USR', 6)}: Users have proper home directories",
        details=f"{no_home} users without /home",
        remediation="Ensure users have home directories"
    ))
    
    # USR-007: Group inventory
    result = run_command("getent group | wc -l")
    group_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Info",
        message=f"{get_core_id('USR', 7)}: Group inventory",
        details=f"{group_count} groups",
        remediation="Review groups regularly"
    ))
    
    # USR-008: Root group members
    result = run_command("getent group root | cut -d: -f4")
    root_group_members = result.stdout.strip()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Info",
        message=f"{get_core_id('USR', 8)}: Root group membership",
        details=f"Members: {root_group_members if root_group_members else 'none'}",
        remediation="Minimize root group membership"
    ))
    
    # USR-009: sudo group/wheel group
    if os_info.family == 'debian':
        sudo_group = 'sudo'
    else:
        sudo_group = 'wheel'
    
    result = run_command(f"getent group {sudo_group}")
    sudo_exists = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Pass" if sudo_exists else "Warning",
        message=f"{get_core_id('USR', 9)}: Sudo group exists",
        details=f"{sudo_group} group {'exists' if sudo_exists else 'missing'}",
        remediation=f"Create sudo group: groupadd {sudo_group}"
    ))
    
    # USR-010: sudo package installed
    sudo_installed = check_package_installed('sudo', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - User Management",
        status="Pass" if sudo_installed else "Fail",
        message=f"{get_core_id('USR', 10)}: sudo package installed",
        details="Installed" if sudo_installed else "Not installed",
        remediation="Install sudo"
    ))
    
    # USR-011: /etc/passwd permissions
    if os.path.exists("/etc/passwd"):
        perms = get_file_permissions("/etc/passwd")
        perms_ok = perms and int(perms, 8) <= int('644', 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - User Management",
            status="Pass" if perms_ok else "Fail",
            message=f"{get_core_id('USR', 11)}: /etc/passwd permissions secure",
            details=f"Permissions: {perms}",
            remediation="chmod 644 /etc/passwd"
        ))
    
    # USR-012: /etc/shadow permissions
    if os.path.exists("/etc/shadow"):
        perms = get_file_permissions("/etc/shadow")
        perms_ok = perms and int(perms, 8) <= int('000', 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - User Management",
            status="Pass" if perms_ok else "Fail",
            message=f"{get_core_id('USR', 12)}: /etc/shadow permissions secure",
            details=f"Permissions: {perms}",
            remediation="chmod 000 /etc/shadow"
        ))
    
    # USR-013: /etc/group permissions
    if os.path.exists("/etc/group"):
        perms = get_file_permissions("/etc/group")
        perms_ok = perms and int(perms, 8) <= int('644', 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - User Management",
            status="Pass" if perms_ok else "Fail",
            message=f"{get_core_id('USR', 13)}: /etc/group permissions secure",
            details=f"Permissions: {perms}",
            remediation="chmod 644 /etc/group"
        ))
    
    # USR-014: Password aging configured
    if os.path.exists("/etc/login.defs"):
        content = read_file_safe("/etc/login.defs")
        pass_max = re.search(r'^PASS_MAX_DAYS\s+(\d+)', content, re.MULTILINE)
        aging_ok = pass_max and int(pass_max.group(1)) <= 90
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - User Management",
            status="Pass" if aging_ok else "Warning",
            message=f"{get_core_id('USR', 14)}: Password aging configured",
            details=f"PASS_MAX_DAYS: {pass_max.group(1) if pass_max else 'not set'}",
            remediation="Set PASS_MAX_DAYS 90 in /etc/login.defs"
        ))
    
    # USR-015: Default umask
    if os.path.exists("/etc/login.defs"):
        content = read_file_safe("/etc/login.defs")
        umask = re.search(r'^UMASK\s+(\d+)', content, re.MULTILINE)
        umask_ok = umask and umask.group(1) in ['027', '077']
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - User Management",
            status="Pass" if umask_ok else "Warning",
            message=f"{get_core_id('USR', 15)}: Default umask secure",
            details=f"UMASK: {umask.group(1) if umask else 'not set'}",
            remediation="Set UMASK 027 in /etc/login.defs"
        ))
    
    # Additional service checks
    
    # SVC-009: Unnecessary network services
    network_unnecessary = ['avahi-daemon', 'cups', 'bluetooth']
    found_net_unnecessary = [svc for svc in network_unnecessary if svc in running_services]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if not found_net_unnecessary else "Info",
        message=f"{get_core_id('SVC', 9)}: Optional network services",
        details=f"Running: {', '.join(found_net_unnecessary)}" if found_net_unnecessary else "None",
        remediation="Disable if not needed: systemctl disable <service>"
    ))
    
    # SVC-010: X11/GUI services on server
    x11_services = ['gdm', 'lightdm', 'xdm', 'kdm']
    x11_running = [svc for svc in x11_services if svc in running_services]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Service Management",
        status="Pass" if not x11_running else "Info",
        message=f"{get_core_id('SVC', 10)}: GUI services on server",
        details=f"Running: {', '.join(x11_running)}" if x11_running else "None",
        remediation="Disable GUI on servers: systemctl set-default multi-user.target"
    ))


# ============================================================================
# FILESYSTEM & NETWORK SECURITY
# Critical Security Configurations
# ============================================================================

def check_filesystem_network(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    Filesystem and Network Security Security Audit Checks
    """
    print(f"[{MODULE_NAME}] Checking Filesystem & Network Security...")
    
    # FS-001: Root filesystem mounted
    result = run_command("mount | grep ' / '")
    root_mounted = result.returncode == 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Pass" if root_mounted else "Fail",
        message=f"{get_core_id('FS', 1)}: Root filesystem mounted",
        details="Mounted" if root_mounted else "Not mounted",
        remediation="Root filesystem must be mounted"
    ))
    
    # FS-002: /tmp exists
    tmp_exists = os.path.exists("/tmp")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Pass" if tmp_exists else "Fail",
        message=f"{get_core_id('FS', 2)}: /tmp directory exists",
        details="Exists" if tmp_exists else "Missing",
        remediation="Create /tmp directory"
    ))
    
    # FS-003: /tmp permissions
    if tmp_exists:
        perms = get_file_permissions("/tmp")
        # /tmp should be 1777 (sticky bit set)
        perms_ok = perms and int(perms, 8) == int('1777', 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Filesystem",
            status="Pass" if perms_ok else "Warning",
            message=f"{get_core_id('FS', 3)}: /tmp permissions secure",
            details=f"Permissions: {perms}",
            remediation="chmod 1777 /tmp"
        ))
    
    # FS-004: Separate partitions
    critical_mounts = ['/tmp', '/var', '/var/log', '/home']
    result = run_command("mount | awk '{print $3}'")
    current_mounts = result.stdout.strip().split('\n')
    
    separate_count = sum(1 for m in critical_mounts if m in current_mounts)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Pass" if separate_count >= 2 else "Info",
        message=f"{get_core_id('FS', 4)}: Separate partitions for critical directories",
        details=f"{separate_count}/4 on separate partitions",
        remediation="Use separate partitions for /tmp, /var, /home"
    ))
    
    # FS-005: nodev on /tmp
    result = run_command("mount | grep ' /tmp ' | grep -c nodev")
    tmp_nodev = safe_int_parse(result.stdout.strip()) > 0
    
    if '/tmp' in current_mounts:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Filesystem",
            status="Pass" if tmp_nodev else "Warning",
            message=f"{get_core_id('FS', 5)}: /tmp mounted with nodev",
            details="nodev set" if tmp_nodev else "Not set",
            remediation="Add nodev to /tmp in /etc/fstab"
        ))
    
    # FS-006: World-writable files
    result = run_command("find / -xdev -type f -perm -0002 2>/dev/null | head -20 | wc -l")
    ww_files = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Pass" if ww_files == 0 else "Warning",
        message=f"{get_core_id('FS', 6)}: World-writable files",
        details=f"{ww_files} world-writable files found",
        remediation="Remove world-write: chmod o-w <file>"
    ))
    
    # FS-007: SUID files inventory
    result = run_command("find / -xdev -perm -4000 -type f 2>/dev/null | wc -l")
    suid_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Info",
        message=f"{get_core_id('FS', 7)}: SUID files inventory",
        details=f"{suid_count} SUID files",
        remediation="Review and minimize SUID files"
    ))
    
    # FS-008: SGID files inventory  
    result = run_command("find / -xdev -perm -2000 -type f 2>/dev/null | wc -l")
    sgid_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Info",
        message=f"{get_core_id('FS', 8)}: SGID files inventory",
        details=f"{sgid_count} SGID files",
        remediation="Review and minimize SGID files"
    ))
    
    # FS-009: Unowned files
    result = run_command("find / -xdev \\( -nouser -o -nogroup \\) 2>/dev/null | head -10 | wc -l")
    unowned = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Pass" if unowned == 0 else "Warning",
        message=f"{get_core_id('FS', 9)}: No unowned files",
        details=f"{unowned} unowned files",
        remediation="Assign ownership: chown <user>:<group> <file>"
    ))
    
    # FS-010: Sticky bit on world-writable directories
    result = run_command("find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -10 | wc -l")
    no_sticky = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Filesystem",
        status="Pass" if no_sticky == 0 else "Warning",
        message=f"{get_core_id('FS', 10)}: Sticky bit on world-writable dirs",
        details=f"{no_sticky} dirs without sticky bit",
        remediation="Add sticky bit: chmod +t <directory>"
    ))
    
    # Network Security Checks
    
    # NET-001: Network interfaces
    result = run_command("ip -o link show | grep -v 'lo:' | wc -l")
    interface_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Info",
        message=f"{get_core_id('NET', 1)}: Network interfaces",
        details=f"{interface_count} interfaces (excluding loopback)",
        remediation="Review network interfaces"
    ))
    
    # NET-002: IP forwarding disabled
    exists, ip_forward = check_kernel_parameter("net.ipv4.ip_forward")
    forward_disabled = ip_forward == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if forward_disabled else "Warning",
        message=f"{get_core_id('NET', 2)}: IP forwarding disabled",
        details=f"ip_forward = {ip_forward}",
        remediation="Disable: sysctl -w net.ipv4.ip_forward=0"
    ))
    
    # NET-003: ICMP redirects disabled
    exists, redirects = check_kernel_parameter("net.ipv4.conf.all.accept_redirects")
    redirects_disabled = redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if redirects_disabled else "Warning",
        message=f"{get_core_id('NET', 3)}: ICMP redirects disabled",
        details=f"accept_redirects = {redirects}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_redirects=0"
    ))
    
    # NET-004: Source routing disabled
    exists, source_route = check_kernel_parameter("net.ipv4.conf.all.accept_source_route")
    source_disabled = source_route == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if source_disabled else "Fail",
        message=f"{get_core_id('NET', 4)}: Source routing disabled",
        details=f"accept_source_route = {source_route}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_source_route=0"
    ))
    
    # NET-005: SYN cookies enabled
    exists, syn_cookies = check_kernel_parameter("net.ipv4.tcp_syncookies")
    syn_enabled = syn_cookies == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if syn_enabled else "Warning",
        message=f"{get_core_id('NET', 5)}: TCP SYN cookies enabled",
        details=f"tcp_syncookies = {syn_cookies}",
        remediation="Enable: sysctl -w net.ipv4.tcp_syncookies=1"
    ))
    
    # NET-006: Reverse path filtering
    exists, rp_filter = check_kernel_parameter("net.ipv4.conf.all.rp_filter")
    rp_enabled = rp_filter == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if rp_enabled else "Warning",
        message=f"{get_core_id('NET', 6)}: Reverse path filtering enabled",
        details=f"rp_filter = {rp_filter}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.rp_filter=1"
    ))
    
    # NET-007: Log martian packets
    exists, log_martians = check_kernel_parameter("net.ipv4.conf.all.log_martians")
    martians_logged = log_martians == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if martians_logged else "Info",
        message=f"{get_core_id('NET', 7)}: Martian packets logged",
        details=f"log_martians = {log_martians}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.log_martians=1"
    ))
    
    # NET-008: ICMP broadcast ignored
    exists, icmp_broadcast = check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts")
    broadcast_ignored = icmp_broadcast == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if broadcast_ignored else "Warning",
        message=f"{get_core_id('NET', 8)}: ICMP broadcast ignored",
        details=f"icmp_echo_ignore_broadcasts = {icmp_broadcast}",
        remediation="Enable: sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
    ))
    
    # NET-009: Listening ports inventory
    result = run_command("ss -tuln 2>/dev/null | grep LISTEN | wc -l")
    if result.returncode != 0:
        result = run_command("netstat -tuln 2>/dev/null | grep LISTEN | wc -l")
    
    listening_ports = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Info",
        message=f"{get_core_id('NET', 9)}: Listening network ports",
        details=f"{listening_ports} ports listening",
        remediation="Minimize listening ports"
    ))
    
    # NET-010: DNS configuration
    if os.path.exists("/etc/resolv.conf"):
        content = read_file_safe("/etc/resolv.conf")
        nameservers = content.count("nameserver")
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Network",
            status="Pass" if nameservers >= 1 else "Warning",
            message=f"{get_core_id('NET', 10)}: DNS servers configured",
            details=f"{nameservers} nameservers",
            remediation="Configure DNS in /etc/resolv.conf"
        ))
    
    # NET-011: Default gateway
    result = run_command("ip route | grep -c default")
    has_gateway = safe_int_parse(result.stdout.strip()) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Pass" if has_gateway else "Warning",
        message=f"{get_core_id('NET', 11)}: Default gateway configured",
        details="Configured" if has_gateway else "Not configured",
        remediation="Configure default gateway"
    ))
    
    # NET-012: IPv6 status
    ipv6_disabled = not os.path.exists("/proc/sys/net/ipv6/conf/all/disable_ipv6") or \
                    read_file_safe("/proc/sys/net/ipv6/conf/all/disable_ipv6").strip() == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Network",
        status="Info",
        message=f"{get_core_id('NET', 12)}: IPv6 status",
        details="Disabled" if ipv6_disabled else "Enabled",
        remediation="Disable if not needed: sysctl -w net.ipv6.conf.all.disable_ipv6=1"
    ))
    
    # NET-013: Firewall rules count (iptables)
    result = run_command("iptables -L 2>/dev/null | grep -c Chain")
    iptables_chains = safe_int_parse(result.stdout.strip())
    
    if iptables_chains > 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Network",
            status="Info",
            message=f"{get_core_id('NET', 13)}: Firewall rules configured",
            details=f"{iptables_chains} iptables chains",
            remediation="Review firewall rules"
        ))
    
    # NET-014: Network parameters in sysctl.conf
    if os.path.exists("/etc/sysctl.conf"):
        content = read_file_safe("/etc/sysctl.conf")
        net_params = content.count("net.")
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Network",
            status="Pass" if net_params >= 5 else "Info",
            message=f"{get_core_id('NET', 14)}: Network parameters persistent",
            details=f"{net_params} network parameters in sysctl.conf",
            remediation="Add network hardening parameters to /etc/sysctl.conf"
        ))
    
    # NET-015: Hosts file configured
    if os.path.exists("/etc/hosts"):
        content = read_file_safe("/etc/hosts")
        localhost_entry = "127.0.0.1" in content and "localhost" in content
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Network",
            status="Pass" if localhost_entry else "Warning",
            message=f"{get_core_id('NET', 15)}: /etc/hosts configured",
            details="Localhost entry present" if localhost_entry else "Missing entries",
            remediation="Configure /etc/hosts"
        ))


# ============================================================================
# SYSTEM HARDENING & SECURITY TOOLS
# Core System Security and Monitoring
# ============================================================================

def check_system_hardening_tools(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    System Hardening and Security Tools Checks
    """
    print(f"[{MODULE_NAME}] Checking System Hardening & Security Tools...")
    
    # HARD-001: ASLR enabled
    exists, aslr = check_kernel_parameter("kernel.randomize_va_space")
    aslr_enabled = aslr == "2"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if aslr_enabled else "Fail",
        message=f"{get_core_id('HARD', 1)}: Address Space Layout Randomization",
        details=f"randomize_va_space = {aslr}",
        remediation="Enable: sysctl -w kernel.randomize_va_space=2"
    ))
    
    # HARD-002: Kernel pointers restricted
    exists, kptr_restrict = check_kernel_parameter("kernel.kptr_restrict")
    kptr_ok = kptr_restrict in ["1", "2"]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if kptr_ok else "Warning",
        message=f"{get_core_id('HARD', 2)}: Kernel pointers restricted",
        details=f"kptr_restrict = {kptr_restrict}",
        remediation="Enable: sysctl -w kernel.kptr_restrict=1"
    ))
    
    # HARD-003: dmesg restricted
    exists, dmesg_restrict = check_kernel_parameter("kernel.dmesg_restrict")
    dmesg_ok = dmesg_restrict == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if dmesg_ok else "Warning",
        message=f"{get_core_id('HARD', 3)}: dmesg access restricted",
        details=f"dmesg_restrict = {dmesg_restrict}",
        remediation="Enable: sysctl -w kernel.dmesg_restrict=1"
    ))
    
    # HARD-004: Core dumps restricted
    exists, core_pattern = check_kernel_parameter("kernel.core_pattern")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 4)}: Core dump configuration",
        details=f"core_pattern = {core_pattern}"[:60],
        remediation="Restrict core dumps in /etc/security/limits.conf"
    ))
    
    # HARD-005: SUID dumpable
    exists, suid_dumpable = check_kernel_parameter("fs.suid_dumpable")
    suid_ok = suid_dumpable == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if suid_ok else "Warning",
        message=f"{get_core_id('HARD', 5)}: SUID core dumps disabled",
        details=f"suid_dumpable = {suid_dumpable}",
        remediation="Disable: sysctl -w fs.suid_dumpable=0"
    ))
    
    # HARD-006: Protected hardlinks
    exists, hardlinks = check_kernel_parameter("fs.protected_hardlinks")
    hardlinks_ok = hardlinks == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if hardlinks_ok else "Warning",
        message=f"{get_core_id('HARD', 6)}: Protected hardlinks enabled",
        details=f"protected_hardlinks = {hardlinks}",
        remediation="Enable: sysctl -w fs.protected_hardlinks=1"
    ))
    
    # HARD-007: Protected symlinks
    exists, symlinks = check_kernel_parameter("fs.protected_symlinks")
    symlinks_ok = symlinks == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if symlinks_ok else "Warning",
        message=f"{get_core_id('HARD', 7)}: Protected symlinks enabled",
        details=f"protected_symlinks = {symlinks}",
        remediation="Enable: sysctl -w fs.protected_symlinks=1"
    ))
    
    # HARD-008: Ptrace scope
    exists, ptrace_scope = check_kernel_parameter("kernel.yama.ptrace_scope")
    ptrace_ok = ptrace_scope in ["1", "2", "3"]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if ptrace_ok else "Warning",
        message=f"{get_core_id('HARD', 8)}: Ptrace scope restricted",
        details=f"ptrace_scope = {ptrace_scope}",
        remediation="Enable: sysctl -w kernel.yama.ptrace_scope=1"
    ))
    
    # Security Tools Checks
    
    # TOOL-001: File integrity monitoring
    fim_tools = ['aide', 'tripwire', 'samhain']
    fim_installed = [tool for tool in fim_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Pass" if fim_installed else "Warning",
        message=f"{get_core_id('TOOL', 1)}: File integrity monitoring installed",
        details=f"Installed: {', '.join(fim_installed)}" if fim_installed else "Not installed",
        remediation="Install AIDE: apt-get install aide || yum install aide"
    ))
    
    # TOOL-002: Intrusion detection
    ids_tools = ['ossec', 'snort', 'suricata']
    ids_installed = [tool for tool in ids_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Info",
        message=f"{get_core_id('TOOL', 2)}: Intrusion detection system",
        details=f"Installed: {', '.join(ids_installed)}" if ids_installed else "Not installed",
        remediation="Consider installing IDS/IPS"
    ))
    
    # TOOL-003: Anti-malware
    av_installed = check_package_installed('clamav', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Pass" if av_installed else "Warning",
        message=f"{get_core_id('TOOL', 3)}: Anti-malware software installed",
        details="ClamAV installed" if av_installed else "Not installed",
        remediation="Install: apt-get install clamav"
    ))
    
    # TOOL-004: Rootkit detection
    rk_tools = ['rkhunter', 'chkrootkit']
    rk_installed = [tool for tool in rk_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Pass" if rk_installed else "Warning",
        message=f"{get_core_id('TOOL', 4)}: Rootkit detection tools",
        details=f"Installed: {', '.join(rk_installed)}" if rk_installed else "Not installed",
        remediation="Install: apt-get install rkhunter"
    ))
    
    # TOOL-005: System monitoring
    mon_tools = ['monit', 'nagios', 'zabbix']
    mon_installed = [tool for tool in mon_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Info",
        message=f"{get_core_id('TOOL', 5)}: System monitoring tools",
        details=f"Installed: {', '.join(mon_installed)}" if mon_installed else "Not installed",
        remediation="Consider installing monitoring tools"
    ))
    
    # TOOL-006: Log analysis
    log_tools = ['logwatch', 'fail2ban']
    log_installed = [tool for tool in log_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Info",
        message=f"{get_core_id('TOOL', 6)}: Log analysis tools",
        details=f"Installed: {', '.join(log_installed)}" if log_installed else "Not installed",
        remediation="Install fail2ban for automated response"
    ))
    
    # TOOL-007: Firewall management tools
    fw_tools = ['ufw', 'firewalld']
    fw_installed = [tool for tool in fw_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - Security Tools",
        status="Pass" if fw_installed else "Warning",
        message=f"{get_core_id('TOOL', 7)}: Firewall management tools",
        details=f"Installed: {', '.join(fw_installed)}" if fw_installed else "Not installed",
        remediation="Install firewall management: ufw or firewalld"
    ))
    
    # Additional Hardening Checks
    
    # HARD-009: Kernel modules restricted
    modprobe_d = os.path.exists("/etc/modprobe.d")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if modprobe_d else "Info",
        message=f"{get_core_id('HARD', 9)}: Kernel module configuration directory",
        details="Exists" if modprobe_d else "Not found",
        remediation="Create /etc/modprobe.d/ for module restrictions"
    ))
    
    # HARD-010: Ctrl-Alt-Del disabled
    ctrl_alt_del_disabled = False
    if os.path.exists("/etc/systemd/system/ctrl-alt-del.target"):
        link = os.path.realpath("/etc/systemd/system/ctrl-alt-del.target")
        ctrl_alt_del_disabled = "/dev/null" in link
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if ctrl_alt_del_disabled else "Warning",
        message=f"{get_core_id('HARD', 10)}: Ctrl-Alt-Del disabled",
        details="Disabled" if ctrl_alt_del_disabled else "Enabled",
        remediation="Disable: systemctl mask ctrl-alt-del.target"
    ))
    
    # HARD-011: Bootloader installed
    grub_exists = os.path.exists("/boot/grub") or os.path.exists("/boot/grub2")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Pass" if grub_exists else "Warning",
        message=f"{get_core_id('HARD', 11)}: Bootloader present",
        details="GRUB found" if grub_exists else "Not found",
        remediation="Install GRUB bootloader"
    ))
    
    # HARD-012: System accounting
    process_acct = check_package_installed('psacct', os_info) or check_package_installed('acct', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 12)}: Process accounting installed",
        details="Installed" if process_acct else "Not installed",
        remediation="Install: apt-get install psacct"
    ))
    
    # HARD-013: System activity reporting
    sysstat = check_package_installed('sysstat', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 13)}: System activity reporting",
        details="sysstat installed" if sysstat else "Not installed",
        remediation="Install: apt-get install sysstat"
    ))
    
    # HARD-014: Memory overcommit
    exists, overcommit = check_kernel_parameter("vm.overcommit_memory")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 14)}: Memory overcommit setting",
        details=f"overcommit_memory = {overcommit}",
        remediation="Configure based on workload requirements"
    ))
    
    # HARD-015: Swap usage
    result = run_command("swapon --show | wc -l")
    swap_configured = safe_int_parse(result.stdout.strip()) > 1  # Header line present
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 15)}: Swap space configured",
        details="Configured" if swap_configured else "No swap",
        remediation="Configure swap based on system requirements"
    ))
    
    # HARD-016: Kernel panic behavior
    exists, panic_timeout = check_kernel_parameter("kernel.panic")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 16)}: Kernel panic timeout",
        details=f"panic = {panic_timeout}",
        remediation="Configure panic behavior"
    ))
    
    # HARD-017: File descriptor limits
    result = run_command("ulimit -n")
    fd_limit = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 17)}: File descriptor limit",
        details=f"Limit: {fd_limit}",
        remediation="Adjust in /etc/security/limits.conf if needed"
    ))
    
    # HARD-018: Process limit
    result = run_command("ulimit -u")
    proc_limit = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 18)}: Process limit",
        details=f"Limit: {proc_limit}",
        remediation="Adjust in /etc/security/limits.conf if needed"
    ))
    
    # HARD-019: Loaded kernel modules
    result = run_command("lsmod | wc -l")
    module_count = safe_int_parse(result.stdout.strip()) - 1  # Subtract header
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="CORE - System Hardening",
        status="Info",
        message=f"{get_core_id('HARD', 19)}: Loaded kernel modules",
        details=f"{module_count} modules loaded",
        remediation="Review and minimize kernel modules"
    ))
    
    # HARD-020: Kernel log level
    if os.path.exists("/proc/sys/kernel/printk"):
        printk = read_file_safe("/proc/sys/kernel/printk").strip().split()[0]
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - System Hardening",
            status="Info",
            message=f"{get_core_id('HARD', 20)}: Kernel log level",
            details=f"Console log level: {printk}",
            remediation="Configure kernel logging"
        ))


# ============================================================================
# Main Orchestration Function
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """
    Main entry point for CORE module
    Executes all security baseline checks and returns results
    """
    results = []
    
    print(f"\n[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] CORE SECURITY BASELINE AUDIT")
    print(f"[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] Version: {MODULE_VERSION}")
    print(f"[{MODULE_NAME}] Focus: Industry Best Practices with OS-Specific Guidance")
    print(f"[{MODULE_NAME}] Areas: OS, Packages, Services, Users, Filesystem, Network, Hardening")
    print(f"[{MODULE_NAME}] Target: 130+ comprehensive OS-aware checks")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    # Detect operating system
    os_info = detect_os()
    shared_data['os_info'] = os_info
    
    print(f"[{MODULE_NAME}] Operating System: {os_info}")
    print(f"[{MODULE_NAME}] Package Manager: {os_info.package_manager}")
    print(f"[{MODULE_NAME}] Init System: {os_info.init_system}")
    print("")
    
    is_root = shared_data.get("is_root", os.geteuid() == 0)
    if not is_root:
        print(f"[{MODULE_NAME}] ⚠️  Note: Running without root privileges")
        print(f"[{MODULE_NAME}] Some checks require elevated privileges for full coverage\n")
    
    try:
        # Execute all check categories
        check_os_package_management(results, shared_data, os_info)
        check_service_user_management(results, shared_data, os_info)
        check_filesystem_network(results, shared_data, os_info)
        check_system_hardening_tools(results, shared_data, os_info)
        
    except Exception as e:
        print(f"[{MODULE_NAME}] ❌ Error during audit execution: {str(e)}")
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CORE - Error",
            status="Error",
            message=f"Module execution error: {str(e)}",
            details="",
            remediation="Review module logs and configuration"
        ))
        import traceback
        traceback.print_exc()
    
    # Generate summary statistics
    pass_count = sum(1 for r in results if r.status == "Pass")
    fail_count = sum(1 for r in results if r.status == "Fail")
    warn_count = sum(1 for r in results if r.status == "Warning")
    info_count = sum(1 for r in results if r.status == "Info")
    error_count = sum(1 for r in results if r.status == "Error")
    
    # Count by category
    os_checks = sum(1 for r in results if "OS Detection" in r.category or "Package Management" in r.category)
    service_checks = sum(1 for r in results if "Service" in r.category or "User" in r.category)
    fs_net_checks = sum(1 for r in results if "Filesystem" in r.category or "Network" in r.category)
    hard_tool_checks = sum(1 for r in results if "Hardening" in r.category or "Tools" in r.category)
    
    print(f"\n[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] AUDIT COMPLETED")
    print(f"[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] Total Security Audit Checks Executed: {len(results)}")
    print(f"[{MODULE_NAME}] ")
    print(f"[{MODULE_NAME}] Results Summary:")
    print(f"[{MODULE_NAME}]   ✅ Pass:    {pass_count:3d} ({pass_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   ❌ Fail:    {fail_count:3d} ({fail_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   ⚠️  Warning: {warn_count:3d} ({warn_count/len(results)*100:.1f}%)")
    print(f"[{MODULE_NAME}]   ℹ️  Info:    {info_count:3d} ({info_count/len(results)*100:.1f}%)")
    if error_count > 0:
        print(f"[{MODULE_NAME}]   🚫 Error:   {error_count:3d}")
    print(f"[{MODULE_NAME}] ")
    print(f"[{MODULE_NAME}] Check Categories:")
    print(f"[{MODULE_NAME}]   OS & Packages:         {os_checks:3d} checks")
    print(f"[{MODULE_NAME}]   Services & Users:      {service_checks:3d} checks")
    print(f"[{MODULE_NAME}]   Filesystem & Network:  {fs_net_checks:3d} checks")
    print(f"[{MODULE_NAME}]   Hardening & Tools:     {hard_tool_checks:3d} checks")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    return results

# ============================================================================
# Module Testing
# ============================================================================

if __name__ == "__main__":
    """
    Standalone testing capability for the CORE module
    """
    import datetime
    
    print("="*80)
    print(f"CORE Module Standalone Test - v{MODULE_VERSION}")
    print("Comprehensive Linux Security Baseline")
    print("="*80)
    
    # Prepare test environment data
    test_data = {
        "hostname": socket.gethostname(),
        "scan_date": datetime.datetime.now(),
        "is_root": os.geteuid() == 0,
        "script_path": Path(__file__).parent.parent if hasattr(Path(__file__), 'parent') else Path.cwd()
    }
    
    print(f"\nTest Environment:")
    print(f"  Hostname: {test_data['hostname']}")
    print(f"  Running as root: {test_data['is_root']}")
    print(f"  Scan time: {test_data['scan_date'].strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*80 + "\n")
    
    # Execute checks
    test_results = run_checks(test_data)
    
    # Detailed analysis
    print(f"\n{'='*80}")
    print(f"DETAILED TEST RESULTS")
    print(f"{'='*80}")
    print(f"Generated {len(test_results)} audit results\n")
    
    from collections import Counter
    
    # Status breakdown
    status_counts = Counter(r.status for r in test_results)
    print("Status Distribution:")
    for status in ["Pass", "Fail", "Warning", "Info", "Error"]:
        count = status_counts.get(status, 0)
        if count > 0:
            pct = (count / len(test_results)) * 100
            bar = '█' * int(pct / 2)
            print(f"  {status:8s}: {count:3d} ({pct:5.1f}%) {bar}")
    
    # Category breakdown
    print(f"\nCheck Area Coverage:")
    category_counts = Counter(r.category for r in test_results)
    for category in sorted(category_counts.keys()):
        count = category_counts[category]
        print(f"  {category:45s}: {count:3d} checks")
    
    print(f"\n{'='*80}")
    print(f"CORE module comprehensive test complete")
    print(f"All {len(test_results)} checks executed successfully")
    print(f"{'='*80}\n")
