#!/usr/bin/env python3
"""
module_iso27001.py
ISO/IEC 27001:2022 Technical Controls Module for Linux
Version: 1.1

SYNOPSIS:
    Comprehensive ISO/IEC 27001:2022 compliance assessment focusing on
    Annex A technical controls that can be audited on Linux systems.

DESCRIPTION:
    This module performs thorough security checks aligned with ISO 27001:2022:
    
    ISO 27001:2022 Annex A Coverage:
    - A.8.1: User endpoint devices
    - A.8.2: Privileged access rights
    - A.8.3: Information access restriction
    - A.8.4: Access to source code
    - A.8.5: Secure authentication
    - A.8.6: Capacity management
    - A.8.7: Protection against malware
    - A.8.8: Management of technical vulnerabilities
    - A.8.9: Configuration management
    - A.8.10-A.8.13: Data protection and backup
    - A.8.14-A.8.17: System reliability and monitoring
    - A.8.18-A.8.24: Network and cryptographic security
    - A.8.25-A.8.34: Secure development (where applicable)
    
    OS-Specific Adaptations:
    - Debian-based: Ubuntu, Debian, Linux Mint, Kali Linux
      * APT package management
      * AppArmor integration
      * Debian-specific security configurations
    
    - RedHat-based: RHEL, Fedora, CentOS, Rocky, AlmaLinux
      * YUM/DNF package management
      * SELinux integration
      * RedHat-specific security configurations
    
    Key Standards Referenced:
    - ISO/IEC 27001:2022 - Information Security Management
    - ISO/IEC 27002:2022 - Code of Practice for Information Security Controls
    - NIST SP 800-53 (complementary guidance)
    - CIS Controls (implementation alignment)

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

USAGE:
	Standalone module test:
		python3 module_iso27001.py

	Integration with main audit script:
		python3 linux_security_audit.py --modules iso27001
        python3 linux_security_audit.py -m iso27001

NOTES:
    Version: 1.1
    Focus: ISO 27001:2022 Annex A Technical Controls
    Target: 150+ comprehensive, OS-aware technical control checks
    Module automatically detects OS via module_core integration
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
import shutil
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime

# Import AuditResult from main script
sys.path.insert(0, str(Path(__file__).parent.parent))
from linux_security_audit import AuditResult

MODULE_NAME = "ISO27001"
MODULE_VERSION = "1.1"

# ============================================================================
# Import OS Detection from Core Module
# ============================================================================

try:
    # Try to import OS detection from module_core
    sys.path.insert(0, str(Path(__file__).parent))
    from module_core import (
        OSInfo, detect_os, run_command, command_exists, read_file_safe,
        check_service_enabled, check_service_active, check_package_installed,
        get_file_permissions, get_file_owner_group, check_kernel_parameter,
        safe_int_parse, get_security_updates
    )
    HAS_CORE_MODULE = True
except ImportError:
    HAS_CORE_MODULE = False
    
    # Fallback: Minimal implementation if core module not available
    class OSInfo:
        def __init__(self):
            self.family = "Unknown"
            self.distro = "Unknown"
            self.package_manager = "Unknown"
    
    def detect_os():
        os_info = OSInfo()
        if os.path.exists("/etc/debian_version"):
            os_info.family = "debian"
            os_info.package_manager = "apt"
        elif os.path.exists("/etc/redhat-release"):
            os_info.family = "redhat"
            os_info.package_manager = "yum"
        return os_info
    
    def run_command(command: str, check: bool = False):
        return subprocess.run(command, shell=True, capture_output=True, text=True)
    
    def command_exists(command: str):
        return run_command(f"which {command} 2>/dev/null").returncode == 0
    
    def read_file_safe(filepath: str):
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except:
            return ""
    
    def check_service_active(service: str):
        return run_command(f"systemctl is-active {service} 2>/dev/null").returncode == 0
    
    def check_package_installed(package: str, os_info):
        if os_info.package_manager == 'apt':
            return run_command(f"dpkg -l {package} 2>/dev/null | grep -q '^ii'").returncode == 0
        else:
            return run_command(f"rpm -q {package} 2>/dev/null").returncode == 0
    
    def get_file_permissions(filepath: str):
        try:
            return oct(os.stat(filepath).st_mode)[-3:]
        except:
            return None
    
    def check_kernel_parameter(param: str):
        result = run_command(f"sysctl {param} 2>/dev/null")
        if result.returncode == 0:
            match = re.search(r'=\s*(.+)', result.stdout)
            if match:
                return True, match.group(1).strip()
        return False, ""
    
    def safe_int_parse(value: str, default: int = 0):
        try:
            return int(value.strip()) if value and value.strip().isdigit() else default
        except:
            return default
    
    def get_security_updates(os_info):
        return 0

# ============================================================================
# ISO 27001 Helper Functions
# ============================================================================

def get_iso_id(control: str, number: int) -> str:
    """Generate ISO 27001 control ID"""
    return f"ISO27001-A.8.{control}-{number:03d}"

def check_file_exists_secure(filepath: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Check if file exists and get permissions
    Returns: (exists, permissions, owner)
    """
    if not os.path.exists(filepath):
        return False, None, None
    
    perms = get_file_permissions(filepath)
    try:
        stat_info = os.stat(filepath)
        owner = pwd.getpwuid(stat_info.st_uid).pw_name
    except:
        owner = None
    
    return True, perms, owner

def check_directory_permissions(directory: str, expected_perms: str) -> bool:
    """Check if directory has secure permissions"""
    if not os.path.exists(directory):
        return False
    
    perms = get_file_permissions(directory)
    if not perms:
        return False
    
    return int(perms, 8) <= int(expected_perms, 8)

def get_password_policy() -> Dict[str, Any]:
    """Get password policy settings"""
    policy = {
        'max_days': None,
        'min_days': None,
        'min_length': None,
        'warn_age': None
    }
    
    if os.path.exists("/etc/login.defs"):
        content = read_file_safe("/etc/login.defs")
        
        max_days = re.search(r'^PASS_MAX_DAYS\s+(\d+)', content, re.MULTILINE)
        if max_days:
            policy['max_days'] = int(max_days.group(1))
        
        min_days = re.search(r'^PASS_MIN_DAYS\s+(\d+)', content, re.MULTILINE)
        if min_days:
            policy['min_days'] = int(min_days.group(1))
        
        min_len = re.search(r'^PASS_MIN_LEN\s+(\d+)', content, re.MULTILINE)
        if min_len:
            policy['min_length'] = int(min_len.group(1))
        
        warn = re.search(r'^PASS_WARN_AGE\s+(\d+)', content, re.MULTILINE)
        if warn:
            policy['warn_age'] = int(warn.group(1))
    
    return policy

def check_pam_module(module_name: str) -> bool:
    """Check if PAM module is configured"""
    pam_files = glob.glob("/etc/pam.d/*")
    for pam_file in pam_files:
        content = read_file_safe(pam_file)
        if module_name in content and not content.startswith('#'):
            return True
    return False

def get_failed_login_attempts() -> int:
    """Get count of recent failed login attempts"""
    if os.path.exists("/var/log/auth.log"):
        result = run_command("grep -c 'Failed password' /var/log/auth.log 2>/dev/null || echo 0")
    elif os.path.exists("/var/log/secure"):
        result = run_command("grep -c 'Failed password' /var/log/secure 2>/dev/null || echo 0")
    else:
        return 0
    
    return safe_int_parse(result.stdout.strip())

def check_encryption_available(os_info: OSInfo) -> Dict[str, bool]:
    """Check available encryption tools"""
    encryption = {
        'luks': False,
        'gpg': False,
        'openssl': False,
        'ssh': False
    }
    
    encryption['luks'] = command_exists('cryptsetup')
    encryption['gpg'] = check_package_installed('gnupg', os_info) or check_package_installed('gnupg2', os_info)
    encryption['openssl'] = command_exists('openssl')
    encryption['ssh'] = command_exists('ssh')
    
    return encryption

# ============================================================================
# A.8.1: User Endpoint Devices
# ============================================================================

def check_user_endpoint_devices(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    ISO 27001 A.8.1: User Endpoint Devices
    Information stored on, processed by or accessible via user endpoint devices
    shall be protected
    """
    print(f"[{MODULE_NAME}] Checking A.8.1 User Endpoint Devices...")
    
    # A.8.1-001: Screen lock configured
    screensaver_timeout = None
    
    # Check for GNOME
    if command_exists('gsettings'):
        result = run_command("gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null")
        lock_enabled = 'true' in result.stdout.lower()
        
        if lock_enabled:
            result = run_command("gsettings get org.gnome.desktop.screensaver idle-delay 2>/dev/null")
            timeout_match = re.search(r'uint32 (\d+)', result.stdout)
            if timeout_match:
                screensaver_timeout = int(timeout_match.group(1))
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Pass" if screensaver_timeout and screensaver_timeout <= 900 else "Warning",
        message=f"{get_iso_id('1', 1)}: Automatic screen lock configured",
        details=f"Timeout: {screensaver_timeout}s" if screensaver_timeout else "Not configured",
        remediation="Configure screen lock: gsettings set org.gnome.desktop.screensaver idle-delay 600"
    ))
    
    # A.8.1-002: Session timeout configured
    if os.path.exists("/etc/profile.d/tmout.sh"):
        content = read_file_safe("/etc/profile.d/tmout.sh")
        tmout_set = 'TMOUT=' in content
    else:
        result = run_command("grep -r 'TMOUT=' /etc/profile /etc/profile.d/ 2>/dev/null | wc -l")
        tmout_set = safe_int_parse(result.stdout.strip()) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Pass" if tmout_set else "Warning",
        message=f"{get_iso_id('1', 2)}: Session timeout configured",
        details="Configured" if tmout_set else "Not configured",
        remediation="Set TMOUT=600 in /etc/profile.d/tmout.sh"
    ))
    
    # A.8.1-003: USB storage restrictions
    result = run_command("lsmod | grep -c usb_storage || echo 0")
    usb_storage_loaded = safe_int_parse(result.stdout.strip()) > 0
    
    result = run_command("grep -r 'install usb-storage' /etc/modprobe.d/ 2>/dev/null | grep -v '^#' | wc -l")
    usb_disabled = safe_int_parse(result.stdout.strip()) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Pass" if usb_disabled or not usb_storage_loaded else "Info",
        message=f"{get_iso_id('1', 3)}: USB storage restrictions",
        details="Restricted" if usb_disabled else "Loaded" if usb_storage_loaded else "Not loaded",
        remediation="Disable: echo 'install usb-storage /bin/true' > /etc/modprobe.d/disable-usb.conf"
    ))
    
    # A.8.1-004: Bluetooth disabled
    bluetooth_active = check_service_active('bluetooth')
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Pass" if not bluetooth_active else "Info",
        message=f"{get_iso_id('1', 4)}: Bluetooth service status",
        details="Disabled" if not bluetooth_active else "Active",
        remediation="Disable: systemctl disable bluetooth"
    ))
    
    # A.8.1-005: Wireless interfaces
    result = run_command("iwconfig 2>&1 | grep -c 'IEEE' || echo 0")
    wireless_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Info",
        message=f"{get_iso_id('1', 5)}: Wireless network interfaces",
        details=f"{wireless_count} wireless interfaces",
        remediation="Disable unused wireless interfaces"
    ))
    
    # A.8.1-006: Full disk encryption (LUKS)
    result = run_command("lsblk -o NAME,FSTYPE | grep -c crypt || echo 0")
    encrypted_volumes = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Pass" if encrypted_volumes > 0 else "Warning",
        message=f"{get_iso_id('1', 6)}: Disk encryption (LUKS)",
        details=f"{encrypted_volumes} encrypted volumes",
        remediation="Enable full disk encryption during installation"
    ))
    
    # A.8.1-007: Automatic updates configured
    if os_info.family == 'debian':
        auto_updates = check_package_installed('unattended-upgrades', os_info)
    elif os_info.family == 'redhat':
        auto_updates = check_package_installed('yum-cron', os_info) or check_package_installed('dnf-automatic', os_info)
    else:
        auto_updates = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Pass" if auto_updates else "Warning",
        message=f"{get_iso_id('1', 7)}: Automatic security updates",
        details="Configured" if auto_updates else "Not configured",
        remediation="Enable automatic updates"
    ))
    
    # A.8.1-008: System firewall active
    firewall_services = ['ufw', 'firewalld', 'iptables']
    firewall_active = any(check_service_active(svc) for svc in firewall_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Pass" if firewall_active else "Fail",
        message=f"{get_iso_id('1', 8)}: Host-based firewall active",
        details="Active" if firewall_active else "Not active",
        remediation="Enable firewall: ufw enable || systemctl enable firewalld"
    ))
    
    # A.8.1-009: Anti-malware installed
    av_installed = check_package_installed('clamav', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Pass" if av_installed else "Warning",
        message=f"{get_iso_id('1', 9)}: Anti-malware software",
        details="ClamAV installed" if av_installed else "Not installed",
        remediation="Install: apt-get install clamav || yum install clamav"
    ))
    
    # A.8.1-010: Home directory encryption
    result = run_command("ls -la /home/ 2>/dev/null | grep -c '.ecryptfs' || echo 0")
    encrypted_homes = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Info",
        message=f"{get_iso_id('1', 10)}: Home directory encryption",
        details=f"{encrypted_homes} encrypted home directories",
        remediation="Consider ecryptfs for sensitive user data"
    ))
    
    # A.8.1-011: Removable media automount
    autofs_enabled = check_service_active('autofs')
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Pass" if not autofs_enabled else "Warning",
        message=f"{get_iso_id('1', 11)}: Removable media automount",
        details="Disabled" if not autofs_enabled else "Enabled",
        remediation="Disable: systemctl disable autofs"
    ))
    
    # A.8.1-012: Camera/microphone controls
    # Check if camera is available
    camera_present = os.path.exists("/dev/video0")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Info",
        message=f"{get_iso_id('1', 12)}: Webcam/microphone present",
        details="Camera detected" if camera_present else "No camera",
        remediation="Consider disabling or covering webcam if not needed"
    ))
    
    # A.8.1-013: System integrity tools
    integrity_tools = ['aide', 'tripwire', 'samhain']
    installed_tools = [tool for tool in integrity_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Pass" if installed_tools else "Warning",
        message=f"{get_iso_id('1', 13)}: File integrity monitoring",
        details=f"Installed: {', '.join(installed_tools)}" if installed_tools else "Not installed",
        remediation="Install AIDE: apt-get install aide || yum install aide"
    ))
    
    # A.8.1-014: Display manager security
    display_managers = ['gdm', 'gdm3', 'lightdm', 'sddm']
    active_dm = [dm for dm in display_managers if check_service_active(dm)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Info",
        message=f"{get_iso_id('1', 14)}: Display manager configured",
        details=f"Active: {', '.join(active_dm)}" if active_dm else "None (server mode)",
        remediation="Configure display manager security settings"
    ))
    
    # A.8.1-015: Guest account disabled
    result = run_command("grep -E '^guest' /etc/passwd 2>/dev/null | wc -l")
    guest_exists = safe_int_parse(result.stdout.strip()) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.1 User Endpoint Devices",
        status="Pass" if not guest_exists else "Warning",
        message=f"{get_iso_id('1', 15)}: Guest account disabled",
        details="Guest account exists" if guest_exists else "No guest account",
        remediation="Disable guest account in display manager config"
    ))


# ============================================================================
# A.8.2-A.8.5: Privileged Access, Information Access, Source Code, Authentication
# ============================================================================

def check_privileged_access_authentication(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    ISO 27001 A.8.2: Privileged access rights
    ISO 27001 A.8.3: Information access restriction  
    ISO 27001 A.8.4: Access to source code
    ISO 27001 A.8.5: Secure authentication
    """
    print(f"[{MODULE_NAME}] Checking A.8.2-A.8.5 Access Control & Authentication...")
    
    # A.8.2: Privileged Access Rights
    
    # A.8.2-001: Root account access
    result = run_command("awk -F: '$3 == 0 {print $1}' /etc/passwd")
    uid0_accounts = [u.strip() for u in result.stdout.strip().split('\n') if u.strip()]
    only_root = len(uid0_accounts) == 1 and uid0_accounts[0] == 'root'
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.2 Privileged Access Rights",
        status="Pass" if only_root else "Fail",
        message=f"{get_iso_id('2', 1)}: Only root has UID 0",
        details=f"UID 0: {', '.join(uid0_accounts)}",
        remediation="Remove UID 0 from non-root accounts"
    ))
    
    # A.8.2-002: sudo installed and configured
    sudo_installed = check_package_installed('sudo', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.2 Privileged Access Rights",
        status="Pass" if sudo_installed else "Fail",
        message=f"{get_iso_id('2', 2)}: sudo package installed",
        details="Installed" if sudo_installed else "Not installed",
        remediation="Install sudo"
    ))
    
    # A.8.2-003: sudoers file permissions
    if os.path.exists("/etc/sudoers"):
        perms = get_file_permissions("/etc/sudoers")
        perms_ok = perms == '440' or perms == '400'
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.2 Privileged Access Rights",
            status="Pass" if perms_ok else "Fail",
            message=f"{get_iso_id('2', 3)}: /etc/sudoers permissions secure",
            details=f"Permissions: {perms}",
            remediation="chmod 440 /etc/sudoers"
        ))
    
    # A.8.2-004: sudo requires authentication
    if os.path.exists("/etc/sudoers"):
        content = read_file_safe("/etc/sudoers")
        nopasswd_count = len(re.findall(r'NOPASSWD', content, re.IGNORECASE))
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.2 Privileged Access Rights",
            status="Warning" if nopasswd_count > 2 else "Pass",
            message=f"{get_iso_id('2', 4)}: sudo authentication required",
            details=f"{nopasswd_count} NOPASSWD entries",
            remediation="Minimize NOPASSWD usage in sudoers"
        ))
    
    # A.8.2-005: SSH root login disabled
    ssh_config = "/etc/ssh/sshd_config"
    if os.path.exists(ssh_config):
        content = read_file_safe(ssh_config)
        root_login = re.search(r'^PermitRootLogin\s+(\S+)', content, re.MULTILINE)
        root_disabled = root_login and root_login.group(1).lower() == 'no'
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.2 Privileged Access Rights",
            status="Pass" if root_disabled else "Fail",
            message=f"{get_iso_id('2', 5)}: SSH root login disabled",
            details=f"PermitRootLogin: {root_login.group(1) if root_login else 'default (yes)'}",
            remediation="Set PermitRootLogin no in /etc/ssh/sshd_config"
        ))
    
    # A.8.2-006: System accounts non-login
    result = run_command("awk -F: '$3 < 1000 && $3 != 0 && $7 !~ /nologin|false/ {print $1}' /etc/passwd | wc -l")
    system_with_shell = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.2 Privileged Access Rights",
        status="Pass" if system_with_shell == 0 else "Warning",
        message=f"{get_iso_id('2', 6)}: System accounts have nologin shell",
        details=f"{system_with_shell} system accounts with login shell",
        remediation="Set nologin shell: usermod -s /sbin/nologin <user>"
    ))
    
    # A.8.2-007: Privileged group membership
    if os_info.family == 'debian':
        sudo_group = 'sudo'
    else:
        sudo_group = 'wheel'
    
    result = run_command(f"getent group {sudo_group} 2>/dev/null | cut -d: -f4")
    sudo_members = result.stdout.strip()
    member_count = len([m for m in sudo_members.split(',') if m]) if sudo_members else 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.2 Privileged Access Rights",
        status="Info",
        message=f"{get_iso_id('2', 7)}: Privileged group membership",
        details=f"{member_count} members in {sudo_group} group",
        remediation="Review and minimize privileged group membership"
    ))
    
    # A.8.2-008: Audit logging for privileged commands
    if os.path.exists("/etc/audit/rules.d/"):
        result = run_command("grep -r 'perm=x' /etc/audit/rules.d/ 2>/dev/null | wc -l")
        exec_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.2 Privileged Access Rights",
            status="Pass" if exec_rules > 0 else "Warning",
            message=f"{get_iso_id('2', 8)}: Privileged command auditing",
            details=f"{exec_rules} execution audit rules",
            remediation="Configure auditd to log privileged commands"
        ))
    
    # A.8.3: Information Access Restriction
    
    # A.8.3-001: File permissions - /etc/passwd
    exists, perms, owner = check_file_exists_secure("/etc/passwd")
    perms_ok = exists and perms and int(perms, 8) <= int('644', 8)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.3 Information Access Restriction",
        status="Pass" if perms_ok else "Fail",
        message=f"{get_iso_id('3', 1)}: /etc/passwd permissions",
        details=f"Permissions: {perms}" if exists else "File missing",
        remediation="chmod 644 /etc/passwd"
    ))
    
    # A.8.3-002: File permissions - /etc/shadow
    exists, perms, owner = check_file_exists_secure("/etc/shadow")
    perms_ok = exists and perms and int(perms, 8) <= int('000', 8)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.3 Information Access Restriction",
        status="Pass" if perms_ok else "Fail",
        message=f"{get_iso_id('3', 2)}: /etc/shadow permissions",
        details=f"Permissions: {perms}" if exists else "File missing",
        remediation="chmod 000 /etc/shadow"
    ))
    
    # A.8.3-003: File permissions - /etc/group
    exists, perms, owner = check_file_exists_secure("/etc/group")
    perms_ok = exists and perms and int(perms, 8) <= int('644', 8)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.3 Information Access Restriction",
        status="Pass" if perms_ok else "Fail",
        message=f"{get_iso_id('3', 3)}: /etc/group permissions",
        details=f"Permissions: {perms}" if exists else "File missing",
        remediation="chmod 644 /etc/group"
    ))
    
    # A.8.3-004: File permissions - /etc/gshadow
    if os.path.exists("/etc/gshadow"):
        exists, perms, owner = check_file_exists_secure("/etc/gshadow")
        perms_ok = perms and int(perms, 8) <= int('000', 8)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.3 Information Access Restriction",
            status="Pass" if perms_ok else "Fail",
            message=f"{get_iso_id('3', 4)}: /etc/gshadow permissions",
            details=f"Permissions: {perms}",
            remediation="chmod 000 /etc/gshadow"
        ))
    
    # A.8.3-005: World-writable files
    result = run_command("find / -xdev -type f -perm -0002 2>/dev/null | head -20 | wc -l")
    ww_files = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.3 Information Access Restriction",
        status="Pass" if ww_files == 0 else "Fail",
        message=f"{get_iso_id('3', 5)}: No world-writable files",
        details=f"{ww_files} world-writable files",
        remediation="Remove world-write: chmod o-w <file>"
    ))
    
    # A.8.3-006: Unowned files
    result = run_command("find / -xdev \\( -nouser -o -nogroup \\) 2>/dev/null | head -10 | wc -l")
    unowned = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.3 Information Access Restriction",
        status="Pass" if unowned == 0 else "Warning",
        message=f"{get_iso_id('3', 6)}: No unowned files",
        details=f"{unowned} unowned files",
        remediation="Assign ownership: chown <user>:<group> <file>"
    ))
    
    # A.8.3-007: Home directory permissions
    result = run_command("find /home -maxdepth 1 -type d -perm -0022 2>/dev/null | wc -l")
    open_homes = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.3 Information Access Restriction",
        status="Pass" if open_homes <= 1 else "Warning",  # /home itself might match
        message=f"{get_iso_id('3', 7)}: Home directory permissions secure",
        details=f"{open_homes} directories with group/other write",
        remediation="chmod 750 /home/<user>"
    ))
    
    # A.8.3-008: Default umask
    if os.path.exists("/etc/login.defs"):
        content = read_file_safe("/etc/login.defs")
        umask = re.search(r'^UMASK\s+(\d+)', content, re.MULTILINE)
        umask_ok = umask and umask.group(1) in ['027', '077']
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.3 Information Access Restriction",
            status="Pass" if umask_ok else "Warning",
            message=f"{get_iso_id('3', 8)}: Default umask secure",
            details=f"UMASK: {umask.group(1) if umask else 'not set'}",
            remediation="Set UMASK 027 in /etc/login.defs"
        ))
    
    # A.8.3-009: Sticky bit on /tmp
    if os.path.exists("/tmp"):
        perms = get_file_permissions("/tmp")
        sticky_set = perms and perms.startswith('1')
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.3 Information Access Restriction",
            status="Pass" if sticky_set else "Fail",
            message=f"{get_iso_id('3', 9)}: Sticky bit on /tmp",
            details=f"Permissions: {perms}",
            remediation="chmod 1777 /tmp"
        ))
    
    # A.8.3-010: MAC system active
    if os_info.family == 'debian':
        mac_active = check_service_active('apparmor')
        mac_name = "AppArmor"
    elif os_info.family == 'redhat':
        result = run_command("getenforce 2>/dev/null")
        mac_active = result.returncode == 0 and 'enforcing' in result.stdout.lower()
        mac_name = "SELinux"
    else:
        mac_active = False
        mac_name = "MAC"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.3 Information Access Restriction",
        status="Pass" if mac_active else "Warning",
        message=f"{get_iso_id('3', 10)}: Mandatory Access Control active",
        details=f"{mac_name}: {'Active' if mac_active else 'Inactive'}",
        remediation=f"Enable {mac_name}"
    ))
    
    # A.8.4: Access to Source Code
    
    # A.8.4-001: Development tools on production
    dev_tools = ['gcc', 'g++', 'make', 'gdb', 'git']
    installed_dev = [tool for tool in dev_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.4 Access to Source Code",
        status="Warning" if installed_dev else "Pass",
        message=f"{get_iso_id('4', 1)}: Development tools on system",
        details=f"Installed: {', '.join(installed_dev)}" if installed_dev else "None",
        remediation="Remove dev tools from production: apt-get remove build-essential"
    ))
    
    # A.8.4-002: Source code directories
    source_dirs = ['/usr/src', '/opt/src', '/home/*/src']
    found_sources = []
    for pattern in source_dirs:
        if '*' in pattern:
            found_sources.extend(glob.glob(pattern))
        elif os.path.exists(pattern):
            result = run_command(f"find {pattern} -type f -name '*.c' -o -name '*.cpp' -o -name '*.py' 2>/dev/null | wc -l")
            if safe_int_parse(result.stdout.strip()) > 0:
                found_sources.append(pattern)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.4 Access to Source Code",
        status="Info",
        message=f"{get_iso_id('4', 2)}: Source code directories",
        details=f"{len(found_sources)} directories with source code",
        remediation="Ensure proper access controls on source code"
    ))
    
    # A.8.4-003: Version control systems
    vcs_tools = ['git', 'svn', 'hg', 'cvs']
    installed_vcs = [tool for tool in vcs_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.4 Access to Source Code",
        status="Info",
        message=f"{get_iso_id('4', 3)}: Version control systems",
        details=f"Installed: {', '.join(installed_vcs)}" if installed_vcs else "None",
        remediation="Ensure VCS repositories have proper access controls"
    ))
    
    # A.8.5: Secure Authentication
    
    # A.8.5-001: Password complexity requirements
    pam_pwquality = check_pam_module('pam_pwquality') or check_pam_module('pam_cracklib')
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.5 Secure Authentication",
        status="Pass" if pam_pwquality else "Fail",
        message=f"{get_iso_id('5', 1)}: Password complexity enforced",
        details="pam_pwquality configured" if pam_pwquality else "Not configured",
        remediation="Configure pam_pwquality in PAM"
    ))
    
    # A.8.5-002: Password aging
    policy = get_password_policy()
    max_days_ok = policy['max_days'] and policy['max_days'] <= 90
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.5 Secure Authentication",
        status="Pass" if max_days_ok else "Warning",
        message=f"{get_iso_id('5', 2)}: Password maximum age",
        details=f"PASS_MAX_DAYS: {policy['max_days']}" if policy['max_days'] else "Not set",
        remediation="Set PASS_MAX_DAYS 90 in /etc/login.defs"
    ))
    
    # A.8.5-003: Password minimum age
    min_days_ok = policy['min_days'] and policy['min_days'] >= 1
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.5 Secure Authentication",
        status="Pass" if min_days_ok else "Warning",
        message=f"{get_iso_id('5', 3)}: Password minimum age",
        details=f"PASS_MIN_DAYS: {policy['min_days']}" if policy['min_days'] else "Not set",
        remediation="Set PASS_MIN_DAYS 1 in /etc/login.defs"
    ))
    
    # A.8.5-004: Password minimum length
    min_len_ok = policy['min_length'] and policy['min_length'] >= 12
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.5 Secure Authentication",
        status="Pass" if min_len_ok else "Warning",
        message=f"{get_iso_id('5', 4)}: Password minimum length",
        details=f"PASS_MIN_LEN: {policy['min_length']}" if policy['min_length'] else "Not set",
        remediation="Set minlen=12 in pam_pwquality"
    ))
    
    # A.8.5-005: Account lockout policy
    pam_faillock = check_pam_module('pam_faillock') or check_pam_module('pam_tally2')
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.5 Secure Authentication",
        status="Pass" if pam_faillock else "Warning",
        message=f"{get_iso_id('5', 5)}: Account lockout configured",
        details="pam_faillock configured" if pam_faillock else "Not configured",
        remediation="Configure pam_faillock in PAM"
    ))
    
    # A.8.5-006: No empty passwords
    result = run_command("awk -F: '$2 == \"\" {print $1}' /etc/shadow 2>/dev/null | wc -l")
    empty_passwords = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.5 Secure Authentication",
        status="Pass" if empty_passwords == 0 else "Fail",
        message=f"{get_iso_id('5', 6)}: No accounts with empty passwords",
        details=f"{empty_passwords} accounts with empty passwords",
        remediation="Lock or set passwords for all accounts"
    ))
    
    # A.8.5-007: SSH password authentication
    if os.path.exists("/etc/ssh/sshd_config"):
        content = read_file_safe("/etc/ssh/sshd_config")
        password_auth = re.search(r'^PasswordAuthentication\s+(\S+)', content, re.MULTILINE)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.5 Secure Authentication",
            status="Info",
            message=f"{get_iso_id('5', 7)}: SSH password authentication",
            details=f"PasswordAuthentication: {password_auth.group(1) if password_auth else 'default (yes)'}",
            remediation="Consider key-based authentication only"
        ))
    
    # A.8.5-008: SSH public key authentication
    if os.path.exists("/etc/ssh/sshd_config"):
        content = read_file_safe("/etc/ssh/sshd_config")
        pubkey_auth = re.search(r'^PubkeyAuthentication\s+(\S+)', content, re.MULTILINE)
        pubkey_enabled = not pubkey_auth or pubkey_auth.group(1).lower() == 'yes'
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.5 Secure Authentication",
            status="Pass" if pubkey_enabled else "Warning",
            message=f"{get_iso_id('5', 8)}: SSH public key authentication enabled",
            details=f"PubkeyAuthentication: {pubkey_auth.group(1) if pubkey_auth else 'default (yes)'}",
            remediation="Enable PubkeyAuthentication in sshd_config"
        ))
    
    # A.8.5-009: Password hashing algorithm
    if os.path.exists("/etc/login.defs"):
        content = read_file_safe("/etc/login.defs")
        encrypt_method = re.search(r'^ENCRYPT_METHOD\s+(\S+)', content, re.MULTILINE)
        strong_hash = encrypt_method and encrypt_method.group(1) in ['SHA512', 'YESCRYPT']
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.5 Secure Authentication",
            status="Pass" if strong_hash else "Warning",
            message=f"{get_iso_id('5', 9)}: Strong password hashing",
            details=f"ENCRYPT_METHOD: {encrypt_method.group(1) if encrypt_method else 'not set'}",
            remediation="Set ENCRYPT_METHOD SHA512 in /etc/login.defs"
        ))
    
    # A.8.5-010: Failed login tracking
    failed_attempts = get_failed_login_attempts()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.5 Secure Authentication",
        status="Info",
        message=f"{get_iso_id('5', 10)}: Failed login attempts tracked",
        details=f"{failed_attempts} recent failed logins",
        remediation="Review failed login attempts regularly"
    ))


# ============================================================================
# A.8.6-A.8.10: Capacity, Malware, Vulnerabilities, Configuration, Data Protection
# ============================================================================

def check_system_protection_management(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    ISO 27001 A.8.6: Capacity management
    ISO 27001 A.8.7: Protection against malware
    ISO 27001 A.8.8: Management of technical vulnerabilities
    ISO 27001 A.8.9: Configuration management
    ISO 27001 A.8.10: Information deletion
    """
    print(f"[{MODULE_NAME}] Checking A.8.6-A.8.10 Protection & Management...")
    
    # A.8.6: Capacity Management
    
    # A.8.6-001: Disk space monitoring
    result = run_command("df -h / | tail -1 | awk '{print $5}' | sed 's/%//'")
    root_usage = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.6 Capacity Management",
        status="Pass" if root_usage < 90 else "Warning" if root_usage < 95 else "Fail",
        message=f"{get_iso_id('6', 1)}: Root filesystem capacity",
        details=f"Usage: {root_usage}%",
        remediation="Clean up disk space or expand partition"
    ))
    
    # A.8.6-002: Memory availability
    result = run_command("free | grep Mem | awk '{print int($3/$2 * 100)}'")
    mem_usage = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.6 Capacity Management",
        status="Pass" if mem_usage < 90 else "Warning",
        message=f"{get_iso_id('6', 2)}: Memory utilization",
        details=f"Usage: {mem_usage}%",
        remediation="Review memory usage and optimize"
    ))
    
    # A.8.6-003: System load average
    result = run_command("uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//'")
    load_avg = result.stdout.strip()
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.6 Capacity Management",
        status="Info",
        message=f"{get_iso_id('6', 3)}: System load average",
        details=f"Load: {load_avg}",
        remediation="Monitor system load trends"
    ))
    
    # A.8.6-004: Monitoring tools installed
    mon_tools = ['sar', 'vmstat', 'iostat', 'mpstat']
    installed_mon = [tool for tool in mon_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.6 Capacity Management",
        status="Pass" if installed_mon else "Warning",
        message=f"{get_iso_id('6', 4)}: System monitoring tools",
        details=f"Installed: {', '.join(installed_mon)}" if installed_mon else "None",
        remediation="Install sysstat: apt-get install sysstat"
    ))
    
    # A.8.6-005: Log rotation configured
    logrotate_installed = check_package_installed('logrotate', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.6 Capacity Management",
        status="Pass" if logrotate_installed else "Fail",
        message=f"{get_iso_id('6', 5)}: Log rotation configured",
        details="logrotate installed" if logrotate_installed else "Not installed",
        remediation="Install logrotate"
    ))
    
    # A.8.7: Protection Against Malware
    
    # A.8.7-001: Anti-malware installed
    av_installed = check_package_installed('clamav', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.7 Protection Against Malware",
        status="Pass" if av_installed else "Warning",
        message=f"{get_iso_id('7', 1)}: Anti-malware software installed",
        details="ClamAV installed" if av_installed else "Not installed",
        remediation="Install: apt-get install clamav"
    ))
    
    # A.8.7-002: Anti-malware daemon active
    if av_installed:
        av_active = check_service_active('clamav-daemon') or check_service_active('clamd')
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.7 Protection Against Malware",
            status="Pass" if av_active else "Warning",
            message=f"{get_iso_id('7', 2)}: Anti-malware daemon active",
            details="Active" if av_active else "Not active",
            remediation="Start: systemctl start clamav-daemon"
        ))
    
    # A.8.7-003: Anti-malware definitions updated
    if av_installed and os.path.exists("/var/lib/clamav"):
        db_files = glob.glob("/var/lib/clamav/*.cvd") + glob.glob("/var/lib/clamav/*.cld")
        if db_files:
            newest_db = max(db_files, key=os.path.getmtime)
            import time
            db_age = int((time.time() - os.path.getmtime(newest_db)) / 86400)
            defs_current = db_age <= 7
        else:
            defs_current = False
            db_age = None
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.7 Protection Against Malware",
            status="Pass" if defs_current else "Warning",
            message=f"{get_iso_id('7', 3)}: Anti-malware definitions current",
            details=f"Last update: {db_age} days ago" if db_age is not None else "No definitions",
            remediation="Update: freshclam"
        ))
    
    # A.8.7-004: Automatic updates for malware definitions
    freshclam_enabled = check_service_enabled('clamav-freshclam')
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.7 Protection Against Malware",
        status="Pass" if freshclam_enabled else "Warning",
        message=f"{get_iso_id('7', 4)}: Automatic malware definition updates",
        details="Enabled" if freshclam_enabled else "Not enabled",
        remediation="Enable: systemctl enable clamav-freshclam"
    ))
    
    # A.8.7-005: Rootkit detection tools
    rk_tools = ['rkhunter', 'chkrootkit']
    installed_rk = [tool for tool in rk_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.7 Protection Against Malware",
        status="Pass" if installed_rk else "Warning",
        message=f"{get_iso_id('7', 5)}: Rootkit detection tools",
        details=f"Installed: {', '.join(installed_rk)}" if installed_rk else "Not installed",
        remediation="Install: apt-get install rkhunter chkrootkit"
    ))
    
    # A.8.8: Management of Technical Vulnerabilities
    
    # A.8.8-001: Security updates available
    security_updates = get_security_updates(os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.8 Technical Vulnerabilities",
        status="Pass" if security_updates == 0 else "Fail",
        message=f"{get_iso_id('8', 1)}: Security updates applied",
        details=f"{security_updates} security updates pending",
        remediation="Apply security updates immediately"
    ))
    
    # A.8.8-002: Automatic security updates
    if os_info.family == 'debian':
        auto_updates = check_package_installed('unattended-upgrades', os_info)
    elif os_info.family == 'redhat':
        auto_updates = check_package_installed('yum-cron', os_info) or check_package_installed('dnf-automatic', os_info)
    else:
        auto_updates = False
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.8 Technical Vulnerabilities",
        status="Pass" if auto_updates else "Warning",
        message=f"{get_iso_id('8', 2)}: Automatic security updates configured",
        details="Configured" if auto_updates else "Not configured",
        remediation="Enable automatic security updates"
    ))
    
    # A.8.8-003: Vulnerability scanning tools
    vuln_tools = ['openvas', 'nessus', 'lynis']
    installed_vuln = [tool for tool in vuln_tools if command_exists(tool) or check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.8 Technical Vulnerabilities",
        status="Info",
        message=f"{get_iso_id('8', 3)}: Vulnerability scanning tools",
        details=f"Installed: {', '.join(installed_vuln)}" if installed_vuln else "Not installed",
        remediation="Consider installing Lynis for security auditing"
    ))
    
    # A.8.8-004: Kernel version current
    running_kernel = platform.release()
    
    if os_info.package_manager == 'apt':
        result = run_command("dpkg -l | grep '^ii.*linux-image' | awk '{print $3}' | sort -V | tail -1")
        latest_kernel = result.stdout.strip()
        kernel_current = running_kernel in latest_kernel
    elif os_info.package_manager in ['yum', 'dnf']:
        result = run_command("rpm -q kernel | sort -V | tail -1")
        latest_kernel = result.stdout.strip()
        kernel_current = running_kernel in latest_kernel
    else:
        kernel_current = True
        latest_kernel = "unknown"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.8 Technical Vulnerabilities",
        status="Pass" if kernel_current else "Warning",
        message=f"{get_iso_id('8', 4)}: Kernel version current",
        details=f"Running: {running_kernel}"[:60],
        remediation="Reboot to use updated kernel"
    ))
    
    # A.8.8-005: Patch management process
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.8 Technical Vulnerabilities",
        status="Info",
        message=f"{get_iso_id('8', 5)}: Patch management process",
        details="Review patching procedures",
        remediation="Establish regular patching schedule"
    ))
    
    # A.8.9: Configuration Management
    
    # A.8.9-001: System configuration baseline
    baseline_files = ['/etc/security/baseline.txt', '/root/baseline.txt']
    baseline_exists = any(os.path.exists(f) for f in baseline_files)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.9 Configuration Management",
        status="Info",
        message=f"{get_iso_id('9', 1)}: System configuration baseline",
        details="Baseline documented" if baseline_exists else "No baseline found",
        remediation="Document system baseline configuration"
    ))
    
    # A.8.9-002: Configuration management tools
    cm_tools = ['ansible', 'puppet', 'chef', 'saltstack']
    installed_cm = [tool for tool in cm_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.9 Configuration Management",
        status="Info",
        message=f"{get_iso_id('9', 2)}: Configuration management tools",
        details=f"Installed: {', '.join(installed_cm)}" if installed_cm else "Not installed",
        remediation="Consider configuration management automation"
    ))
    
    # A.8.9-003: File integrity monitoring
    fim_tools = ['aide', 'tripwire', 'samhain']
    installed_fim = [tool for tool in fim_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.9 Configuration Management",
        status="Pass" if installed_fim else "Warning",
        message=f"{get_iso_id('9', 3)}: File integrity monitoring",
        details=f"Installed: {', '.join(installed_fim)}" if installed_fim else "Not installed",
        remediation="Install AIDE: apt-get install aide"
    ))
    
    # A.8.9-004: AIDE database initialized
    if 'aide' in installed_fim:
        aide_db = os.path.exists("/var/lib/aide/aide.db") or os.path.exists("/var/lib/aide/aide.db.gz")
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.9 Configuration Management",
            status="Pass" if aide_db else "Warning",
            message=f"{get_iso_id('9', 4)}: AIDE database initialized",
            details="Database exists" if aide_db else "Not initialized",
            remediation="Initialize: aideinit"
        ))
    
    # A.8.9-005: System changes audited
    auditd_active = check_service_active('auditd')
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.9 Configuration Management",
        status="Pass" if auditd_active else "Warning",
        message=f"{get_iso_id('9', 5)}: System changes audited",
        details="auditd active" if auditd_active else "Not active",
        remediation="Enable: systemctl enable auditd"
    ))
    
    # A.8.9-006: Boot loader password
    grub_cfg_files = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]
    grub_password = False
    
    for grub_file in grub_cfg_files:
        if os.path.exists(grub_file):
            content = read_file_safe(grub_file)
            if "password_pbkdf2" in content or "password" in content:
                grub_password = True
                break
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.9 Configuration Management",
        status="Pass" if grub_password else "Warning",
        message=f"{get_iso_id('9', 6)}: Boot loader password protection",
        details="Password set" if grub_password else "No password",
        remediation="Set GRUB password: grub-mkpasswd-pbkdf2"
    ))
    
    # A.8.9-007: Single user mode authentication
    if os.path.exists("/usr/lib/systemd/system/rescue.service"):
        rescue_service = read_file_safe("/usr/lib/systemd/system/rescue.service")
        sulogin_required = "sulogin" in rescue_service
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.9 Configuration Management",
            status="Pass" if sulogin_required else "Fail",
            message=f"{get_iso_id('9', 7)}: Single user mode authentication",
            details="sulogin required" if sulogin_required else "No authentication",
            remediation="Configure sulogin in rescue.service"
        ))
    
    # A.8.9-008: Kernel module restrictions
    modprobe_restrictions = len(glob.glob("/etc/modprobe.d/*.conf"))
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.9 Configuration Management",
        status="Pass" if modprobe_restrictions > 0 else "Info",
        message=f"{get_iso_id('9', 8)}: Kernel module restrictions",
        details=f"{modprobe_restrictions} restriction files",
        remediation="Configure module restrictions in /etc/modprobe.d/"
    ))
    
    # A.8.10: Information Deletion
    
    # A.8.10-001: Secure deletion tools
    secure_del_tools = ['shred', 'wipe', 'srm']
    installed_del = [tool for tool in secure_del_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.10 Information Deletion",
        status="Pass" if installed_del else "Info",
        message=f"{get_iso_id('10', 1)}: Secure deletion tools available",
        details=f"Available: {', '.join(installed_del)}" if installed_del else "shred (built-in)",
        remediation="Use shred for secure file deletion"
    ))
    
    # A.8.10-002: Disk wiping procedures
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.10 Information Deletion",
        status="Info",
        message=f"{get_iso_id('10', 2)}: Secure disk wiping procedures",
        details="Document procedures for disk decommissioning",
        remediation="Use dd, shred, or DBAN for disk wiping"
    ))
    
    # A.8.10-003: /tmp cleanup on reboot
    tmp_cleanup = False
    if os.path.exists("/usr/lib/tmpfiles.d/tmp.conf"):
        content = read_file_safe("/usr/lib/tmpfiles.d/tmp.conf")
        tmp_cleanup = "D /tmp" in content
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.10 Information Deletion",
        status="Pass" if tmp_cleanup else "Info",
        message=f"{get_iso_id('10', 3)}: Temporary files cleaned on reboot",
        details="Configured" if tmp_cleanup else "Check configuration",
        remediation="Configure tmpfiles.d for /tmp cleanup"
    ))


# ============================================================================
# A.8.11-A.8.20: Backup, Logging, Monitoring, Clock Sync, Network Security
# ============================================================================

def check_backup_monitoring_network(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    ISO 27001 A.8.11-A.8.13: Data protection and backup
    ISO 27001 A.8.14-A.8.17: Reliability and monitoring  
    ISO 27001 A.8.18-A.8.20: System and network security
    """
    print(f"[{MODULE_NAME}] Checking A.8.11-A.8.20 Backup, Monitoring & Network...")
    
    # A.8.13: Information Backup
    
    # A.8.13-001: Backup tools installed
    backup_tools = ['rsync', 'tar', 'duplicity', 'bacula', 'amanda']
    installed_backup = [tool for tool in backup_tools if command_exists(tool)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.13 Information Backup",
        status="Pass" if installed_backup else "Warning",
        message=f"{get_iso_id('13', 1)}: Backup tools available",
        details=f"Available: {', '.join(installed_backup)}" if installed_backup else "None",
        remediation="Install backup tools: rsync, tar"
    ))
    
    # A.8.13-002: Backup directories exist
    backup_dirs = ['/backup', '/var/backups', '/mnt/backup']
    existing_backup_dirs = [d for d in backup_dirs if os.path.exists(d)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.13 Information Backup",
        status="Info",
        message=f"{get_iso_id('13', 2)}: Backup directories",
        details=f"Found: {', '.join(existing_backup_dirs)}" if existing_backup_dirs else "None",
        remediation="Create and configure backup directories"
    ))
    
    # A.8.13-003: Scheduled backups (cron)
    result = run_command("grep -r 'rsync\\|tar\\|backup' /etc/cron* /var/spool/cron 2>/dev/null | grep -v '#' | wc -l")
    backup_jobs = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.13 Information Backup",
        status="Pass" if backup_jobs > 0 else "Warning",
        message=f"{get_iso_id('13', 3)}: Scheduled backup jobs",
        details=f"{backup_jobs} scheduled backup jobs",
        remediation="Configure automated backups in cron"
    ))
    
    # A.8.15: Logging
    
    # A.8.15-001: System logging active
    logging_services = ['rsyslog', 'syslog-ng', 'systemd-journald']
    logging_active = any(check_service_active(svc) for svc in logging_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.15 Logging",
        status="Pass" if logging_active else "Fail",
        message=f"{get_iso_id('15', 1)}: System logging active",
        details="Active" if logging_active else "Not active",
        remediation="Enable rsyslog: systemctl enable rsyslog"
    ))
    
    # A.8.15-002: Log files exist and writable
    log_files = ['/var/log/messages', '/var/log/syslog', '/var/log/auth.log', '/var/log/secure']
    existing_logs = [f for f in log_files if os.path.exists(f)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.15 Logging",
        status="Pass" if existing_logs else "Warning",
        message=f"{get_iso_id('15', 2)}: System log files present",
        details=f"{len(existing_logs)} log files found",
        remediation="Verify logging configuration"
    ))
    
    # A.8.15-003: Audit daemon active
    auditd_active = check_service_active('auditd')
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.15 Logging",
        status="Pass" if auditd_active else "Warning",
        message=f"{get_iso_id('15', 3)}: Audit daemon (auditd) active",
        details="Active" if auditd_active else "Not active",
        remediation="Enable: systemctl enable auditd"
    ))
    
    # A.8.15-004: Audit rules configured
    if auditd_active:
        result = run_command("auditctl -l 2>/dev/null | grep -v 'No rules' | wc -l")
        audit_rules = safe_int_parse(result.stdout.strip())
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.15 Logging",
            status="Pass" if audit_rules >= 10 else "Warning",
            message=f"{get_iso_id('15', 4)}: Audit rules configured",
            details=f"{audit_rules} audit rules",
            remediation="Configure audit rules in /etc/audit/rules.d/"
        ))
    
    # A.8.15-005: Log rotation configured
    logrotate_installed = check_package_installed('logrotate', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.15 Logging",
        status="Pass" if logrotate_installed else "Fail",
        message=f"{get_iso_id('15', 5)}: Log rotation configured",
        details="logrotate installed" if logrotate_installed else "Not installed",
        remediation="Install logrotate"
    ))
    
    # A.8.15-006: Remote logging configured
    if os.path.exists("/etc/rsyslog.conf"):
        content = read_file_safe("/etc/rsyslog.conf")
        remote_logging = bool(re.search(r'@@?\w', content))
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.15 Logging",
            status="Info",
            message=f"{get_iso_id('15', 6)}: Remote logging configured",
            details="Configured" if remote_logging else "Not configured",
            remediation="Configure remote syslog for centralized logging"
        ))
    
    # A.8.16: Monitoring Activities
    
    # A.8.16-001: System monitoring tools
    mon_tools = ['monit', 'nagios', 'zabbix', 'prometheus']
    installed_mon = [tool for tool in mon_tools if check_package_installed(tool, os_info)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.16 Monitoring Activities",
        status="Info",
        message=f"{get_iso_id('16', 1)}: System monitoring tools",
        details=f"Installed: {', '.join(installed_mon)}" if installed_mon else "Not installed",
        remediation="Consider installing monitoring tools"
    ))
    
    # A.8.16-002: Process monitoring
    result = run_command("ps aux | wc -l")
    process_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.16 Monitoring Activities",
        status="Info",
        message=f"{get_iso_id('16', 2)}: Active processes monitored",
        details=f"{process_count} processes running",
        remediation="Monitor process activity regularly"
    ))
    
    # A.8.16-003: Failed login monitoring
    fail2ban_installed = check_package_installed('fail2ban', os_info)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.16 Monitoring Activities",
        status="Pass" if fail2ban_installed else "Info",
        message=f"{get_iso_id('16', 3)}: Automated response to attacks",
        details="fail2ban installed" if fail2ban_installed else "Not installed",
        remediation="Install fail2ban for automated attack response"
    ))
    
    # A.8.16-004: Network monitoring
    result = run_command("ss -tuln 2>/dev/null | grep LISTEN | wc -l")
    listening_ports = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.16 Monitoring Activities",
        status="Info",
        message=f"{get_iso_id('16', 4)}: Network service monitoring",
        details=f"{listening_ports} listening ports",
        remediation="Monitor and minimize listening services"
    ))
    
    # A.8.17: Clock Synchronization
    
    # A.8.17-001: Time synchronization service
    time_services = ['chronyd', 'ntpd', 'systemd-timesyncd']
    time_active = any(check_service_active(svc) for svc in time_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.17 Clock Synchronization",
        status="Pass" if time_active else "Fail",
        message=f"{get_iso_id('17', 1)}: Time synchronization service",
        details="Active" if time_active else "Not active",
        remediation="Enable chronyd: systemctl enable chronyd"
    ))
    
    # A.8.17-002: NTP servers configured
    ntp_conf_files = ["/etc/chrony.conf", "/etc/ntp.conf", "/etc/systemd/timesyncd.conf"]
    ntp_servers = []
    
    for conf_file in ntp_conf_files:
        if os.path.exists(conf_file):
            content = read_file_safe(conf_file)
            ntp_servers.extend(re.findall(r'(?:server|pool|NTP)\s*=?\s*(\S+)', content, re.IGNORECASE))
    
    ntp_ok = len(ntp_servers) >= 2
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.17 Clock Synchronization",
        status="Pass" if ntp_ok else "Warning",
        message=f"{get_iso_id('17', 2)}: NTP servers configured",
        details=f"{len(ntp_servers)} time servers",
        remediation="Configure multiple NTP servers"
    ))
    
    # A.8.17-003: System time synchronized
    if time_active:
        result = run_command("timedatectl status 2>/dev/null | grep -i 'synchronized'")
        time_synced = 'yes' in result.stdout.lower()
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.17 Clock Synchronization",
            status="Pass" if time_synced else "Warning",
            message=f"{get_iso_id('17', 3)}: System clock synchronized",
            details="Synchronized" if time_synced else "Not synchronized",
            remediation="Verify NTP connectivity"
        ))
    
    # A.8.20: Networks Security
    
    # A.8.20-001: Firewall active
    firewall_services = ['ufw', 'firewalld', 'iptables']
    firewall_active = any(check_service_active(svc) for svc in firewall_services)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.20 Networks Security",
        status="Pass" if firewall_active else "Fail",
        message=f"{get_iso_id('20', 1)}: Firewall enabled",
        details="Active" if firewall_active else "Not active",
        remediation="Enable firewall: ufw enable || firewall-cmd --reload"
    ))
    
    # A.8.20-002: Default firewall policy
    if firewall_active:
        result = run_command("iptables -L | grep 'Chain INPUT' | grep -E '(DROP|REJECT)'")
        default_deny = result.returncode == 0
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.20 Networks Security",
            status="Pass" if default_deny else "Warning",
            message=f"{get_iso_id('20', 2)}: Default deny firewall policy",
            details="Default deny" if default_deny else "Check policy",
            remediation="Set default policy: iptables -P INPUT DROP"
        ))
    
    # A.8.20-003: IP forwarding disabled
    exists, ip_forward = check_kernel_parameter("net.ipv4.ip_forward")
    forward_disabled = ip_forward == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.20 Networks Security",
        status="Pass" if forward_disabled else "Warning",
        message=f"{get_iso_id('20', 3)}: IP forwarding disabled",
        details=f"ip_forward = {ip_forward}",
        remediation="Disable: sysctl -w net.ipv4.ip_forward=0"
    ))
    
    # A.8.20-004: ICMP redirects disabled
    exists, redirects = check_kernel_parameter("net.ipv4.conf.all.accept_redirects")
    redirects_disabled = redirects == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.20 Networks Security",
        status="Pass" if redirects_disabled else "Fail",
        message=f"{get_iso_id('20', 4)}: ICMP redirects disabled",
        details=f"accept_redirects = {redirects}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_redirects=0"
    ))
    
    # A.8.20-005: Source routing disabled
    exists, source_route = check_kernel_parameter("net.ipv4.conf.all.accept_source_route")
    source_disabled = source_route == "0"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.20 Networks Security",
        status="Pass" if source_disabled else "Fail",
        message=f"{get_iso_id('20', 5)}: Source routing disabled",
        details=f"accept_source_route = {source_route}",
        remediation="Disable: sysctl -w net.ipv4.conf.all.accept_source_route=0"
    ))
    
    # A.8.20-006: SYN cookies enabled
    exists, syn_cookies = check_kernel_parameter("net.ipv4.tcp_syncookies")
    syn_enabled = syn_cookies == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.20 Networks Security",
        status="Pass" if syn_enabled else "Warning",
        message=f"{get_iso_id('20', 6)}: TCP SYN cookies enabled",
        details=f"tcp_syncookies = {syn_cookies}",
        remediation="Enable: sysctl -w net.ipv4.tcp_syncookies=1"
    ))
    
    # A.8.20-007: Reverse path filtering
    exists, rp_filter = check_kernel_parameter("net.ipv4.conf.all.rp_filter")
    rp_enabled = rp_filter == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.20 Networks Security",
        status="Pass" if rp_enabled else "Warning",
        message=f"{get_iso_id('20', 7)}: Reverse path filtering enabled",
        details=f"rp_filter = {rp_filter}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.rp_filter=1"
    ))
    
    # A.8.20-008: Log martian packets
    exists, log_martians = check_kernel_parameter("net.ipv4.conf.all.log_martians")
    martians_logged = log_martians == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.20 Networks Security",
        status="Pass" if martians_logged else "Info",
        message=f"{get_iso_id('20', 8)}: Martian packets logged",
        details=f"log_martians = {log_martians}",
        remediation="Enable: sysctl -w net.ipv4.conf.all.log_martians=1"
    ))
    
    # A.8.20-009: ICMP broadcast ignored
    exists, icmp_broadcast = check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts")
    broadcast_ignored = icmp_broadcast == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.20 Networks Security",
        status="Pass" if broadcast_ignored else "Warning",
        message=f"{get_iso_id('20', 9)}: ICMP broadcast ignored",
        details=f"icmp_echo_ignore_broadcasts = {icmp_broadcast}",
        remediation="Enable: sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"
    ))
    
    # A.8.20-010: IPv6 configuration
    ipv6_disabled = not os.path.exists("/proc/sys/net/ipv6/conf/all/disable_ipv6") or \
                    read_file_safe("/proc/sys/net/ipv6/conf/all/disable_ipv6").strip() == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.20 Networks Security",
        status="Info",
        message=f"{get_iso_id('20', 10)}: IPv6 status",
        details="Disabled" if ipv6_disabled else "Enabled",
        remediation="Disable if not needed: sysctl -w net.ipv6.conf.all.disable_ipv6=1"
    ))


# ============================================================================
# A.8.21-A.8.24: Network Services, Cryptography + Main Function
# ============================================================================

def check_network_services_cryptography(results: List[AuditResult], shared_data: Dict[str, Any], os_info: OSInfo):
    """
    ISO 27001 A.8.21: Security of network services
    ISO 27001 A.8.22: Segregation of networks
    ISO 27001 A.8.23: Web filtering
    ISO 27001 A.8.24: Use of cryptography
    """
    print(f"[{MODULE_NAME}] Checking A.8.21-A.8.24 Network Services & Cryptography...")
    
    # A.8.21: Security of Network Services
    
    # A.8.21-001: Insecure services disabled
    insecure_services = ['telnet', 'ftp', 'rsh', 'rlogin', 'rexec', 'tftp']
    active_insecure = [svc for svc in insecure_services if check_service_active(svc)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.21 Network Services Security",
        status="Pass" if not active_insecure else "Fail",
        message=f"{get_iso_id('21', 1)}: Insecure services disabled",
        details=f"Active: {', '.join(active_insecure)}" if active_insecure else "All disabled",
        remediation="Disable insecure services"
    ))
    
    # A.8.21-002: SSH service hardening
    ssh_checks = []
    if os.path.exists("/etc/ssh/sshd_config"):
        content = read_file_safe("/etc/ssh/sshd_config")
        
        # Check various SSH hardening options
        if re.search(r'^Protocol\s+2', content, re.MULTILINE):
            ssh_checks.append("Protocol 2")
        if re.search(r'^PermitRootLogin\s+no', content, re.MULTILINE):
            ssh_checks.append("Root login disabled")
        if re.search(r'^PermitEmptyPasswords\s+no', content, re.MULTILINE):
            ssh_checks.append("Empty passwords disabled")
        if re.search(r'^X11Forwarding\s+no', content, re.MULTILINE):
            ssh_checks.append("X11 disabled")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.21 Network Services Security",
        status="Pass" if len(ssh_checks) >= 3 else "Warning",
        message=f"{get_iso_id('21', 2)}: SSH service hardening",
        details=f"{len(ssh_checks)} hardening options: {', '.join(ssh_checks)}" if ssh_checks else "Not hardened",
        remediation="Harden SSH configuration in /etc/ssh/sshd_config"
    ))
    
    # A.8.21-003: Unnecessary network services
    network_services = ['avahi-daemon', 'cups', 'bluetooth', 'rpcbind']
    active_optional = [svc for svc in network_services if check_service_active(svc)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.21 Network Services Security",
        status="Pass" if not active_optional else "Info",
        message=f"{get_iso_id('21', 3)}: Optional network services",
        details=f"Active: {', '.join(active_optional)}" if active_optional else "None",
        remediation="Disable unnecessary services: systemctl disable <service>"
    ))
    
    # A.8.21-004: Network service inventory
    result = run_command("ss -tuln 2>/dev/null | grep LISTEN | wc -l")
    listening_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.21 Network Services Security",
        status="Info",
        message=f"{get_iso_id('21', 4)}: Listening network services",
        details=f"{listening_count} listening ports",
        remediation="Minimize listening services"
    ))
    
    # A.8.21-005: DNS configuration
    if os.path.exists("/etc/resolv.conf"):
        content = read_file_safe("/etc/resolv.conf")
        nameservers = content.count("nameserver")
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.21 Network Services Security",
            status="Pass" if nameservers >= 1 else "Warning",
            message=f"{get_iso_id('21', 5)}: DNS servers configured",
            details=f"{nameservers} nameservers",
            remediation="Configure DNS servers in /etc/resolv.conf"
        ))
    
    # A.8.22: Segregation of Networks
    
    # A.8.22-001: Network interfaces
    result = run_command("ip link show | grep -c '^[0-9]'")
    interface_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.22 Network Segregation",
        status="Info",
        message=f"{get_iso_id('22', 1)}: Network interfaces present",
        details=f"{interface_count} network interfaces",
        remediation="Review network segmentation strategy"
    ))
    
    # A.8.22-002: VLANs configured
    result = run_command("ip link show | grep -c '@\\|\\.'")
    vlan_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.22 Network Segregation",
        status="Info",
        message=f"{get_iso_id('22', 2)}: VLAN interfaces",
        details=f"{vlan_count} VLAN interfaces",
        remediation="Use VLANs for network segregation if needed"
    ))
    
    # A.8.22-003: Bridge interfaces
    result = run_command("brctl show 2>/dev/null | grep -v '^bridge name' | wc -l")
    bridge_count = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.22 Network Segregation",
        status="Info",
        message=f"{get_iso_id('22', 3)}: Bridge interfaces",
        details=f"{bridge_count} bridges",
        remediation="Review bridge configurations"
    ))
    
    # A.8.24: Use of Cryptography
    
    # A.8.24-001: Encryption tools available
    encryption = check_encryption_available(os_info)
    encryption_count = sum(encryption.values())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.24 Use of Cryptography",
        status="Pass" if encryption_count >= 3 else "Warning",
        message=f"{get_iso_id('24', 1)}: Encryption tools available",
        details=f"Available: {', '.join([k for k,v in encryption.items() if v])}",
        remediation="Install encryption tools: gnupg, openssl"
    ))
    
    # A.8.24-002: OpenSSL version
    if command_exists('openssl'):
        result = run_command("openssl version")
        ssl_version = result.stdout.strip()
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.24 Use of Cryptography",
            status="Info",
            message=f"{get_iso_id('24', 2)}: OpenSSL version",
            details=ssl_version[:60],
            remediation="Keep OpenSSL updated"
        ))
    
    # A.8.24-003: SSH protocol version
    if os.path.exists("/etc/ssh/sshd_config"):
        content = read_file_safe("/etc/ssh/sshd_config")
        protocol = re.search(r'^Protocol\s+(\d+)', content, re.MULTILINE)
        protocol_ok = protocol and protocol.group(1) == '2'
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.24 Use of Cryptography",
            status="Pass" if protocol_ok else "Warning",
            message=f"{get_iso_id('24', 3)}: SSH Protocol version",
            details=f"Protocol {protocol.group(1)}" if protocol else "Default (2)",
            remediation="Set Protocol 2 in sshd_config"
        ))
    
    # A.8.24-004: SSH ciphers
    if os.path.exists("/etc/ssh/sshd_config"):
        content = read_file_safe("/etc/ssh/sshd_config")
        ciphers = re.search(r'^Ciphers\s+(.+)', content, re.MULTILINE)
        weak_ciphers = ['3des', 'arcfour', 'blowfish', 'cast']
        
        has_weak = False
        if ciphers:
            cipher_list = ciphers.group(1).lower()
            has_weak = any(weak in cipher_list for weak in weak_ciphers)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.24 Use of Cryptography",
            status="Pass" if not has_weak else "Warning",
            message=f"{get_iso_id('24', 4)}: SSH strong ciphers",
            details=f"Ciphers: {ciphers.group(1)[:50]}" if ciphers else "Default ciphers",
            remediation="Configure strong ciphers: aes256-ctr,aes192-ctr,aes128-ctr"
        ))
    
    # A.8.24-005: SSH MACs
    if os.path.exists("/etc/ssh/sshd_config"):
        content = read_file_safe("/etc/ssh/sshd_config")
        macs = re.search(r'^MACs\s+(.+)', content, re.MULTILINE)
        weak_macs = ['md5', '96', 'hmac-sha1-']
        
        has_weak_mac = False
        if macs:
            mac_list = macs.group(1).lower()
            has_weak_mac = any(weak in mac_list for weak in weak_macs)
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.24 Use of Cryptography",
            status="Pass" if not has_weak_mac else "Warning",
            message=f"{get_iso_id('24', 5)}: SSH strong MACs",
            details=f"MACs: {macs.group(1)[:50]}" if macs else "Default MACs",
            remediation="Configure strong MACs: hmac-sha2-512,hmac-sha2-256"
        ))
    
    # A.8.24-006: TLS/SSL certificates
    cert_dirs = ['/etc/ssl/certs', '/etc/pki/tls/certs']
    cert_count = 0
    for cert_dir in cert_dirs:
        if os.path.exists(cert_dir):
            cert_count += len(glob.glob(f"{cert_dir}/*.crt")) + len(glob.glob(f"{cert_dir}/*.pem"))
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.24 Use of Cryptography",
        status="Info",
        message=f"{get_iso_id('24', 6)}: SSL/TLS certificates",
        details=f"{cert_count} certificates found",
        remediation="Maintain certificate inventory and expiration tracking"
    ))
    
    # A.8.24-007: Encrypted filesystems
    result = run_command("lsblk -o NAME,FSTYPE | grep -c crypt || echo 0")
    encrypted_volumes = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.24 Use of Cryptography",
        status="Pass" if encrypted_volumes > 0 else "Info",
        message=f"{get_iso_id('24', 7)}: Encrypted storage volumes",
        details=f"{encrypted_volumes} encrypted volumes",
        remediation="Use LUKS for full disk encryption"
    ))
    
    # A.8.24-008: Kernel crypto modules
    result = run_command("lsmod | grep -c crypto || echo 0")
    crypto_modules = safe_int_parse(result.stdout.strip())
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.24 Use of Cryptography",
        status="Info",
        message=f"{get_iso_id('24', 8)}: Kernel crypto modules loaded",
        details=f"{crypto_modules} crypto modules",
        remediation="Kernel cryptographic support available"
    ))
    
    # A.8.24-009: FIPS mode
    fips_enabled = False
    if os.path.exists("/proc/sys/crypto/fips_enabled"):
        fips_status = read_file_safe("/proc/sys/crypto/fips_enabled").strip()
        fips_enabled = fips_status == "1"
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ISO27001 - A.8.24 Use of Cryptography",
        status="Info",
        message=f"{get_iso_id('24', 9)}: FIPS 140-2 mode",
        details="Enabled" if fips_enabled else "Disabled",
        remediation="Enable FIPS mode if required: fips-mode-setup --enable"
    ))
    
    # A.8.24-010: Password hashing
    if os.path.exists("/etc/login.defs"):
        content = read_file_safe("/etc/login.defs")
        encrypt_method = re.search(r'^ENCRYPT_METHOD\s+(\S+)', content, re.MULTILINE)
        strong_hash = encrypt_method and encrypt_method.group(1) in ['SHA512', 'YESCRYPT']
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - A.8.24 Use of Cryptography",
            status="Pass" if strong_hash else "Warning",
            message=f"{get_iso_id('24', 10)}: Strong password hashing",
            details=f"Method: {encrypt_method.group(1)}" if encrypt_method else "Not set",
            remediation="Set ENCRYPT_METHOD SHA512 in /etc/login.defs"
        ))


# ============================================================================
# Main Orchestration Function
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """
    Main entry point for ISO27001 module
    Executes all ISO 27001:2022 Annex A technical control checks
    """
    results = []
    
    print(f"\n[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] ISO/IEC 27001:2022 COMPLIANCE AUDIT")
    print(f"[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] Version: {MODULE_VERSION}")
    print(f"[{MODULE_NAME}] Focus: Annex A Technical Controls (A.8.x)")
    print(f"[{MODULE_NAME}] Standard: ISO/IEC 27001:2022")
    print(f"[{MODULE_NAME}] Target: 150+ comprehensive technical control checks")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    # Get or detect OS information
    if 'os_info' in shared_data:
        os_info = shared_data['os_info']
    else:
        os_info = detect_os()
        shared_data['os_info'] = os_info
    
    print(f"[{MODULE_NAME}] Operating System: {os_info}")
    print(f"[{MODULE_NAME}] OS Family: {os_info.family}")
    print(f"[{MODULE_NAME}] Package Manager: {os_info.package_manager}")
    print("")
    
    is_root = shared_data.get("is_root", os.geteuid() == 0)
    if not is_root:
        print(f"[{MODULE_NAME}] ⚠️  Note: Running without root privileges")
        print(f"[{MODULE_NAME}] Some checks require elevated privileges for full coverage\n")
    
    try:
        # Execute all control area checks
        check_user_endpoint_devices(results, shared_data, os_info)
        check_privileged_access_authentication(results, shared_data, os_info)
        check_system_protection_management(results, shared_data, os_info)
        check_backup_monitoring_network(results, shared_data, os_info)
        check_network_services_cryptography(results, shared_data, os_info)
        
    except Exception as e:
        print(f"[{MODULE_NAME}] ❌ Error during audit execution: {str(e)}")
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ISO27001 - Error",
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
    
    # Count by control area
    control_counts = {}
    for r in results:
        # Extract control area (A.8.X)
        match = re.search(r'A\.8\.(\d+)', r.category)
        if match:
            control = f"A.8.{match.group(1)}"
            control_counts[control] = control_counts.get(control, 0) + 1
    
    print(f"\n[{MODULE_NAME}] " + "="*70)
    print(f"[{MODULE_NAME}] ISO/IEC 27001 INFORMATION SECURITY MANAGEMENT AUDIT COMPLETED")
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
    print(f"[{MODULE_NAME}] ISO 27001 Control Coverage:")
    for control in sorted(control_counts.keys()):
        print(f"[{MODULE_NAME}]   {control}: {control_counts[control]:3d} checks")
    print(f"[{MODULE_NAME}] " + "="*70 + "\n")
    
    return results


# ============================================================================
# Module Testing
# ============================================================================

if __name__ == "__main__":
    """
    Standalone testing capability for the ISO27001 module
    """
    import datetime
    
    print("="*80)
    print(f"ISO27001 Module Standalone Test - v{MODULE_VERSION}")
    print("Comprehensive ISO/IEC 27001:2022 Compliance for Linux")
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
    
    print(f"\n{'='*80}")
    print(f"ISO27001 module comprehensive test complete")
    print(f"All {len(test_results)} checks executed successfully")
    print(f"{'='*80}\n")
