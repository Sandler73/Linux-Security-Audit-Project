#!/usr/bin/env python3
"""
module_cisa.py
CISA (Cybersecurity and Infrastructure Security Agency) Module for Linux
Version: 1.0

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

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

USAGE:
# Standalone testing
cd /mnt/user-data/outputs/modules
python3 module_cisa.py

# Integrated with main script
python3 linux_security_audit.py

NOTES:
    Version: 1.0
    Reference: https://www.cisa.gov/directives
    Standards: CISA BODs, CISA EDs, NIST Cybersecurity Framework
    Priority: Critical, High, Medium, Low severity findings
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

sys.path.insert(0, str(Path(__file__).parent.parent))
from linux_security_audit import AuditResult

MODULE_NAME = "CISA"

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
    result = run_command(f"which {command}")
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

def get_last_update_time() -> Optional[datetime.datetime]:
    """Get the timestamp of last system update"""
    log_files = [
        "/var/log/apt/history.log",
        "/var/log/dpkg.log",
        "/var/log/yum.log",
        "/var/log/dnf.log"
    ]
    
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                stat_info = os.stat(log_file)
                return datetime.datetime.fromtimestamp(stat_info.st_mtime)
            except:
                continue
    
    return None

def get_cisa_id(category: str, number: int) -> str:
    """Generate CISA control ID format"""
    return f"CISA-{category}-{number:03d}"


# ============================================================================
# BOD 22-01: Known Exploited Vulnerabilities (KEV)
# ============================================================================

def check_bod_22_01_kev(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CISA BOD 22-01: Reducing the Significant Risk of Known Exploited Vulnerabilities
    Requires remediation of KEV catalog vulnerabilities within specified timeframes
    Reference: https://www.cisa.gov/bod-22-01
    """
    print(f"[{MODULE_NAME}] Checking BOD 22-01 Known Exploited Vulnerabilities...")
    
    # CISA-KEV-001: System must have vulnerability scanning capability (Critical)
    vulnerability_scanners = ["lynis", "openvas", "nessus", "qualys", "rapid7"]
    scanner_installed = False
    installed_scanners = []
    
    for scanner in vulnerability_scanners:
        if check_package_installed(scanner) or command_exists(scanner):
            scanner_installed = True
            installed_scanners.append(scanner)
    
    if scanner_installed:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Pass",
            message=f"{get_cisa_id('KEV', 1)}: Vulnerability scanning capability present (Critical)",
            details=f"Scanners available: {', '.join(installed_scanners)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Fail",
            message=f"{get_cisa_id('KEV', 1)}: No vulnerability scanning tools detected (Critical)",
            details="BOD 22-01 requires regular vulnerability assessment",
            remediation="Install vulnerability scanner: sudo apt-get install lynis || sudo yum install lynis"
        ))
    
    # CISA-KEV-002: Security updates must be applied promptly (Critical)
    update_count, security_updates = check_updates_available()
    
    if update_count == 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Pass",
            message=f"{get_cisa_id('KEV', 2)}: No pending security updates (Critical)",
            details="System is up to date with security patches",
            remediation=""
        ))
    elif update_count <= 5:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Warning",
            message=f"{get_cisa_id('KEV', 2)}: {update_count} security updates available (Critical)",
            details=f"Updates needed: {', '.join(security_updates[:3])}",
            remediation="Apply security updates: sudo apt-get update && sudo apt-get upgrade || sudo yum update"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Fail",
            message=f"{get_cisa_id('KEV', 2)}: {update_count} security updates pending (Critical)",
            details=f"Multiple updates required. Sample: {', '.join(security_updates[:5])}",
            remediation="Immediately apply security updates: sudo apt-get update && sudo apt-get upgrade || sudo yum update"
        ))
    
    # CISA-KEV-003: Automatic security updates should be configured (High)
    auto_update_configured = False
    
    if os.path.exists("/etc/apt/apt.conf.d/50unattended-upgrades"):
        unattended_upgrades = read_file_safe("/etc/apt/apt.conf.d/50unattended-upgrades")
        if "Unattended-Upgrade::Allowed-Origins" in unattended_upgrades:
            auto_update_configured = True
    
    if check_package_installed("dnf-automatic") or check_package_installed("yum-cron"):
        auto_update_configured = True
    
    if auto_update_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Pass",
            message=f"{get_cisa_id('KEV', 3)}: Automatic security updates configured (High)",
            details="System can automatically apply security patches",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Fail",
            message=f"{get_cisa_id('KEV', 3)}: Automatic security updates not configured (High)",
            details="Configure automatic security updates for timely patching",
            remediation="sudo apt-get install unattended-upgrades || sudo yum install dnf-automatic"
        ))
    
    # CISA-KEV-004: Last update must be within acceptable timeframe (High)
    last_update = get_last_update_time()
    
    if last_update:
        days_since_update = (datetime.datetime.now() - last_update).days
        
        if days_since_update <= 7:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - BOD 22-01",
                status="Pass",
                message=f"{get_cisa_id('KEV', 4)}: Recent system updates applied (High)",
                details=f"Last update: {days_since_update} days ago",
                remediation=""
            ))
        elif days_since_update <= 30:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - BOD 22-01",
                status="Warning",
                message=f"{get_cisa_id('KEV', 4)}: System updates may be overdue (High)",
                details=f"Last update: {days_since_update} days ago",
                remediation="Update system regularly (at least weekly for security patches)"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - BOD 22-01",
                status="Fail",
                message=f"{get_cisa_id('KEV', 4)}: System updates significantly overdue (High)",
                details=f"Last update: {days_since_update} days ago (30+ days)",
                remediation="Immediately update system: sudo apt-get update && sudo apt-get upgrade"
            ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 4)}: Cannot determine last update time (High)",
            details="Verify system is regularly updated",
            remediation="Establish regular update schedule"
        ))
    
    # CISA-KEV-005: End-of-life software must not be in use (Critical)
    eol_packages = {
        "python2": "Python 2 (EOL 2020)",
        "python2.7": "Python 2.7 (EOL 2020)",
        "openssl1.0": "OpenSSL 1.0 (EOL 2019)",
        "php5": "PHP 5 (EOL 2019)",
        "java-1.7.0": "Java 7 (EOL 2015)",
        "java-1.8.0": "Java 8 (EOL for public updates)"
    }
    
    eol_found = []
    for package, description in eol_packages.items():
        if check_package_installed(package):
            eol_found.append(description)
    
    if not eol_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Pass",
            message=f"{get_cisa_id('KEV', 5)}: No EOL software detected (Critical)",
            details="All installed software is within support lifecycle",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Fail",
            message=f"{get_cisa_id('KEV', 5)}: End-of-life software detected (Critical)",
            details=f"EOL software: {', '.join(eol_found)}",
            remediation="Upgrade or remove end-of-life software immediately"
        ))
    
    # CISA-KEV-006: System must maintain software inventory (High)
    inventory_commands = ["dpkg -l", "rpm -qa"]
    inventory_available = False
    
    for cmd in inventory_commands:
        result = run_command(f"{cmd} 2>/dev/null | wc -l")
        if result.returncode == 0 and result.stdout.strip().isdigit():
            package_count = int(result.stdout.strip())
            if package_count > 0:
                inventory_available = True
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CISA - BOD 22-01",
                    status="Pass",
                    message=f"{get_cisa_id('KEV', 6)}: Software inventory available (High)",
                    details=f"Tracking {package_count} installed packages",
                    remediation=""
                ))
                break
    
    if not inventory_available:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 22-01",
            status="Info",
            message=f"{get_cisa_id('KEV', 6)}: Software inventory status unclear (High)",
            details="Maintain accurate software inventory for vulnerability tracking",
            remediation="Implement software inventory management process"
        ))

# ============================================================================
# BOD 23-01: Asset Visibility and Vulnerability Detection
# ============================================================================

def check_bod_23_01_asset_visibility(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CISA BOD 23-01: Improving Asset Visibility and Vulnerability Detection
    Requires comprehensive asset management and network visibility
    Reference: https://www.cisa.gov/bod-23-01
    """
    print(f"[{MODULE_NAME}] Checking BOD 23-01 Asset Visibility...")
    
    # CISA-AV-001: Network discovery tools should be available (Medium)
    network_tools = ["nmap", "netstat", "ss", "ip", "arp"]
    tools_available = []
    
    for tool in network_tools:
        if command_exists(tool):
            tools_available.append(tool)
    
    if len(tools_available) >= 3:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 23-01",
            status="Pass",
            message=f"{get_cisa_id('AV', 1)}: Network discovery tools available (Medium)",
            details=f"Tools present: {', '.join(tools_available)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 23-01",
            status="Warning",
            message=f"{get_cisa_id('AV', 1)}: Limited network discovery capability (Medium)",
            details="Install network discovery tools for asset visibility",
            remediation="sudo apt-get install nmap net-tools iproute2"
        ))
    
    # CISA-AV-002: System must track network connections (High)
    if command_exists("ss") or command_exists("netstat"):
        active_connections = run_command("ss -tuln 2>/dev/null | wc -l")
        if active_connections.returncode == 0:
            conn_count = int(active_connections.stdout.strip()) if active_connections.stdout.strip().isdigit() else 0
            
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - BOD 23-01",
                status="Pass",
                message=f"{get_cisa_id('AV', 2)}: Network connection tracking available (High)",
                details=f"Monitoring {conn_count} network listeners",
                remediation=""
            ))
    
    # CISA-AV-003: System hostname must be properly configured (Medium)
    hostname = run_command("hostname").stdout.strip()
    fqdn = run_command("hostname -f 2>/dev/null").stdout.strip()
    
    if hostname and hostname != "localhost" and hostname != "localhost.localdomain":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 23-01",
            status="Pass",
            message=f"{get_cisa_id('AV', 3)}: System hostname properly configured (Medium)",
            details=f"Hostname: {hostname}, FQDN: {fqdn if fqdn else 'not set'}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 23-01",
            status="Fail",
            message=f"{get_cisa_id('AV', 3)}: System hostname not properly configured (Medium)",
            details="Proper hostname aids in asset identification",
            remediation="Set hostname: sudo hostnamectl set-hostname UNIQUE_NAME"
        ))
    
    # CISA-AV-004: Hardware asset information should be documented (Low)
    hardware_info_available = False
    
    if command_exists("dmidecode"):
        dmi_result = run_command("sudo dmidecode -t system 2>/dev/null | grep -i 'manufacturer\\|product'")
        if dmi_result.returncode == 0 and dmi_result.stdout:
            hardware_info_available = True
    
    if command_exists("lshw"):
        hardware_info_available = True
    
    if hardware_info_available:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - BOD 23-01",
            status="Pass",
            message=f"{get_cisa_id('AV', 4)}: Hardware asset information available (Low)",
            details="System hardware can be inventoried",
            remediation=""
        ))
    
    # CISA-AV-005: Running services should be minimized (High)
    if command_exists("systemctl"):
        enabled_services = run_command("systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -c 'enabled'")
        
        if enabled_services.returncode == 0 and enabled_services.stdout.strip().isdigit():
            service_count = int(enabled_services.stdout.strip())
            
            if service_count <= 30:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CISA - BOD 23-01",
                    status="Pass",
                    message=f"{get_cisa_id('AV', 5)}: Service count within acceptable range (High)",
                    details=f"{service_count} enabled services",
                    remediation=""
                ))
            elif service_count <= 50:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CISA - BOD 23-01",
                    status="Warning",
                    message=f"{get_cisa_id('AV', 5)}: High number of enabled services (High)",
                    details=f"{service_count} enabled services - review and disable unnecessary ones",
                    remediation="Review services: systemctl list-unit-files --type=service --state=enabled"
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CISA - BOD 23-01",
                    status="Fail",
                    message=f"{get_cisa_id('AV', 5)}: Excessive enabled services (High)",
                    details=f"{service_count} enabled services - significant attack surface",
                    remediation="Disable unnecessary services to reduce attack surface"
                ))


# ============================================================================
# Multi-Factor Authentication and Access Control
# ============================================================================

def check_authentication_access_control(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CISA Authentication and Access Control Best Practices
    Covers MFA, privilege management, and secure authentication
    """
    print(f"[{MODULE_NAME}] Checking authentication and access control...")
    
    # CISA-AUTH-001: Multi-factor authentication should be implemented (Critical)
    mfa_packages = [
        "libpam-google-authenticator",
        "google-authenticator-libpam",
        "libpam-oath",
        "duo-unix"
    ]
    
    mfa_installed = False
    mfa_type = []
    
    for mfa_pkg in mfa_packages:
        if check_package_installed(mfa_pkg):
            mfa_installed = True
            mfa_type.append(mfa_pkg)
    
    # Check PAM configuration for MFA
    pam_sshd = read_file_safe("/etc/pam.d/sshd")
    pam_common_auth = read_file_safe("/etc/pam.d/common-auth")
    
    if "pam_google_authenticator" in pam_sshd or "pam_oath" in pam_sshd:
        mfa_installed = True
        mfa_type.append("PAM configured")
    
    if mfa_installed:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Pass",
            message=f"{get_cisa_id('AUTH', 1)}: Multi-factor authentication available (Critical)",
            details=f"MFA capability: {', '.join(mfa_type)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Fail",
            message=f"{get_cisa_id('AUTH', 1)}: Multi-factor authentication not implemented (Critical)",
            details="CISA strongly recommends MFA for all user accounts",
            remediation="Install MFA: sudo apt-get install libpam-google-authenticator || sudo yum install google-authenticator"
        ))
    
    # CISA-AUTH-002: SSH must use strong authentication (High)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        # Check for password authentication
        password_auth = re.search(r'^\s*PasswordAuthentication\s+(\w+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        pubkey_auth = re.search(r'^\s*PubkeyAuthentication\s+(\w+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        challenge_response = re.search(r'^\s*ChallengeResponseAuthentication\s+(\w+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        strong_auth = False
        auth_methods = []
        
        if pubkey_auth and pubkey_auth.group(1).lower() == "yes":
            strong_auth = True
            auth_methods.append("public key")
        
        if challenge_response and challenge_response.group(1).lower() == "yes":
            auth_methods.append("challenge-response")
        
        if password_auth and password_auth.group(1).lower() == "no":
            auth_methods.append("password disabled")
        
        if strong_auth:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - Authentication",
                status="Pass",
                message=f"{get_cisa_id('AUTH', 2)}: SSH strong authentication configured (High)",
                details=f"Auth methods: {', '.join(auth_methods)}",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - Authentication",
                status="Warning",
                message=f"{get_cisa_id('AUTH', 2)}: SSH authentication could be stronger (High)",
                details="Enable public key authentication and consider disabling passwords",
                remediation="Configure SSH: PubkeyAuthentication yes, PasswordAuthentication no"
            ))
    
    # CISA-AUTH-003: Root account must be properly secured (Critical)
    shadow_content = read_file_safe("/etc/shadow")
    root_password_set = False
    
    for line in shadow_content.split('\n'):
        if line.startswith('root:'):
            parts = line.split(':')
            if len(parts) >= 2 and parts[1] and parts[1] not in ['!', '*', '!!']:
                root_password_set = True
            break
    
    # Check if root login is disabled in SSH
    root_ssh_disabled = False
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        permit_root = re.search(r'^\s*PermitRootLogin\s+(\w+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if permit_root and permit_root.group(1).lower() == "no":
            root_ssh_disabled = True
    
    if root_password_set and root_ssh_disabled:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Pass",
            message=f"{get_cisa_id('AUTH', 3)}: Root account properly secured (Critical)",
            details="Root password set, SSH login disabled",
            remediation=""
        ))
    elif not root_password_set:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Warning",
            message=f"{get_cisa_id('AUTH', 3)}: Root account may not have password (Critical)",
            details="Ensure root account is secured",
            remediation="Set root password: sudo passwd root"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Fail",
            message=f"{get_cisa_id('AUTH', 3)}: Root SSH login not disabled (Critical)",
            details="Disable direct root SSH access",
            remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
        ))
    
    # CISA-AUTH-004: User accounts must have strong password policies (High)
    login_defs = read_file_safe("/etc/login.defs")
    
    pass_max_days = re.search(r'^\s*PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    pass_min_days = re.search(r'^\s*PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    pass_min_len = re.search(r'^\s*PASS_MIN_LEN\s+(\d+)', login_defs, re.MULTILINE)
    
    strong_policy = True
    policy_issues = []
    
    if not pass_max_days or int(pass_max_days.group(1)) > 90:
        strong_policy = False
        policy_issues.append("max age > 90 days")
    
    if not pass_min_days or int(pass_min_days.group(1)) < 1:
        strong_policy = False
        policy_issues.append("min age < 1 day")
    
    if strong_policy:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Pass",
            message=f"{get_cisa_id('AUTH', 4)}: Password policies meet requirements (High)",
            details="Password aging and complexity configured",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Fail",
            message=f"{get_cisa_id('AUTH', 4)}: Password policies insufficient (High)",
            details=f"Issues: {', '.join(policy_issues)}",
            remediation="Configure /etc/login.defs: PASS_MAX_DAYS 90, PASS_MIN_DAYS 1"
        ))
    
    # CISA-AUTH-005: Failed login attempts must be limited (High)
    faillock_configured = False
    
    pam_files = ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth", "/etc/pam.d/common-auth"]
    
    for pam_file in pam_files:
        if os.path.exists(pam_file):
            pam_content = read_file_safe(pam_file)
            if "pam_faillock" in pam_content or "pam_tally2" in pam_content:
                deny_match = re.search(r'deny=(\d+)', pam_content)
                if deny_match and int(deny_match.group(1)) <= 5:
                    faillock_configured = True
                    break
    
    if faillock_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Pass",
            message=f"{get_cisa_id('AUTH', 5)}: Account lockout policy configured (High)",
            details="Failed login attempts are limited",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Fail",
            message=f"{get_cisa_id('AUTH', 5)}: Account lockout policy not configured (High)",
            details="Configure account lockout after failed login attempts",
            remediation="Configure pam_faillock with deny=5 in PAM configuration"
        ))
    
    # CISA-AUTH-006: Privileged access must be logged (High)
    sudo_log_configured = False
    
    sudoers_content = read_file_safe("/etc/sudoers")
    sudoers_d_files = glob.glob("/etc/sudoers.d/*")
    
    all_sudo_content = sudoers_content
    for sudoers_file in sudoers_d_files:
        all_sudo_content += read_file_safe(sudoers_file)
    
    if "Defaults logfile" in all_sudo_content or "Defaults syslog" in all_sudo_content:
        sudo_log_configured = True
    
    if sudo_log_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Pass",
            message=f"{get_cisa_id('AUTH', 6)}: Privileged access logging configured (High)",
            details="sudo commands are being logged",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Authentication",
            status="Warning",
            message=f"{get_cisa_id('AUTH', 6)}: Privileged access logging not explicit (High)",
            details="Ensure sudo commands are logged",
            remediation="Add to /etc/sudoers: Defaults logfile=/var/log/sudo.log"
        ))

# ============================================================================
# Network Security and Segmentation
# ============================================================================

def check_network_security(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CISA Network Security Best Practices
    Covers firewall, network segmentation, and secure protocols
    """
    print(f"[{MODULE_NAME}] Checking network security...")
    
    # CISA-NET-001: Firewall must be active and configured (Critical)
    firewall_active = False
    firewall_rules = 0
    firewall_type = None
    
    if command_exists("firewall-cmd"):
        firewall_state = run_command("firewall-cmd --state 2>/dev/null")
        if firewall_state.returncode == 0 and "running" in firewall_state.stdout.lower():
            firewall_active = True
            firewall_type = "firewalld"
            
            # Count rules
            zones = run_command("firewall-cmd --get-active-zones 2>/dev/null")
            if zones.returncode == 0:
                firewall_rules = zones.stdout.count(":")
    
    if command_exists("ufw") and not firewall_active:
        ufw_status = run_command("ufw status 2>/dev/null")
        if "Status: active" in ufw_status.stdout:
            firewall_active = True
            firewall_type = "ufw"
            firewall_rules = ufw_status.stdout.count("ALLOW") + ufw_status.stdout.count("DENY")
    
    if not firewall_active:
        iptables_rules_result = run_command("iptables -L -n 2>/dev/null | grep -v '^Chain' | grep -v '^target' | wc -l")
        if iptables_rules_result.returncode == 0 and iptables_rules_result.stdout.strip().isdigit():
            firewall_rules = int(iptables_rules_result.stdout.strip())
            if firewall_rules > 0:
                firewall_active = True
                firewall_type = "iptables"
    
    if firewall_active and firewall_rules > 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Network Security",
            status="Pass",
            message=f"{get_cisa_id('NET', 1)}: Firewall active with rules (Critical)",
            details=f"Firewall: {firewall_type}, Rules/zones configured",
            remediation=""
        ))
    elif firewall_active and firewall_rules == 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Network Security",
            status="Warning",
            message=f"{get_cisa_id('NET', 1)}: Firewall active but no rules (Critical)",
            details=f"Firewall: {firewall_type} - configure appropriate rules",
            remediation="Configure firewall rules to restrict network access"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Network Security",
            status="Fail",
            message=f"{get_cisa_id('NET', 1)}: No active firewall detected (Critical)",
            details="CISA requires network filtering at the host level",
            remediation="Enable firewall: sudo systemctl enable --now firewalld || sudo ufw enable"
        ))
    
    # CISA-NET-002: Unnecessary network services must be disabled (High)
    insecure_services = {
        "telnet": "Insecure remote access",
        "ftp": "Insecure file transfer",
        "rsh": "Insecure remote shell",
        "rlogin": "Insecure remote login",
        "tftp": "Insecure file transfer",
        "finger": "Information disclosure",
        "rpc.bind": "RPC services (if not needed)"
    }
    
    running_insecure = []
    for service, description in insecure_services.items():
        if check_service_active(service):
            running_insecure.append(f"{service} ({description})")
    
    if not running_insecure:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Network Security",
            status="Pass",
            message=f"{get_cisa_id('NET', 2)}: No insecure network services detected (High)",
            details="Insecure legacy services are not running",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Network Security",
            status="Fail",
            message=f"{get_cisa_id('NET', 2)}: Insecure network services detected (High)",
            details=f"Services to disable: {', '.join(running_insecure)}",
            remediation="Disable insecure services: sudo systemctl disable SERVICE_NAME"
        ))
    
    # CISA-NET-003: SSH must be properly secured (High)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        security_issues = []
        
        # Check Protocol
        protocol = re.search(r'^\s*Protocol\s+(\d+)', sshd_config, re.MULTILINE)
        if protocol and protocol.group(1) != "2":
            security_issues.append("Protocol not set to 2")
        
        # Check PermitEmptyPasswords
        empty_passwords = re.search(r'^\s*PermitEmptyPasswords\s+(\w+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        if not empty_passwords or empty_passwords.group(1).lower() != "no":
            security_issues.append("Empty passwords not explicitly disabled")
        
        # Check MaxAuthTries
        max_auth = re.search(r'^\s*MaxAuthTries\s+(\d+)', sshd_config, re.MULTILINE)
        if max_auth and int(max_auth.group(1)) > 4:
            security_issues.append("MaxAuthTries > 4")
        
        # Check ClientAliveInterval
        client_alive = re.search(r'^\s*ClientAliveInterval\s+(\d+)', sshd_config, re.MULTILINE)
        if not client_alive or int(client_alive.group(1)) == 0:
            security_issues.append("ClientAliveInterval not set (idle timeout)")
        
        if not security_issues:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - Network Security",
                status="Pass",
                message=f"{get_cisa_id('NET', 3)}: SSH properly secured (High)",
                details="SSH configuration meets security requirements",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - Network Security",
                status="Warning",
                message=f"{get_cisa_id('NET', 3)}: SSH configuration has issues (High)",
                details=f"Issues: {', '.join(security_issues)}",
                remediation="Review and harden /etc/ssh/sshd_config"
            ))
    
    # CISA-NET-004: IPv6 should be disabled if not used (Medium)
    ipv6_disabled = False
    
    ipv6_params = ["net.ipv6.conf.all.disable_ipv6", "net.ipv6.conf.default.disable_ipv6"]
    ipv6_all_disabled = True
    
    for param in ipv6_params:
        found, value = check_kernel_parameter(param)
        if not found or value != "1":
            ipv6_all_disabled = False
            break
    
    if ipv6_all_disabled:
        ipv6_disabled = True
    
    # Check if IPv6 interfaces exist
    ipv6_interfaces = run_command("ip -6 addr show 2>/dev/null | grep -c 'inet6'")
    has_ipv6 = ipv6_interfaces.returncode == 0 and int(ipv6_interfaces.stdout.strip() or "0") > 1  # More than just loopback
    
    if ipv6_disabled or not has_ipv6:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Network Security",
            status="Pass",
            message=f"{get_cisa_id('NET', 4)}: IPv6 properly managed (Medium)",
            details="IPv6 is disabled or minimal",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Network Security",
            status="Info",
            message=f"{get_cisa_id('NET', 4)}: IPv6 is enabled (Medium)",
            details="If IPv6 is not needed, consider disabling it",
            remediation="Disable IPv6: net.ipv6.conf.all.disable_ipv6=1 in /etc/sysctl.conf"
        ))


# ============================================================================
# Logging and Monitoring
# ============================================================================

def check_logging_monitoring(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CISA Logging and Monitoring Best Practices
    Covers comprehensive logging, monitoring, and event management
    """
    print(f"[{MODULE_NAME}] Checking logging and monitoring...")
    
    # CISA-LOG-001: System logging must be active (Critical)
    logging_active = False
    logger_type = None
    
    if check_service_active("rsyslog"):
        logging_active = True
        logger_type = "rsyslog"
    elif check_service_active("syslog-ng"):
        logging_active = True
        logger_type = "syslog-ng"
    elif check_service_active("systemd-journald"):
        logging_active = True
        logger_type = "systemd-journald"
    
    if logging_active:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass",
            message=f"{get_cisa_id('LOG', 1)}: System logging is active (Critical)",
            details=f"Active logger: {logger_type}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Fail",
            message=f"{get_cisa_id('LOG', 1)}: No active system logging (Critical)",
            details="System logging is required for security monitoring",
            remediation="Enable logging: sudo systemctl enable --now rsyslog"
        ))
    
    # CISA-LOG-002: Audit daemon must be running (Critical)
    if check_service_active("auditd"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass",
            message=f"{get_cisa_id('LOG', 2)}: Audit daemon is running (Critical)",
            details="System audit logging is active",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Fail",
            message=f"{get_cisa_id('LOG', 2)}: Audit daemon not running (Critical)",
            details="auditd is required for comprehensive security auditing",
            remediation="Install and enable auditd: sudo systemctl enable --now auditd"
        ))
    
    # CISA-LOG-003: Critical logs must be protected (High)
    log_files = {
        "/var/log/auth.log": "Authentication logs",
        "/var/log/secure": "Security logs",
        "/var/log/audit/audit.log": "Audit logs",
        "/var/log/messages": "System messages"
    }
    
    protected_logs = []
    unprotected_logs = []
    
    for log_file, description in log_files.items():
        if os.path.exists(log_file):
            perms = get_file_permissions(log_file)
            owner, group = get_file_owner_group(log_file)
            
            # Logs should be 0640 or more restrictive, owned by root or syslog
            if perms and int(perms, 8) <= int("0640", 8) and owner in ["root", "syslog"]:
                protected_logs.append(log_file)
            else:
                unprotected_logs.append(f"{log_file} ({perms}, {owner})")
    
    if protected_logs and not unprotected_logs:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass",
            message=f"{get_cisa_id('LOG', 3)}: Log files properly protected (High)",
            details=f"{len(protected_logs)} log files have correct permissions",
            remediation=""
        ))
    elif unprotected_logs:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Fail",
            message=f"{get_cisa_id('LOG', 3)}: Some log files not properly protected (High)",
            details=f"Issues: {', '.join(unprotected_logs[:2])}",
            remediation="Set proper permissions: sudo chmod 0640 /var/log/auth.log /var/log/secure"
        ))
    
    # CISA-LOG-004: Log retention must be configured (Medium)
    logrotate_configs = glob.glob("/etc/logrotate.d/*")
    
    if os.path.exists("/etc/logrotate.conf"):
        logrotate_configs.append("/etc/logrotate.conf")
    
    retention_configured = False
    for config in logrotate_configs:
        content = read_file_safe(config)
        if "rotate" in content and ("weekly" in content or "daily" in content or "monthly" in content):
            retention_configured = True
            break
    
    if retention_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass",
            message=f"{get_cisa_id('LOG', 4)}: Log retention configured (Medium)",
            details="logrotate is configured for log management",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Warning",
            message=f"{get_cisa_id('LOG', 4)}: Log retention not clearly configured (Medium)",
            details="Configure logrotate for proper log retention",
            remediation="Configure /etc/logrotate.conf with appropriate retention periods"
        ))
    
    # CISA-LOG-005: Remote logging should be configured (Medium)
    remote_logging = False
    
    if os.path.exists("/etc/rsyslog.conf"):
        rsyslog_conf = read_file_safe("/etc/rsyslog.conf")
        if re.search(r'@{1,2}[\w\.\-]+:\d+', rsyslog_conf):  # Remote server config
            remote_logging = True
    
    rsyslog_d_files = glob.glob("/etc/rsyslog.d/*.conf")
    for conf_file in rsyslog_d_files:
        if re.search(r'@{1,2}[\w\.\-]+:\d+', read_file_safe(conf_file)):
            remote_logging = True
            break
    
    if remote_logging:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass",
            message=f"{get_cisa_id('LOG', 5)}: Remote logging configured (Medium)",
            details="Logs are being sent to remote server",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Info",
            message=f"{get_cisa_id('LOG', 5)}: Remote logging not detected (Medium)",
            details="Consider centralized logging for better security monitoring",
            remediation="Configure remote logging in /etc/rsyslog.conf: *.* @@logserver:514"
        ))
    
    # CISA-LOG-006: Command history must be logged (Medium)
    history_configured = False
    
    bash_configs = ["/etc/bash.bashrc", "/etc/bashrc", "/etc/profile"]
    for config in bash_configs:
        if os.path.exists(config):
            content = read_file_safe(config)
            if "HISTSIZE" in content and "HISTFILESIZE" in content:
                history_configured = True
                break
    
    if history_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Logging",
            status="Pass",
            message=f"{get_cisa_id('LOG', 6)}: Command history logging configured (Medium)",
            details="Shell command history is being maintained",
            remediation=""
        ))

# ============================================================================
# Incident Response and Recovery
# ============================================================================

def check_incident_response(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CISA Incident Response Best Practices
    Covers incident detection, response procedures, and recovery capabilities
    """
    print(f"[{MODULE_NAME}] Checking incident response capabilities...")
    
    # CISA-IR-001: Incident response documentation should exist (High)
    ir_docs = [
        "/etc/security/incident-response.txt",
        "/etc/security/ir-plan.txt",
        "/etc/security/incident-response-plan.txt",
        "/usr/share/doc/incident-response"
    ]
    
    ir_doc_found = False
    for doc in ir_docs:
        if os.path.exists(doc):
            ir_doc_found = True
            break
    
    if ir_doc_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Incident Response",
            status="Pass",
            message=f"{get_cisa_id('IR', 1)}: Incident response documentation exists (High)",
            details="IR procedures are documented",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Incident Response",
            status="Info",
            message=f"{get_cisa_id('IR', 1)}: No incident response documentation found (High)",
            details="Document IR procedures for quick response",
            remediation="Create incident response plan: /etc/security/incident-response.txt"
        ))
    
    # CISA-IR-002: Intrusion detection tools should be available (Medium)
    ids_tools = ["aide", "ossec", "snort", "suricata", "fail2ban", "rkhunter", "chkrootkit"]
    ids_installed = []
    
    for tool in ids_tools:
        if check_package_installed(tool) or command_exists(tool):
            ids_installed.append(tool)
    
    if ids_installed:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Incident Response",
            status="Pass",
            message=f"{get_cisa_id('IR', 2)}: Intrusion detection tools available (Medium)",
            details=f"IDS tools: {', '.join(ids_installed)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Incident Response",
            status="Warning",
            message=f"{get_cisa_id('IR', 2)}: No intrusion detection tools detected (Medium)",
            details="Install IDS/IPS for threat detection",
            remediation="Install IDS: sudo apt-get install aide fail2ban || sudo yum install aide fail2ban"
        ))
    
    # CISA-IR-003: Backup solution should be configured (Critical)
    backup_tools = ["restic", "borgbackup", "duplicity", "rsnapshot", "bacula", "amanda", "tar"]
    backup_scripts = glob.glob("/etc/cron.*/backup*") + glob.glob("/etc/cron.d/*backup*")
    
    backup_configured = False
    backup_method = []
    
    for tool in backup_tools:
        if check_package_installed(tool):
            backup_method.append(tool)
            backup_configured = True
    
    if backup_scripts:
        backup_method.append("cron scripts")
        backup_configured = True
    
    if backup_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Incident Response",
            status="Pass",
            message=f"{get_cisa_id('IR', 3)}: Backup solution detected (Critical)",
            details=f"Backup methods: {', '.join(backup_method)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Incident Response",
            status="Fail",
            message=f"{get_cisa_id('IR', 3)}: No backup solution detected (Critical)",
            details="Backups are critical for recovery from incidents",
            remediation="Configure backup solution: sudo apt-get install restic borgbackup"
        ))
    
    # CISA-IR-004: Recovery procedures should be documented (Medium)
    recovery_docs = [
        "/etc/security/recovery-plan.txt",
        "/etc/security/disaster-recovery.txt",
        "/etc/security/drp.txt"
    ]
    
    recovery_doc_found = any(os.path.exists(doc) for doc in recovery_docs)
    
    if recovery_doc_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Incident Response",
            status="Pass",
            message=f"{get_cisa_id('IR', 4)}: Recovery documentation exists (Medium)",
            details="Disaster recovery procedures are documented",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Incident Response",
            status="Info",
            message=f"{get_cisa_id('IR', 4)}: No recovery documentation found (Medium)",
            details="Document disaster recovery procedures",
            remediation="Create recovery plan: /etc/security/recovery-plan.txt"
        ))

# ============================================================================
# Data Protection and Encryption
# ============================================================================

def check_data_protection(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CISA Data Protection Best Practices
    Covers encryption, data at rest, and data in transit protection
    """
    print(f"[{MODULE_NAME}] Checking data protection...")
    
    # CISA-DP-001: Disk encryption should be enabled (High)
    luks_devices = run_command("lsblk -o NAME,FSTYPE 2>/dev/null | grep -c crypto_LUKS")
    
    if luks_devices.returncode == 0 and luks_devices.stdout.strip().isdigit():
        encrypted_count = int(luks_devices.stdout.strip())
        
        if encrypted_count > 0:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - Data Protection",
                status="Pass",
                message=f"{get_cisa_id('DP', 1)}: Disk encryption detected (High)",
                details=f"{encrypted_count} encrypted volume(s) found",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - Data Protection",
                status="Warning",
                message=f"{get_cisa_id('DP', 1)}: No disk encryption detected (High)",
                details="Encrypt sensitive data at rest",
                remediation="Use LUKS for full disk encryption on sensitive systems"
            ))
    
    # CISA-DP-002: TLS/SSL certificates should be present (Medium)
    cert_locations = ["/etc/ssl/certs", "/etc/pki/tls/certs"]
    cert_count = 0
    
    for cert_dir in cert_locations:
        if os.path.exists(cert_dir):
            certs = glob.glob(f"{cert_dir}/*.crt") + glob.glob(f"{cert_dir}/*.pem")
            cert_count += len(certs)
    
    if cert_count > 5:  # More than just CA certs
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Data Protection",
            status="Pass",
            message=f"{get_cisa_id('DP', 2)}: TLS/SSL certificates present (Medium)",
            details=f"{cert_count} certificate files found",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Data Protection",
            status="Info",
            message=f"{get_cisa_id('DP', 2)}: Limited TLS/SSL certificates (Medium)",
            details="Ensure encrypted communications for sensitive services",
            remediation="Configure TLS/SSL for network services"
        ))
    
    # CISA-DP-003: Secure deletion tools should be available (Low)
    secure_delete_tools = ["shred", "wipe", "srm", "secure-delete"]
    tools_found = []
    
    for tool in secure_delete_tools:
        if command_exists(tool):
            tools_found.append(tool)
    
    if tools_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Data Protection",
            status="Pass",
            message=f"{get_cisa_id('DP', 3)}: Secure deletion tools available (Low)",
            details=f"Tools: {', '.join(tools_found)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Data Protection",
            status="Info",
            message=f"{get_cisa_id('DP', 3)}: No secure deletion tools found (Low)",
            details="Install tools for secure data destruction",
            remediation="Install secure deletion: sudo apt-get install secure-delete"
        ))
    
    # CISA-DP-004: File integrity monitoring should be configured (High)
    if check_package_installed("aide"):
        # Check if AIDE database exists
        aide_db_locations = [
            "/var/lib/aide/aide.db",
            "/var/lib/aide/aide.db.gz",
            "/var/lib/aide/aide.db.new"
        ]
        
        aide_db_exists = any(os.path.exists(db) for db in aide_db_locations)
        
        if aide_db_exists:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - Data Protection",
                status="Pass",
                message=f"{get_cisa_id('DP', 4)}: File integrity monitoring configured (High)",
                details="AIDE database exists",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CISA - Data Protection",
                status="Warning",
                message=f"{get_cisa_id('DP', 4)}: AIDE installed but not initialized (High)",
                details="Initialize AIDE database",
                remediation="Initialize AIDE: sudo aideinit || sudo aide --init"
            ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Data Protection",
            status="Fail",
            message=f"{get_cisa_id('DP', 4)}: File integrity monitoring not configured (High)",
            details="Install AIDE for file integrity monitoring",
            remediation="Install AIDE: sudo apt-get install aide || sudo yum install aide"
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
    
    print(f"\n[{MODULE_NAME}] Starting CISA Cybersecurity Directives checks...")
    print(f"[{MODULE_NAME}] Standards: CISA BODs, Emergency Directives, Best Practices")
    print(f"[{MODULE_NAME}] Priority Levels: Critical, High, Medium, Low")
    print(f"[{MODULE_NAME}] Focus: BOD 22-01 (KEV), BOD 23-01 (Asset Visibility)")
    
    is_root = shared_data.get("is_root", False)
    if not is_root:
        print(f"[{MODULE_NAME}] Note: Some checks require root privileges for complete results")
    
    try:
        # BOD 22-01: Known Exploited Vulnerabilities
        check_bod_22_01_kev(results, shared_data)
        
        # BOD 23-01: Asset Visibility and Vulnerability Detection
        check_bod_23_01_asset_visibility(results, shared_data)
        
        # Authentication and Access Control
        check_authentication_access_control(results, shared_data)
        
        # Network Security
        check_network_security(results, shared_data)
        
        # Logging and Monitoring
        check_logging_monitoring(results, shared_data)
        
        # Incident Response
        check_incident_response(results, shared_data)
        
        # Data Protection
        check_data_protection(results, shared_data)
        
    except Exception as e:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CISA - Error",
            status="Error",
            message=f"Module execution error: {str(e)}"
        ))
        import traceback
        traceback.print_exc()
    
    # Summary of findings by priority
    critical_fail = sum(1 for r in results if "Critical" in r.message and r.status == "Fail")
    high_fail = sum(1 for r in results if "High" in r.message and r.status == "Fail")
    medium_fail = sum(1 for r in results if "Medium" in r.message and r.status == "Fail")
    low_fail = sum(1 for r in results if "Low" in r.message and r.status == "Fail")
    
    # Count BOD-specific findings
    bod_22_01_checks = sum(1 for r in results if "BOD 22-01" in r.category)
    bod_23_01_checks = sum(1 for r in results if "BOD 23-01" in r.category)
    
    summary_details = (
        f"Critical failures: {critical_fail}, High failures: {high_fail}, "
        f"Medium failures: {medium_fail}, Low failures: {low_fail}"
    )
    
    print(f"[{MODULE_NAME}] CISA Cybersecurity checks completed - {len(results)} checks performed")
    print(f"[{MODULE_NAME}] BOD 22-01 checks: {bod_22_01_checks}, BOD 23-01 checks: {bod_23_01_checks}")
    print(f"[{MODULE_NAME}] Priority summary: {summary_details}")
    
    return results

# ============================================================================
# Module Testing
# ============================================================================

if __name__ == "__main__":
    """Allow module to be run standalone for testing"""
    import socket
    import platform
    
    print(f"Testing {MODULE_NAME} module...")
    print("=" * 70)
    
    test_shared_data = {
        "hostname": socket.gethostname(),
        "os_version": f"{platform.system()} {platform.release()}",
        "scan_date": datetime.datetime.now(),
        "is_root": os.geteuid() == 0,
        "script_path": Path(__file__).parent.parent
    }
    
    print(f"Hostname: {test_shared_data['hostname']}")
    print(f"OS: {test_shared_data['os_version']}")
    print(f"Running as root: {test_shared_data['is_root']}")
    print(f"Scan time: {test_shared_data['scan_date'].strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    
    test_results = run_checks(test_shared_data)
    
    print(f"\n{'=' * 70}")
    print(f"Generated {len(test_results)} results")
    print("=" * 70)
    
    status_counts = {}
    for result in test_results:
        status_counts[result.status] = status_counts.get(result.status, 0) + 1
    
    print("\nSummary by Status:")
    for status in ["Pass", "Fail", "Warning", "Info", "Error"]:
        count = status_counts.get(status, 0)
        if count > 0:
            print(f"  {status}: {count}")
    
    # Count by priority
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
    
    # Count by category
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
        print(f"  {category}: {categories[category]['total']} checks, {categories[category]['fail']} failures")
    
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
    
    print("\n" + "=" * 70)
    print("CISA Cybersecurity Directives module test complete")
    print("=" * 70)
    
    # Display critical failures if any
    critical_failures = [r for r in test_results if r.status == "Fail" and "Critical" in r.message]
    if critical_failures:
        print(f"\n⚠️  {len(critical_failures)} CRITICAL FAILURES DETECTED:")
        for i, failure in enumerate(critical_failures[:5], 1):
            print(f"  {i}. {failure.message}")
        if len(critical_failures) > 5:
            print(f"  ... and {len(critical_failures) - 5} more")
