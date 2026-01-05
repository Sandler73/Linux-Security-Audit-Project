#!/usr/bin/env python3
"""
module_stig.py
DISA STIG (Security Technical Implementation Guide) Module for Linux
Version: 1.0

SYNOPSIS:
    DISA Security Technical Implementation Guide compliance checks for Linux systems.

DESCRIPTION:
    This module performs comprehensive STIG compliance checks based on DISA security
    technical implementation guides for Linux operating systems. Covers controls from:
    
    Account Management (AC):
    - Account creation and management
    - Account restrictions and limitations
    - Session management
    - Privilege escalation controls
    
    Audit and Accountability (AU):
    - Audit logging configuration
    - Audit record generation
    - Audit storage and protection
    - Audit review and analysis
    
    Configuration Management (CM):
    - Baseline configuration
    - Configuration settings
    - Security hardening
    - Software integrity
    
    Identification and Authentication (IA):
    - User identification
    - Authenticator management
    - Multi-factor authentication
    - Password policies and complexity
    
    System and Communications Protection (SC):
    - Boundary protection
    - Transmission confidentiality
    - Network separation
    - Cryptographic protection
    
    System and Information Integrity (SI):
    - Flaw remediation
    - Malicious code protection
    - Security alerts and advisories
    - Software and information integrity
    
    Access Control (AC):
    - Account enforcement
    - Access enforcement
    - Information flow enforcement
    - Least privilege
    
    Based on DISA STIGs:
    - Red Hat Enterprise Linux 8 STIG V1R12
    - Red Hat Enterprise Linux 9 STIG V1R3
    - Ubuntu 20.04 STIG V1R9
    - General Purpose Operating System STIG

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

USAGE:
# Standalone testing
cd /mnt/user-data/outputs/modules
python3 module_stig.py

# Integrated with main script
python3 linux_security_audit.py -m stig

NOTES:
    Version: 1.0
    Reference: https://public.cyber.mil/stigs/
    Standards: DISA STIG, NIST SP 800-53, DoD 8500 series
    CAT I: Critical/High severity findings
    CAT II: Medium severity findings  
    CAT III: Low severity findings
"""

import os
import sys
import re
import subprocess
import glob
import pwd
import grp
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))
from linux_security_audit import AuditResult

MODULE_NAME = "STIG"

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

def get_stig_id(category: str, number: int) -> str:
    """Generate STIG ID format"""
    return f"V-{number:06d}"


# ============================================================================
# Account Management (AC) - STIG Controls
# ============================================================================

def check_account_management(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    STIG AC - Account Management Controls
    Covers account creation, maintenance, and restrictions
    Maps to: RHEL-08-010020 through RHEL-08-010180
    """
    print(f"[{MODULE_NAME}] Checking account management (STIG AC)...")
    
    # RHEL-08-010020: Accounts must be locked after 3 unsuccessful logon attempts (CAT II)
    faillock_conf = read_file_safe("/etc/security/faillock.conf")
    pam_files = ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth", "/etc/pam.d/common-auth"]
    
    faillock_configured = False
    deny_value = None
    
    # Check faillock.conf
    if faillock_conf:
        deny_match = re.search(r'^\s*deny\s*=\s*(\d+)', faillock_conf, re.MULTILINE)
        if deny_match:
            deny_value = int(deny_match.group(1))
            if deny_value <= 3:
                faillock_configured = True
    
    # Check PAM configuration
    for pam_file in pam_files:
        if os.path.exists(pam_file):
            pam_content = read_file_safe(pam_file)
            if "pam_faillock" in pam_content:
                deny_pam = re.search(r'pam_faillock.*deny=(\d+)', pam_content)
                if deny_pam and int(deny_pam.group(1)) <= 3:
                    faillock_configured = True
                    deny_value = int(deny_pam.group(1))
    
    if faillock_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10020)}: Account lockout after failed attempts configured (CAT II)",
            details=f"Accounts locked after {deny_value} failed attempts",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10020)}: Account lockout not properly configured (CAT II)",
            details="System must lock accounts after 3 unsuccessful logon attempts",
            remediation="Configure pam_faillock: echo 'deny = 3' >> /etc/security/faillock.conf"
        ))
    
    # RHEL-08-010030: Accounts must remain locked for 15 minutes (CAT II)
    unlock_time = None
    if faillock_conf:
        unlock_match = re.search(r'^\s*unlock_time\s*=\s*(\d+)', faillock_conf, re.MULTILINE)
        if unlock_match:
            unlock_time = int(unlock_match.group(1))
    
    if unlock_time and unlock_time >= 900:  # 900 seconds = 15 minutes
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10030)}: Account lockout duration configured (CAT II)",
            details=f"Accounts locked for {unlock_time} seconds",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10030)}: Account lockout duration insufficient (CAT II)",
            details="Accounts must remain locked for at least 15 minutes (900 seconds)",
            remediation="Configure faillock: echo 'unlock_time = 900' >> /etc/security/faillock.conf"
        ))
    
    # RHEL-08-010040: Account identifiers must be disabled after 35 days of inactivity (CAT II)
    useradd_inactive = read_file_safe("/etc/default/useradd")
    inactive_match = re.search(r'^\s*INACTIVE\s*=\s*(\d+)', useradd_inactive, re.MULTILINE)
    
    if inactive_match and int(inactive_match.group(1)) <= 35 and int(inactive_match.group(1)) >= 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10040)}: Account inactivity period configured (CAT II)",
            details=f"Accounts disabled after {inactive_match.group(1)} days of inactivity",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10040)}: Account inactivity period not configured (CAT II)",
            details="Accounts must be disabled after 35 days of inactivity",
            remediation="sudo useradd -D -f 35"
        ))
    
    # RHEL-08-010050: Emergency accounts must be automatically removed or disabled (CAT I)
    passwd_content = read_file_safe("/etc/passwd")
    emergency_keywords = ["emergency", "emerg", "temp", "temporary"]
    emergency_accounts = []
    
    for line in passwd_content.split('\n'):
        if line and not line.startswith('#'):
            username = line.split(':')[0]
            if any(keyword in username.lower() for keyword in emergency_keywords):
                emergency_accounts.append(username)
    
    if emergency_accounts:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Warning",
            message=f"{get_stig_id('RHEL-08', 10050)}: Emergency accounts detected (CAT I)",
            details=f"Emergency accounts found: {', '.join(emergency_accounts)}. Verify expiration.",
            remediation="Set expiration: sudo chage -E $(date -d '+72 hours' +%Y-%m-%d) USERNAME"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10050)}: No emergency accounts detected (CAT I)",
            details="No emergency or temporary accounts found",
            remediation=""
        ))
    
    # RHEL-08-010070: All account passwords must have a minimum lifetime of 24 hours (CAT II)
    login_defs = read_file_safe("/etc/login.defs")
    pass_min_days = re.search(r'^\s*PASS_MIN_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    
    if pass_min_days and int(pass_min_days.group(1)) >= 1:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10070)}: Password minimum age configured (CAT II)",
            details=f"PASS_MIN_DAYS set to {pass_min_days.group(1)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10070)}: Password minimum age not configured (CAT II)",
            details="Password minimum lifetime must be at least 1 day",
            remediation="sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs"
        ))
    
    # RHEL-08-010080: All account passwords must have a maximum lifetime of 60 days (CAT II)
    pass_max_days = re.search(r'^\s*PASS_MAX_DAYS\s+(\d+)', login_defs, re.MULTILINE)
    
    if pass_max_days and int(pass_max_days.group(1)) <= 60 and int(pass_max_days.group(1)) > 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10080)}: Password maximum age configured (CAT II)",
            details=f"PASS_MAX_DAYS set to {pass_max_days.group(1)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10080)}: Password maximum age not configured (CAT II)",
            details="Password maximum lifetime must be 60 days or less",
            remediation="sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 60/' /etc/login.defs"
        ))
    
    # RHEL-08-010090: Passwords must have minimum of 15-character length (CAT II)
    pwquality_conf = read_file_safe("/etc/security/pwquality.conf")
    minlen_match = re.search(r'^\s*minlen\s*=\s*(\d+)', pwquality_conf, re.MULTILINE)
    
    if minlen_match and int(minlen_match.group(1)) >= 15:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10090)}: Password minimum length configured (CAT II)",
            details=f"Minimum password length: {minlen_match.group(1)} characters",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10090)}: Password minimum length insufficient (CAT II)",
            details="Passwords must be at least 15 characters",
            remediation="echo 'minlen = 15' >> /etc/security/pwquality.conf"
        ))
    
    # RHEL-08-010100: Passwords must contain at least one uppercase character (CAT II)
    ucredit_match = re.search(r'^\s*ucredit\s*=\s*(-?\d+)', pwquality_conf, re.MULTILINE)
    
    if ucredit_match and int(ucredit_match.group(1)) < 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10100)}: Password uppercase requirement configured (CAT II)",
            details="Passwords must contain uppercase characters",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10100)}: Password uppercase requirement not configured (CAT II)",
            details="Passwords must contain at least one uppercase character",
            remediation="echo 'ucredit = -1' >> /etc/security/pwquality.conf"
        ))
    
    # RHEL-08-010110: Passwords must contain at least one lowercase character (CAT II)
    lcredit_match = re.search(r'^\s*lcredit\s*=\s*(-?\d+)', pwquality_conf, re.MULTILINE)
    
    if lcredit_match and int(lcredit_match.group(1)) < 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10110)}: Password lowercase requirement configured (CAT II)",
            details="Passwords must contain lowercase characters",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10110)}: Password lowercase requirement not configured (CAT II)",
            details="Passwords must contain at least one lowercase character",
            remediation="echo 'lcredit = -1' >> /etc/security/pwquality.conf"
        ))
    
    # RHEL-08-010120: Passwords must contain at least one numeric character (CAT II)
    dcredit_match = re.search(r'^\s*dcredit\s*=\s*(-?\d+)', pwquality_conf, re.MULTILINE)
    
    if dcredit_match and int(dcredit_match.group(1)) < 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10120)}: Password numeric requirement configured (CAT II)",
            details="Passwords must contain numeric characters",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10120)}: Password numeric requirement not configured (CAT II)",
            details="Passwords must contain at least one numeric character",
            remediation="echo 'dcredit = -1' >> /etc/security/pwquality.conf"
        ))
    
    # RHEL-08-010130: Passwords must contain at least one special character (CAT II)
    ocredit_match = re.search(r'^\s*ocredit\s*=\s*(-?\d+)', pwquality_conf, re.MULTILINE)
    
    if ocredit_match and int(ocredit_match.group(1)) < 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10130)}: Password special character requirement configured (CAT II)",
            details="Passwords must contain special characters",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10130)}: Password special character requirement not configured (CAT II)",
            details="Passwords must contain at least one special character",
            remediation="echo 'ocredit = -1' >> /etc/security/pwquality.conf"
        ))
    
    # RHEL-08-010140: Must require at least 8 characters be changed between old and new passwords (CAT II)
    difok_match = re.search(r'^\s*difok\s*=\s*(\d+)', pwquality_conf, re.MULTILINE)
    
    if difok_match and int(difok_match.group(1)) >= 8:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10140)}: Password change requirement configured (CAT II)",
            details=f"At least {difok_match.group(1)} characters must differ",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10140)}: Password change requirement not configured (CAT II)",
            details="At least 8 characters must differ between old and new passwords",
            remediation="echo 'difok = 8' >> /etc/security/pwquality.conf"
        ))
    
    # RHEL-08-010150: Passwords must be prohibited from reuse for 5 generations (CAT II)
    pam_password_files = ["/etc/pam.d/system-auth", "/etc/pam.d/password-auth", "/etc/pam.d/common-password"]
    
    remember_configured = False
    for pam_file in pam_password_files:
        if os.path.exists(pam_file):
            pam_content = read_file_safe(pam_file)
            remember_match = re.search(r'pam_pwhistory.*remember=(\d+)', pam_content)
            if not remember_match:
                remember_match = re.search(r'pam_unix.*remember=(\d+)', pam_content)
            
            if remember_match and int(remember_match.group(1)) >= 5:
                remember_configured = True
                break
    
    if remember_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10150)}: Password history configured (CAT II)",
            details="Password reuse prohibited for 5 generations",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10150)}: Password history not configured (CAT II)",
            details="Passwords must be prohibited from reuse for 5 generations",
            remediation="Add 'remember=5' to pam_pwhistory or pam_unix in PAM configuration"
        ))
    
    # RHEL-08-010160: Passwords must not be stored using reversible encryption (CAT I)
    shadow_content = read_file_safe("/etc/shadow")
    reversible_encryption = False
    weak_hashes = []
    
    for line in shadow_content.split('\n'):
        if line and not line.startswith('#'):
            parts = line.split(':')
            if len(parts) >= 2 and parts[1] and parts[1] not in ['!', '*', '!!']:
                # Check if password field contains DES, MD5, or other weak hashes
                if parts[1].startswith('$1$'):  # MD5
                    weak_hashes.append(f"{parts[0]} (MD5)")
                    reversible_encryption = True
                elif not parts[1].startswith('$'):  # DES or crypt
                    weak_hashes.append(f"{parts[0]} (DES/crypt)")
                    reversible_encryption = True
    
    if not reversible_encryption:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10160)}: Strong password hashing in use (CAT I)",
            details="Passwords use SHA-256 or SHA-512 hashing",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Account Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10160)}: Weak password hashing detected (CAT I)",
            details=f"Weak hashes found: {', '.join(weak_hashes[:5])}",
            remediation="Configure SHA-512 in /etc/login.defs: ENCRYPT_METHOD SHA512"
        ))
    
    # RHEL-08-010170: System must require root password for single-user mode (CAT II)
    if os.path.exists("/usr/lib/systemd/system/rescue.service"):
        rescue_service = read_file_safe("/usr/lib/systemd/system/rescue.service")
        if "ExecStart=-/usr/lib/systemd/systemd-sulogin-shell rescue" in rescue_service:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Account Management",
                status="Pass",
                message=f"{get_stig_id('RHEL-08', 10170)}: Root password required for rescue mode (CAT II)",
                details="Single-user/rescue mode requires authentication",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Account Management",
                status="Warning",
                message=f"{get_stig_id('RHEL-08', 10170)}: Rescue mode authentication unclear (CAT II)",
                details="Verify rescue.service requires root password",
                remediation="Edit /usr/lib/systemd/system/rescue.service to include sulogin"
            ))


# ============================================================================
# Audit and Accountability (AU) - STIG Controls
# ============================================================================

def check_audit_and_accountability(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    STIG AU - Audit and Accountability Controls
    Covers audit logging, review, and protection
    Maps to: RHEL-08-030000 through RHEL-08-030730
    """
    print(f"[{MODULE_NAME}] Checking audit and accountability (STIG AU)...")
    
    # RHEL-08-030000: Audit service must be installed (CAT II)
    if check_package_installed("audit") or check_package_installed("auditd"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 30000)}: Audit service is installed (CAT II)",
            details="auditd package is present",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 30000)}: Audit service not installed (CAT II)",
            details="auditd must be installed for security auditing",
            remediation="sudo apt-get install auditd || sudo yum install audit"
        ))
    
    # RHEL-08-030010: Audit service must be enabled (CAT II)
    if check_service_enabled("auditd"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 30010)}: Audit service is enabled (CAT II)",
            details="auditd will start on boot",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 30010)}: Audit service not enabled (CAT II)",
            details="auditd must be enabled to start on boot",
            remediation="sudo systemctl enable auditd"
        ))
    
    # RHEL-08-030020: Audit service must be active (CAT II)
    if check_service_active("auditd"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 30020)}: Audit service is running (CAT II)",
            details="auditd is actively collecting audit records",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 30020)}: Audit service not running (CAT II)",
            details="auditd must be running to collect audit records",
            remediation="sudo systemctl start auditd"
        ))
    
    # RHEL-08-030030: Auditing must be enabled at boot (CAT II)
    grub_cfg_locations = [
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg",
        "/boot/efi/EFI/*/grub.cfg"
    ]
    
    audit_enabled_at_boot = False
    for location in grub_cfg_locations:
        for grub_file in glob.glob(location):
            if os.path.exists(grub_file):
                grub_content = read_file_safe(grub_file)
                if "audit=1" in grub_content:
                    audit_enabled_at_boot = True
                    break
        if audit_enabled_at_boot:
            break
    
    # Also check /etc/default/grub
    if os.path.exists("/etc/default/grub"):
        default_grub = read_file_safe("/etc/default/grub")
        if "audit=1" in default_grub:
            audit_enabled_at_boot = True
    
    if audit_enabled_at_boot:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 30030)}: Auditing enabled at boot (CAT II)",
            details="audit=1 kernel parameter configured",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 30030)}: Auditing not enabled at boot (CAT II)",
            details="audit=1 must be in kernel parameters",
            remediation="Add 'audit=1' to GRUB_CMDLINE_LINUX in /etc/default/grub and run grub2-mkconfig"
        ))
    
    # RHEL-08-030040: Audit backlog limit must be sufficient (CAT II)
    backlog_limit_set = False
    for location in grub_cfg_locations:
        for grub_file in glob.glob(location):
            if os.path.exists(grub_file):
                grub_content = read_file_safe(grub_file)
                backlog_match = re.search(r'audit_backlog_limit=(\d+)', grub_content)
                if backlog_match and int(backlog_match.group(1)) >= 8192:
                    backlog_limit_set = True
                    break
        if backlog_limit_set:
            break
    
    if os.path.exists("/etc/default/grub"):
        default_grub = read_file_safe("/etc/default/grub")
        backlog_match = re.search(r'audit_backlog_limit=(\d+)', default_grub)
        if backlog_match and int(backlog_match.group(1)) >= 8192:
            backlog_limit_set = True
    
    if backlog_limit_set:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 30040)}: Audit backlog limit sufficient (CAT II)",
            details="audit_backlog_limit >= 8192",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 30040)}: Audit backlog limit not set (CAT II)",
            details="audit_backlog_limit must be at least 8192",
            remediation="Add 'audit_backlog_limit=8192' to GRUB_CMDLINE_LINUX in /etc/default/grub"
        ))
    
    # RHEL-08-030050: Audit log directory must have proper permissions (CAT II)
    audit_log_dir = "/var/log/audit"
    
    if os.path.exists(audit_log_dir):
        perms = get_file_permissions(audit_log_dir)
        owner, group = get_file_owner_group(audit_log_dir)
        
        if perms and perms == "700" and owner == "root" and group == "root":
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Audit",
                status="Pass",
                message=f"{get_stig_id('RHEL-08', 30050)}: Audit log directory properly secured (CAT II)",
                details=f"{audit_log_dir} has 0700 permissions, owned by root:root",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Audit",
                status="Fail",
                message=f"{get_stig_id('RHEL-08', 30050)}: Audit log directory permissions incorrect (CAT II)",
                details=f"{audit_log_dir} must be 0700 and owned by root:root (current: {perms}, {owner}:{group})",
                remediation=f"sudo chmod 0700 {audit_log_dir} && sudo chown root:root {audit_log_dir}"
            ))
    
    # RHEL-08-030060: Audit log files must have proper permissions (CAT II)
    if os.path.exists(audit_log_dir):
        audit_logs = glob.glob(f"{audit_log_dir}/audit.log*")
        improper_logs = []
        
        for log_file in audit_logs:
            perms = get_file_permissions(log_file)
            if perms and int(perms, 8) > int("0600", 8):
                improper_logs.append(log_file)
        
        if not improper_logs and audit_logs:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Audit",
                status="Pass",
                message=f"{get_stig_id('RHEL-08', 30060)}: Audit log files properly secured (CAT II)",
                details=f"{len(audit_logs)} audit log file(s) have correct permissions",
                remediation=""
            ))
        elif improper_logs:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Audit",
                status="Fail",
                message=f"{get_stig_id('RHEL-08', 30060)}: Audit log files have incorrect permissions (CAT II)",
                details=f"{len(improper_logs)} file(s) with improper permissions",
                remediation=f"sudo chmod 0600 {audit_log_dir}/audit.log*"
            ))
    
    # RHEL-08-030070: Audit system must take action when storage is full (CAT II)
    auditd_conf = read_file_safe("/etc/audit/auditd.conf")
    
    space_left_action = re.search(r'^\s*space_left_action\s*=\s*(\w+)', auditd_conf, re.MULTILINE)
    admin_space_left_action = re.search(r'^\s*admin_space_left_action\s*=\s*(\w+)', auditd_conf, re.MULTILINE)
    disk_full_action = re.search(r'^\s*disk_full_action\s*=\s*(\w+)', auditd_conf, re.MULTILINE)
    disk_error_action = re.search(r'^\s*disk_error_action\s*=\s*(\w+)', auditd_conf, re.MULTILINE)
    
    proper_actions = ["SYSLOG", "EXEC", "SINGLE", "HALT"]
    
    actions_configured = (
        space_left_action and space_left_action.group(1).upper() in proper_actions and
        disk_full_action and disk_full_action.group(1).upper() in ["SYSLOG", "SINGLE", "HALT"]
    )
    
    if actions_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 30070)}: Audit storage full actions configured (CAT II)",
            details="Appropriate actions configured for low/full storage",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 30070)}: Audit storage full actions not configured (CAT II)",
            details="Must configure space_left_action and disk_full_action",
            remediation="Configure in /etc/audit/auditd.conf: space_left_action = SYSLOG, disk_full_action = HALT"
        ))
    
    # RHEL-08-030080: Audit records must be off-loaded to a different system (CAT II)
    audisp_remote_conf = "/etc/audisp/plugins.d/au-remote.conf"
    audit_remote_conf = "/etc/audit/plugins.d/au-remote.conf"
    
    remote_logging = False
    for remote_conf_file in [audisp_remote_conf, audit_remote_conf]:
        if os.path.exists(remote_conf_file):
            remote_conf = read_file_safe(remote_conf_file)
            active_match = re.search(r'^\s*active\s*=\s*(\w+)', remote_conf, re.MULTILINE)
            
            if active_match and active_match.group(1).lower() == "yes":
                remote_logging = True
                break
    
    if remote_logging:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 30080)}: Remote audit logging configured (CAT II)",
            details="Audit records are being sent to remote system",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Info",
            message=f"{get_stig_id('RHEL-08', 30080)}: Remote audit logging not active (CAT II)",
            details="Consider configuring remote audit logging",
            remediation="Configure au-remote plugin: set 'active = yes' in /etc/audit/plugins.d/au-remote.conf"
        ))
    
    # RHEL-08-030090: Audit system must protect audit tools (CAT II)
    audit_tools = [
        "/sbin/auditctl",
        "/sbin/aureport",
        "/sbin/ausearch",
        "/sbin/autrace",
        "/sbin/auditd",
        "/sbin/audispd",
        "/sbin/augenrules"
    ]
    
    protected_tools = []
    unprotected_tools = []
    
    for tool in audit_tools:
        if os.path.exists(tool):
            perms = get_file_permissions(tool)
            owner, group = get_file_owner_group(tool)
            
            if perms and int(perms, 8) <= int("0755", 8) and owner == "root":
                protected_tools.append(tool)
            else:
                unprotected_tools.append(tool)
    
    if protected_tools and not unprotected_tools:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 30090)}: Audit tools properly protected (CAT II)",
            details=f"{len(protected_tools)} audit tools have correct permissions",
            remediation=""
        ))
    elif unprotected_tools:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 30090)}: Some audit tools not protected (CAT II)",
            details=f"{len(unprotected_tools)} tool(s) have incorrect permissions",
            remediation="sudo chmod 0755 /sbin/audit* && sudo chown root:root /sbin/audit*"
        ))
    
    # RHEL-08-030100: Audit records must contain information about what type of events occurred (CAT II)
    audit_rules_count = 0
    
    if os.path.exists("/etc/audit/rules.d"):
        audit_rules_count = len([f for f in os.listdir("/etc/audit/rules.d") if f.endswith('.rules')])
    
    if os.path.exists("/etc/audit/audit.rules"):
        audit_rules = read_file_safe("/etc/audit/audit.rules")
        if audit_rules.count('\n') > 10:  # Basic check for rules
            audit_rules_count += 1
    
    if audit_rules_count > 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 30100)}: Audit rules configured (CAT II)",
            details=f"Found {audit_rules_count} audit rule file(s)",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 30100)}: No audit rules configured (CAT II)",
            details="Audit rules must be configured to capture security events",
            remediation="Configure audit rules in /etc/audit/rules.d/ and reload: sudo augenrules --load"
        ))
    
    # RHEL-08-030110: Audit must generate records for privileged functions (CAT II)
    # Check for common privileged command auditing
    privileged_commands = [
        "/usr/bin/sudo",
        "/usr/bin/su",
        "/usr/bin/passwd",
        "/usr/bin/chsh",
        "/usr/bin/chfn"
    ]
    
    audit_rules_files = glob.glob("/etc/audit/rules.d/*.rules")
    if os.path.exists("/etc/audit/audit.rules"):
        audit_rules_files.append("/etc/audit/audit.rules")
    
    privileged_audited = []
    for rules_file in audit_rules_files:
        rules_content = read_file_safe(rules_file)
        for cmd in privileged_commands:
            if cmd in rules_content:
                privileged_audited.append(cmd)
    
    if len(privileged_audited) >= 3:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 30110)}: Privileged command auditing configured (CAT II)",
            details=f"{len(privileged_audited)} privileged commands are audited",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Audit",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 30110)}: Insufficient privileged command auditing (CAT II)",
            details="Must audit sudo, su, passwd, and other privileged commands",
            remediation="Add audit rules for privileged commands: -w /usr/bin/sudo -p x -k privileged"
        ))


# ============================================================================
# Identification and Authentication (IA) - STIG Controls
# ============================================================================

def check_identification_authentication(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    STIG IA - Identification and Authentication
    Covers user identification and authenticator management
    Maps to: RHEL-08-020000 through RHEL-08-020350
    """
    print(f"[{MODULE_NAME}] Checking identification and authentication (STIG IA)...")
    
    # RHEL-08-020000: System must display Standard Mandatory DoD Notice (CAT II)
    dod_banner_keywords = ["authorized", "monitor", "consent", "government", "security"]
    
    banner_files = ["/etc/issue", "/etc/issue.net", "/etc/motd"]
    banner_configured = False
    banner_details = []
    
    for banner_file in banner_files:
        if os.path.exists(banner_file):
            content = read_file_safe(banner_file)
            if content and len(content) > 20:
                keyword_count = sum(1 for keyword in dod_banner_keywords if keyword.lower() in content.lower())
                if keyword_count >= 2:
                    banner_configured = True
                    banner_details.append(banner_file)
    
    if banner_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Identification/Authentication",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 20000)}: System banner configured (CAT II)",
            details=f"Consent banner present in: {', '.join(banner_details)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Identification/Authentication",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 20000)}: System banner not configured (CAT II)",
            details="Must display Standard Mandatory DoD Notice and Consent Banner",
            remediation="Add appropriate consent banner to /etc/issue and /etc/issue.net"
        ))
    
    # RHEL-08-020010: System must not have accounts configured with blank or null passwords (CAT I)
    shadow_content = read_file_safe("/etc/shadow")
    blank_password_accounts = []
    
    for line in shadow_content.split('\n'):
        if line and not line.startswith('#'):
            parts = line.split(':')
            if len(parts) >= 2:
                username = parts[0]
                password_field = parts[1]
                
                # Check for truly blank (empty) password field, not locked accounts
                if password_field == '':
                    try:
                        user_info = pwd.getpwnam(username)
                        if user_info.pw_uid >= 1000:  # Regular user account
                            blank_password_accounts.append(username)
                    except:
                        pass
    
    if not blank_password_accounts:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Identification/Authentication",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 20010)}: No accounts with blank passwords (CAT I)",
            details="All user accounts have passwords configured",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Identification/Authentication",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 20010)}: Accounts with blank passwords detected (CAT I)",
            details=f"Accounts: {', '.join(blank_password_accounts)}",
            remediation="Set passwords: sudo passwd USERNAME or lock accounts: sudo passwd -l USERNAME"
        ))
    
    # RHEL-08-020020: SSH daemon must be configured to use only FIPS 140-2 approved MACs (CAT II)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        # FIPS approved MACs
        approved_macs = [
            "hmac-sha2-256",
            "hmac-sha2-512",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com"
        ]
        
        macs_match = re.search(r'^\s*MACs\s+(.+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if macs_match:
            configured_macs = [m.strip() for m in macs_match.group(1).strip().split(',')]
            all_approved = all(any(approved in mac for approved in approved_macs) for mac in configured_macs if mac)
            
            if all_approved and configured_macs:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="STIG - Identification/Authentication",
                    status="Pass",
                    message=f"{get_stig_id('RHEL-08', 20020)}: SSH MACs FIPS 140-2 approved (CAT II)",
                    details="SSH configured with approved message authentication codes",
                    remediation=""
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="STIG - Identification/Authentication",
                    status="Fail",
                    message=f"{get_stig_id('RHEL-08', 20020)}: SSH MACs not FIPS 140-2 approved (CAT II)",
                    details="SSH must use only FIPS approved MACs",
                    remediation="Add to /etc/ssh/sshd_config: MACs hmac-sha2-512,hmac-sha2-256"
                ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Fail",
                message=f"{get_stig_id('RHEL-08', 20020)}: SSH MACs not configured (CAT II)",
                details="SSH MACs must be explicitly configured",
                remediation="Add to /etc/ssh/sshd_config: MACs hmac-sha2-512,hmac-sha2-256"
            ))
    
    # RHEL-08-020030: SSH daemon must be configured to use only FIPS 140-2 approved ciphers (CAT II)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        # FIPS approved ciphers
        approved_ciphers = [
            "aes128-ctr",
            "aes192-ctr",
            "aes256-ctr",
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com"
        ]
        
        ciphers_match = re.search(r'^\s*Ciphers\s+(.+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if ciphers_match:
            configured_ciphers = [c.strip() for c in ciphers_match.group(1).strip().split(',')]
            weak_ciphers = []
            
            for cipher in configured_ciphers:
                if cipher and not any(approved in cipher.lower() for approved in approved_ciphers):
                    weak_ciphers.append(cipher)
            
            if not weak_ciphers and configured_ciphers:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="STIG - Identification/Authentication",
                    status="Pass",
                    message=f"{get_stig_id('RHEL-08', 20030)}: SSH ciphers FIPS 140-2 approved (CAT II)",
                    details="SSH configured with approved ciphers",
                    remediation=""
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="STIG - Identification/Authentication",
                    status="Fail",
                    message=f"{get_stig_id('RHEL-08', 20030)}: SSH has non-FIPS approved ciphers (CAT II)",
                    details=f"Weak ciphers: {', '.join(weak_ciphers)}",
                    remediation="Configure FIPS ciphers in /etc/ssh/sshd_config: Ciphers aes256-ctr,aes192-ctr,aes128-ctr"
                ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Warning",
                message=f"{get_stig_id('RHEL-08', 20030)}: SSH ciphers not explicitly configured (CAT II)",
                details="Explicitly configure FIPS approved ciphers",
                remediation="Add to /etc/ssh/sshd_config: Ciphers aes256-ctr,aes192-ctr,aes128-ctr"
            ))
    
    # RHEL-08-020040: SSH daemon must perform strict mode checking of home directory files (CAT II)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        strictmodes_match = re.search(r'^\s*StrictModes\s+(\w+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if strictmodes_match and strictmodes_match.group(1).lower() == "yes":
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Pass",
                message=f"{get_stig_id('RHEL-08', 20040)}: SSH StrictModes enabled (CAT II)",
                details="SSH will check file permissions before authentication",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Fail",
                message=f"{get_stig_id('RHEL-08', 20040)}: SSH StrictModes not enabled (CAT II)",
                details="StrictModes must be set to 'yes'",
                remediation="Add to /etc/ssh/sshd_config: StrictModes yes"
            ))
    
    # RHEL-08-020050: SSH daemon must not allow compression or must only allow compression after authentication (CAT II)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        compression_match = re.search(r'^\s*Compression\s+(\w+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if compression_match and compression_match.group(1).lower() in ["no", "delayed"]:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Pass",
                message=f"{get_stig_id('RHEL-08', 20050)}: SSH compression properly configured (CAT II)",
                details=f"Compression set to: {compression_match.group(1)}",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Fail",
                message=f"{get_stig_id('RHEL-08', 20050)}: SSH compression not properly configured (CAT II)",
                details="Compression must be 'no' or 'delayed'",
                remediation="Add to /etc/ssh/sshd_config: Compression delayed"
            ))
    
    # RHEL-08-020060: SSH daemon must not allow authentication using known host's authentication (CAT II)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        hostbased_match = re.search(r'^\s*HostbasedAuthentication\s+(\w+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if hostbased_match and hostbased_match.group(1).lower() == "no":
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Pass",
                message=f"{get_stig_id('RHEL-08', 20060)}: SSH host-based authentication disabled (CAT II)",
                details="HostbasedAuthentication is set to 'no'",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Fail",
                message=f"{get_stig_id('RHEL-08', 20060)}: SSH host-based authentication not disabled (CAT II)",
                details="HostbasedAuthentication must be set to 'no'",
                remediation="Add to /etc/ssh/sshd_config: HostbasedAuthentication no"
            ))
    
    # RHEL-08-020070: SSH daemon must not permit user environment settings (CAT II)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        permitenv_match = re.search(r'^\s*PermitUserEnvironment\s+(\w+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if permitenv_match and permitenv_match.group(1).lower() == "no":
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Pass",
                message=f"{get_stig_id('RHEL-08', 20070)}: SSH user environment disabled (CAT II)",
                details="PermitUserEnvironment is set to 'no'",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Fail",
                message=f"{get_stig_id('RHEL-08', 20070)}: SSH user environment not disabled (CAT II)",
                details="PermitUserEnvironment must be set to 'no'",
                remediation="Add to /etc/ssh/sshd_config: PermitUserEnvironment no"
            ))
    
    # RHEL-08-020080: SSH daemon must not allow X11 forwarding (CAT II)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        x11_match = re.search(r'^\s*X11Forwarding\s+(\w+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if x11_match and x11_match.group(1).lower() == "no":
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Pass",
                message=f"{get_stig_id('RHEL-08', 20080)}: SSH X11 forwarding disabled (CAT II)",
                details="X11Forwarding is set to 'no'",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Fail",
                message=f"{get_stig_id('RHEL-08', 20080)}: SSH X11 forwarding not disabled (CAT II)",
                details="X11Forwarding must be set to 'no'",
                remediation="Add to /etc/ssh/sshd_config: X11Forwarding no"
            ))
    
    # RHEL-08-020090: SSH daemon must not permit tunnels (CAT II)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        tunnel_match = re.search(r'^\s*PermitTunnel\s+(\w+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if tunnel_match and tunnel_match.group(1).lower() == "no":
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Pass",
                message=f"{get_stig_id('RHEL-08', 20090)}: SSH tunneling disabled (CAT II)",
                details="PermitTunnel is set to 'no'",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Fail",
                message=f"{get_stig_id('RHEL-08', 20090)}: SSH tunneling not disabled (CAT II)",
                details="PermitTunnel must be set to 'no'",
                remediation="Add to /etc/ssh/sshd_config: PermitTunnel no"
            ))
    
    # RHEL-08-020100: SSH must prevent remote hosts from connecting to proxy display (CAT II)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        x11uselocal_match = re.search(r'^\s*X11UseLocalhost\s+(\w+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if x11uselocal_match and x11uselocal_match.group(1).lower() == "yes":
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Pass",
                message=f"{get_stig_id('RHEL-08', 20100)}: SSH X11 localhost binding enabled (CAT II)",
                details="X11UseLocalhost is set to 'yes'",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Identification/Authentication",
                status="Info",
                message=f"{get_stig_id('RHEL-08', 20100)}: SSH X11 localhost binding not configured (CAT II)",
                details="If X11 is used, X11UseLocalhost should be 'yes'",
                remediation="Add to /etc/ssh/sshd_config: X11UseLocalhost yes"
            ))


# ============================================================================
# System and Communications Protection (SC) - STIG Controls
# ============================================================================

def check_system_communications_protection(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    STIG SC - System and Communications Protection
    Covers network protection, encryption, and communications security
    Maps to: RHEL-08-040000 through RHEL-08-040380
    """
    print(f"[{MODULE_NAME}] Checking system and communications protection (STIG SC)...")
    
    # RHEL-08-040010: System must prevent IPv4 ICMP redirect messages (CAT II)
    icmp_params = [
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.conf.default.accept_redirects", "0")
    ]
    
    all_configured = True
    for param, expected in icmp_params:
        found, value = check_kernel_parameter(param)
        if not found or value != expected:
            all_configured = False
            break
    
    if all_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 40010)}: IPv4 ICMP redirects disabled (CAT II)",
            details="ICMP redirect acceptance is disabled",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 40010)}: IPv4 ICMP redirects not disabled (CAT II)",
            details="System must not accept ICMP redirects",
            remediation="Configure sysctl: net.ipv4.conf.all.accept_redirects=0, net.ipv4.conf.default.accept_redirects=0"
        ))
    
    # RHEL-08-040020: System must not send IPv4 ICMP redirects (CAT II)
    send_redirects_params = [
        ("net.ipv4.conf.all.send_redirects", "0"),
        ("net.ipv4.conf.default.send_redirects", "0")
    ]
    
    all_configured = True
    for param, expected in send_redirects_params:
        found, value = check_kernel_parameter(param)
        if not found or value != expected:
            all_configured = False
            break
    
    if all_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 40020)}: IPv4 ICMP redirect sending disabled (CAT II)",
            details="System will not send ICMP redirects",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 40020)}: IPv4 ICMP redirect sending not disabled (CAT II)",
            details="System must not send ICMP redirects",
            remediation="Configure sysctl: net.ipv4.conf.all.send_redirects=0, net.ipv4.conf.default.send_redirects=0"
        ))
    
    # RHEL-08-040030: System must not respond to IPv4 ICMP echoes sent to broadcast address (CAT II)
    found, value = check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts")
    
    if found and value == "1":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 40030)}: ICMP broadcast echo ignore enabled (CAT II)",
            details="System ignores ICMP echoes to broadcast addresses",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 40030)}: ICMP broadcast echo ignore not enabled (CAT II)",
            details="System must ignore ICMP broadcast echoes",
            remediation="Configure sysctl: net.ipv4.icmp_echo_ignore_broadcasts=1"
        ))
    
    # RHEL-08-040040: System must ignore IPv4 bogus ICMP error responses (CAT II)
    found, value = check_kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses")
    
    if found and value == "1":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 40040)}: Bogus ICMP responses ignored (CAT II)",
            details="System ignores bogus ICMP error responses",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 40040)}: Bogus ICMP responses not ignored (CAT II)",
            details="System must ignore bogus ICMP error responses",
            remediation="Configure sysctl: net.ipv4.icmp_ignore_bogus_error_responses=1"
        ))
    
    # RHEL-08-040050: System must use reverse path filtering (CAT II)
    rp_filter_params = [
        ("net.ipv4.conf.all.rp_filter", "1"),
        ("net.ipv4.conf.default.rp_filter", "1")
    ]
    
    all_configured = True
    for param, expected in rp_filter_params:
        found, value = check_kernel_parameter(param)
        if not found or value != expected:
            all_configured = False
            break
    
    if all_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 40050)}: Reverse path filtering enabled (CAT II)",
            details="Source address validation is active",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 40050)}: Reverse path filtering not enabled (CAT II)",
            details="System must use reverse path filtering",
            remediation="Configure sysctl: net.ipv4.conf.all.rp_filter=1, net.ipv4.conf.default.rp_filter=1"
        ))
    
    # RHEL-08-040060: System must not accept source-routed IPv4 packets (CAT II)
    source_route_params = [
        ("net.ipv4.conf.all.accept_source_route", "0"),
        ("net.ipv4.conf.default.accept_source_route", "0")
    ]
    
    all_configured = True
    for param, expected in source_route_params:
        found, value = check_kernel_parameter(param)
        if not found or value != expected:
            all_configured = False
            break
    
    if all_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 40060)}: Source-routed packets rejected (CAT II)",
            details="Source routing is disabled",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 40060)}: Source-routed packets not rejected (CAT II)",
            details="System must not accept source-routed packets",
            remediation="Configure sysctl: net.ipv4.conf.all.accept_source_route=0, net.ipv4.conf.default.accept_source_route=0"
        ))
    
    # RHEL-08-040070: System must use TCP syncookies (CAT II)
    found, value = check_kernel_parameter("net.ipv4.tcp_syncookies")
    
    if found and value == "1":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 40070)}: TCP SYN cookies enabled (CAT II)",
            details="SYN flood attack mitigation is active",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 40070)}: TCP SYN cookies not enabled (CAT II)",
            details="System must use TCP syncookies for SYN flood protection",
            remediation="Configure sysctl: net.ipv4.tcp_syncookies=1"
        ))
    
    # RHEL-08-040080: System must be configured to use a firewall (CAT II)
    firewall_active = False
    firewall_type = None
    
    if command_exists("firewall-cmd"):
        firewall_state = run_command("firewall-cmd --state 2>/dev/null")
        if firewall_state.returncode == 0 and "running" in firewall_state.stdout.lower():
            firewall_active = True
            firewall_type = "firewalld"
    
    if command_exists("ufw") and not firewall_active:
        ufw_status = run_command("ufw status 2>/dev/null")
        if "Status: active" in ufw_status.stdout:
            firewall_active = True
            firewall_type = "ufw"
    
    if not firewall_active:
        iptables_rules = run_command("iptables -L -n 2>/dev/null | grep -v '^Chain' | grep -v '^target' | wc -l")
        if iptables_rules.returncode == 0 and int(iptables_rules.stdout.strip()) > 0:
            firewall_active = True
            firewall_type = "iptables"
    
    if firewall_active:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 40080)}: Firewall is active (CAT II)",
            details=f"Host-based firewall ({firewall_type}) is configured and running",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 40080)}: Firewall not active (CAT II)",
            details="System must have an active firewall",
            remediation="sudo systemctl enable --now firewalld || sudo ufw enable"
        ))
    
    # RHEL-08-040090: System must log martian packets (CAT II)
    log_martians_params = [
        ("net.ipv4.conf.all.log_martians", "1"),
        ("net.ipv4.conf.default.log_martians", "1")
    ]
    
    all_configured = True
    for param, expected in log_martians_params:
        found, value = check_kernel_parameter(param)
        if not found or value != expected:
            all_configured = False
            break
    
    if all_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 40090)}: Martian packet logging enabled (CAT II)",
            details="Suspicious packets are being logged",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 40090)}: Martian packet logging not enabled (CAT II)",
            details="System must log martian packets",
            remediation="Configure sysctl: net.ipv4.conf.all.log_martians=1, net.ipv4.conf.default.log_martians=1"
        ))
    
    # RHEL-08-040100: System must not forward IPv4 source-routed packets (CAT II)
    found, value = check_kernel_parameter("net.ipv4.conf.all.forwarding")
    
    if found and value == "0":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Communications Protection",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 40100)}: IPv4 forwarding disabled (CAT II)",
            details="System is not configured as a router",
            remediation=""
        ))

# ============================================================================
# System and Information Integrity (SI) - STIG Controls
# ============================================================================

def check_system_information_integrity(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    STIG SI - System and Information Integrity
    Covers flaw remediation, malicious code protection, security alerts
    Maps to: RHEL-08-010000 through RHEL-08-010430
    """
    print(f"[{MODULE_NAME}] Checking system and information integrity (STIG SI)...")
    
    # RHEL-08-010000: File integrity tool must be installed (CAT II)
    if check_package_installed("aide") or check_package_installed("aide-common"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - System Integrity",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10000)}: File integrity tool installed (CAT II)",
            details="AIDE is installed for file integrity monitoring",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - System Integrity",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10000)}: File integrity tool not installed (CAT II)",
            details="AIDE must be installed for file integrity checking",
            remediation="sudo apt-get install aide aide-common && sudo aideinit || sudo yum install aide && sudo aide --init"
        ))
    
    # RHEL-08-010010: File integrity tool must be configured (CAT II)
    aide_conf_locations = ["/etc/aide/aide.conf", "/etc/aide.conf"]
    aide_configured = False
    
    for conf_file in aide_conf_locations:
        if os.path.exists(conf_file):
            aide_conf = read_file_safe(conf_file)
            if len(aide_conf) > 100:  # Basic check for configuration
                aide_configured = True
                break
    
    if aide_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - System Integrity",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10010)}: File integrity tool configured (CAT II)",
            details="AIDE configuration file exists",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - System Integrity",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10010)}: File integrity tool not configured (CAT II)",
            details="AIDE must be configured with appropriate rules",
            remediation="Configure AIDE in /etc/aide/aide.conf and initialize database"
        ))
    
    # RHEL-08-010360: SELinux/AppArmor must be installed (CAT II)
    mac_installed = False
    mac_type = None
    
    if check_package_installed("libselinux"):
        mac_installed = True
        mac_type = "SELinux"
    elif check_package_installed("apparmor"):
        mac_installed = True
        mac_type = "AppArmor"
    
    if mac_installed:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - System Integrity",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10360)}: Mandatory Access Control installed (CAT II)",
            details=f"{mac_type} packages are present",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - System Integrity",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10360)}: MAC not installed (CAT II)",
            details="SELinux or AppArmor must be installed for mandatory access control",
            remediation="sudo yum install libselinux || sudo apt-get install apparmor"
        ))
    
    # RHEL-08-010370: SELinux/AppArmor must be configured in enforcing mode (CAT II)
    mac_enforcing = False
    
    if command_exists("getenforce"):
        selinux_status = run_command("getenforce").stdout.strip()
        if selinux_status == "Enforcing":
            mac_enforcing = True
            mac_type = "SELinux"
    elif command_exists("aa-status"):
        aa_status = run_command("aa-status 2>/dev/null")
        if "apparmor module is loaded" in aa_status.stdout.lower():
            mac_enforcing = True
            mac_type = "AppArmor"
    
    if mac_enforcing:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - System Integrity",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10370)}: {mac_type} in enforcing mode (CAT II)",
            details="Mandatory access control is actively enforcing policies",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - System Integrity",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10370)}: MAC not in enforcing mode (CAT II)",
            details="Mandatory access control must be active",
            remediation="sudo setenforce 1 || sudo systemctl enable apparmor && sudo systemctl start apparmor"
        ))
    
    # RHEL-08-010380: System must have virus protection installed (CAT II)
    antivirus_packages = ["clamav", "clamav-daemon", "mcafee", "sophos"]
    av_installed = False
    av_found = []
    
    for av_pkg in antivirus_packages:
        if check_package_installed(av_pkg):
            av_installed = True
            av_found.append(av_pkg)
    
    if av_installed:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - System Integrity",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10380)}: Antivirus protection installed (CAT II)",
            details=f"Virus scanning capability: {', '.join(av_found)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - System Integrity",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10380)}: Antivirus protection not installed (CAT II)",
            details="System must have virus scanning software",
            remediation="sudo apt-get install clamav clamav-daemon || sudo yum install clamav clamav-update"
        ))
    
    # RHEL-08-010390: System must update virus definitions at least weekly (CAT II)
    if check_package_installed("clamav"):
        freshclam_conf = "/etc/clamav/freshclam.conf"
        clamav_cron = glob.glob("/etc/cron.d/*clam*") or glob.glob("/etc/cron.daily/*clam*") or glob.glob("/etc/cron.weekly/*clam*")
        
        if os.path.exists(freshclam_conf) or clamav_cron:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - System Integrity",
                status="Pass",
                message=f"{get_stig_id('RHEL-08', 10390)}: Virus definitions update configured (CAT II)",
                details="ClamAV updates are scheduled",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - System Integrity",
                status="Warning",
                message=f"{get_stig_id('RHEL-08', 10390)}: Virus definitions update not configured (CAT II)",
                details="Configure automatic ClamAV database updates",
                remediation="Configure freshclam or add to cron: 0 2 * * * /usr/bin/freshclam"
            ))
    
    # RHEL-08-010400: System must notify designated personnel of account changes (CAT II)
    audit_rules_files = glob.glob("/etc/audit/rules.d/*.rules")
    if os.path.exists("/etc/audit/audit.rules"):
        audit_rules_files.append("/etc/audit/audit.rules")
    
    account_monitoring = False
    for rules_file in audit_rules_files:
        rules_content = read_file_safe(rules_file)
        if "/etc/passwd" in rules_content or "/etc/shadow" in rules_content or "/etc/group" in rules_content:
            account_monitoring = True
            break
    
    if account_monitoring:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - System Integrity",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10400)}: Account change monitoring configured (CAT II)",
            details="Audit rules monitor account file changes",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - System Integrity",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10400)}: Account change monitoring not configured (CAT II)",
            details="Must audit changes to /etc/passwd, /etc/shadow, /etc/group",
            remediation="Add audit rules: -w /etc/passwd -p wa -k identity, -w /etc/shadow -p wa -k identity, -w /etc/group -p wa -k identity"
        ))


# ============================================================================
# Configuration Management (CM) - STIG Controls
# ============================================================================

def check_configuration_management(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    STIG CM - Configuration Management
    Covers baseline configuration and security hardening
    Maps to: RHEL-08-010440 through RHEL-08-010490
    """
    print(f"[{MODULE_NAME}] Checking configuration management (STIG CM)...")
    
    # RHEL-08-010440: System security patches and updates must be installed (CAT II)
    update_check = None
    updates_available = False
    
    if command_exists("apt"):
        update_check = run_command("apt list --upgradable 2>/dev/null | grep -v 'Listing' | wc -l")
        if update_check.returncode == 0:
            pending = int(update_check.stdout.strip()) if update_check.stdout.strip().isdigit() else 0
            updates_available = pending > 0
    elif command_exists("yum"):
        update_check = run_command("yum check-update --quiet 2>&1 | grep -c '^[a-zA-Z]'")
        if update_check.returncode == 0 or update_check.returncode == 100:
            pending = int(update_check.stdout.strip()) if update_check.stdout.strip().isdigit() else 0
            updates_available = pending > 0
    
    if not updates_available:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Configuration Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10440)}: System is up to date (CAT II)",
            details="No pending security updates detected",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Configuration Management",
            status="Warning",
            message=f"{get_stig_id('RHEL-08', 10440)}: Pending security updates detected (CAT II)",
            details="Security updates are available",
            remediation="sudo apt-get update && sudo apt-get upgrade || sudo yum update"
        ))
    
    # RHEL-08-010450: System must disable kernel core dumps (CAT II)
    limits_conf = read_file_safe("/etc/security/limits.conf")
    limits_d_files = glob.glob("/etc/security/limits.d/*.conf")
    
    core_dump_disabled = False
    
    # Check limits.conf
    if re.search(r'^\s*\*\s+hard\s+core\s+0', limits_conf, re.MULTILINE):
        core_dump_disabled = True
    
    # Check limits.d files
    for limits_file in limits_d_files:
        content = read_file_safe(limits_file)
        if re.search(r'^\s*\*\s+hard\s+core\s+0', content, re.MULTILINE):
            core_dump_disabled = True
            break
    
    # Also check sysctl
    found, value = check_kernel_parameter("fs.suid_dumpable")
    if found and value == "0":
        core_dump_disabled = True
    
    if core_dump_disabled:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Configuration Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10450)}: Kernel core dumps disabled (CAT II)",
            details="Core dumps are restricted",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Configuration Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10450)}: Kernel core dumps not disabled (CAT II)",
            details="Core dumps must be disabled",
            remediation="echo '* hard core 0' >> /etc/security/limits.conf && echo 'fs.suid_dumpable = 0' >> /etc/sysctl.conf && sysctl -p"
        ))
    
    # RHEL-08-010460: System must disable prelinking (CAT II)
    if not check_package_installed("prelink"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Configuration Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10460)}: Prelinking not installed (CAT II)",
            details="prelink package is not present",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Configuration Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10460)}: Prelinking is installed (CAT II)",
            details="prelink must be removed",
            remediation="sudo prelink -ua && sudo apt-get remove prelink || sudo yum remove prelink"
        ))
    
    # RHEL-08-010470: Address Space Layout Randomization (ASLR) must be enabled (CAT II)
    found, value = check_kernel_parameter("kernel.randomize_va_space")
    
    if found and value == "2":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Configuration Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10470)}: ASLR is fully enabled (CAT II)",
            details="Full address space randomization active",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Configuration Management",
            status="Fail",
            message=f"{get_stig_id('RHEL-08', 10470)}: ASLR not fully enabled (CAT II)",
            details="kernel.randomize_va_space must be set to 2",
            remediation="echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.conf && sysctl -p"
        ))
    
    # RHEL-08-010480: YUM/DNF must remove all software components after updated versions installed (CAT II)
    if command_exists("yum") or command_exists("dnf"):
        yum_conf = read_file_safe("/etc/yum.conf")
        dnf_conf = read_file_safe("/etc/dnf/dnf.conf")
        
        clean_configured = False
        
        if "clean_requirements_on_remove=1" in yum_conf or "clean_requirements_on_remove=True" in yum_conf:
            clean_configured = True
        if "clean_requirements_on_remove=1" in dnf_conf or "clean_requirements_on_remove=True" in dnf_conf:
            clean_configured = True
        
        if clean_configured:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Configuration Management",
                status="Pass",
                message=f"{get_stig_id('RHEL-08', 10480)}: Package cleanup configured (CAT II)",
                details="YUM/DNF will remove old software components",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="STIG - Configuration Management",
                status="Fail",
                message=f"{get_stig_id('RHEL-08', 10480)}: Package cleanup not configured (CAT II)",
                details="Configure automatic removal of superseded packages",
                remediation="Add to /etc/yum.conf or /etc/dnf/dnf.conf: clean_requirements_on_remove=1"
            ))
    
    # RHEL-08-010490: System must be configured to boot into multi-user target (CAT II)
    default_target = run_command("systemctl get-default 2>/dev/null").stdout.strip()
    
    if default_target in ["multi-user.target", "graphical.target"]:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Configuration Management",
            status="Pass",
            message=f"{get_stig_id('RHEL-08', 10490)}: System boot target configured (CAT II)",
            details=f"Default target: {default_target}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Configuration Management",
            status="Info",
            message=f"{get_stig_id('RHEL-08', 10490)}: Verify boot target (CAT II)",
            details=f"Current target: {default_target}",
            remediation="Set target: sudo systemctl set-default multi-user.target"
        ))
    
    # Additional checks for overall system hardening
    # Check for unnecessary services
    unnecessary_services = [
        "avahi-daemon",
        "cups",
        "dhcpd",
        "named",
        "vsftpd",
        "httpd",
        "dovecot",
        "smb",
        "squid",
        "snmpd"
    ]
    
    running_unnecessary = []
    for service in unnecessary_services:
        if check_service_active(service):
            running_unnecessary.append(service)
    
    if not running_unnecessary:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Configuration Management",
            status="Pass",
            message="STIG Best Practice: Unnecessary services disabled",
            details="No unnecessary network services detected",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Configuration Management",
            status="Info",
            message="STIG Best Practice: Review running services",
            details=f"Services to review: {', '.join(running_unnecessary)}",
            remediation="Disable unnecessary services: sudo systemctl disable SERVICE_NAME"
        ))

# ============================================================================
# Main Module Entry Point
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """
    Main entry point for DISA STIG module
    
    Args:
        shared_data: Dictionary with shared data from main script
        
    Returns:
        List of AuditResult objects
    """
    results = []
    
    print(f"\n[{MODULE_NAME}] Starting DISA STIG compliance checks...")
    print(f"[{MODULE_NAME}] Standards: RHEL 8/9 STIG, Ubuntu 20.04 STIG, General OS STIG")
    print(f"[{MODULE_NAME}] Severity Levels: CAT I (High), CAT II (Medium), CAT III (Low)")
    
    is_root = shared_data.get("is_root", False)
    if not is_root:
        print(f"[{MODULE_NAME}] Note: Some checks require root privileges for complete results")
    
    try:
        # Account Management Controls
        check_account_management(results, shared_data)
        
        # Audit and Accountability
        check_audit_and_accountability(results, shared_data)
        
        # Identification and Authentication
        check_identification_authentication(results, shared_data)
        
        # System and Communications Protection
        check_system_communications_protection(results, shared_data)
        
        # System and Information Integrity
        check_system_information_integrity(results, shared_data)
        
        # Configuration Management
        check_configuration_management(results, shared_data)
        
    except Exception as e:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="STIG - Error",
            status="Error",
            message=f"Module execution error: {str(e)}"
        ))
        import traceback
        traceback.print_exc()
    
    # Summary of findings by category
    cat_i_fail = sum(1 for r in results if "CAT I" in r.message and r.status == "Fail")
    cat_ii_fail = sum(1 for r in results if "CAT II" in r.message and r.status == "Fail")
    cat_iii_fail = sum(1 for r in results if "CAT III" in r.message and r.status == "Fail")
    
    summary_details = f"CAT I failures: {cat_i_fail}, CAT II failures: {cat_ii_fail}, CAT III failures: {cat_iii_fail}"
    
    print(f"[{MODULE_NAME}] DISA STIG checks completed - {len(results)} checks performed")
    print(f"[{MODULE_NAME}] Severity summary: {summary_details}")
    
    return results

# ============================================================================
# Module Testing
# ============================================================================

if __name__ == "__main__":
    """Allow module to be run standalone for testing"""
    import socket
    import platform
    import datetime
    
    print(f"Testing {MODULE_NAME} module...")
    print("=" * 60)
    
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
    print("=" * 60)
    
    test_results = run_checks(test_shared_data)
    
    print(f"\n{'=' * 60}")
    print(f"Generated {len(test_results)} results")
    print("=" * 60)
    
    status_counts = {}
    for result in test_results:
        status_counts[result.status] = status_counts.get(result.status, 0) + 1
    
    print("\nSummary by Status:")
    for status in ["Pass", "Fail", "Warning", "Info", "Error"]:
        count = status_counts.get(status, 0)
        if count > 0:
            print(f"  {status}: {count}")
    
    # Count by severity
    cat_i_total = sum(1 for r in test_results if "CAT I" in r.message)
    cat_ii_total = sum(1 for r in test_results if "CAT II" in r.message)
    cat_iii_total = sum(1 for r in test_results if "CAT III" in r.message)
    
    cat_i_fail = sum(1 for r in test_results if "CAT I" in r.message and r.status == "Fail")
    cat_ii_fail = sum(1 for r in test_results if "CAT II" in r.message and r.status == "Fail")
    cat_iii_fail = sum(1 for r in test_results if "CAT III" in r.message and r.status == "Fail")
    
    if cat_i_total > 0 or cat_ii_total > 0 or cat_iii_total > 0:
        print("\nSummary by STIG Category:")
        if cat_i_total > 0:
            print(f"  CAT I (High): {cat_i_total} checks, {cat_i_fail} failures")
        if cat_ii_total > 0:
            print(f"  CAT II (Medium): {cat_ii_total} checks, {cat_ii_fail} failures")
        if cat_iii_total > 0:
            print(f"  CAT III (Low): {cat_iii_total} checks, {cat_iii_fail} failures")
    
    print("\n" + "=" * 60)
    print("STIG module test complete")
    print("=" * 60)
