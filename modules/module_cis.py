#!/usr/bin/env python3
"""
module_cis.py
CIS Benchmark Module for Linux
Version: 1.0

SYNOPSIS:
    CIS (Center for Internet Security) Benchmark compliance checks for Linux systems.

DESCRIPTION:
    This module performs comprehensive CIS Benchmark checks including:
    
    Section 1 - Initial Setup:
    - Filesystem configuration and partitioning
    - Software updates and package management
    - Filesystem integrity checking
    - Secure boot settings
    - Additional process hardening
    - Mandatory access controls
    - Warning banners
    
    Section 2 - Services:
    - Service clients (NIS, rsh, talk, telnet, LDAP, RPC)
    - Time synchronization
    - Special purpose services (X11, printing, DHCP, DNS, FTP, HTTP, email, Samba, HTTP Proxy, SNMP)
    
    Section 3 - Network Configuration:
    - Network parameters (host and router)
    - IPv6 configuration
    - TCP Wrappers
    - Uncommon network protocols
    - Firewall configuration
    
    Section 4 - Logging and Auditing:
    - System accounting (auditd)
    - Configure logging (rsyslog/journald)
    
    Section 5 - Access, Authentication and Authorization:
    - Configure cron
    - SSH Server Configuration
    - Configure PAM
    - User Accounts and Environment
    - User Shell Timeout
    
    Section 6 - System Maintenance:
    - System File Permissions
    - User and Group Settings
    
    Based on CIS Benchmarks:
    - CIS Ubuntu Linux 20.04/22.04 LTS Benchmark v2.0
    - CIS Red Hat Enterprise Linux 8/9 Benchmark v3.0
    - CIS Debian Linux 11/12 Benchmark v2.0

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

NOTES:
    Version: 1.0
    Reference: https://www.cisecurity.org/benchmark/linux
    Scoring: Level 1 (basic security) and Level 2 (defense in depth)
"""

import os
import sys
import re
import subprocess
import glob
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

sys.path.insert(0, str(Path(__file__).parent.parent))
from linux_security_audit import AuditResult

MODULE_NAME = "CIS"

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

def check_mount_option(mount_point: str, option: str) -> bool:
    """Check if a mount point has a specific option"""
    result = run_command(f"findmnt -n {mount_point} 2>/dev/null")
    if result.returncode == 0:
        return option in result.stdout
    return False

def check_kernel_parameter(parameter: str) -> Tuple[bool, str]:
    """Check kernel parameter value"""
    result = run_command(f"sysctl {parameter} 2>/dev/null")
    if result.returncode == 0:
        match = re.search(r'=\s*(.+)', result.stdout)
        if match:
            return True, match.group(1).strip()
    return False, ""

# ============================================================================
# Section 1: Initial Setup
# ============================================================================

def check_filesystem_configuration(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 1.1 - Filesystem Configuration
    Check filesystem mount options and separate partitions
    """
    print(f"[{MODULE_NAME}] Checking filesystem configuration...")
    
    # 1.1.1.x - Disable unused filesystems
    unused_filesystems = [
        ("cramfs", "1.1.1.1"),
        ("freevxfs", "1.1.1.2"),
        ("jffs2", "1.1.1.3"),
        ("hfs", "1.1.1.4"),
        ("hfsplus", "1.1.1.5"),
        ("udf", "1.1.1.6")
    ]
    
    for fs_name, cis_id in unused_filesystems:
        lsmod_check = run_command(f"lsmod | grep {fs_name}")
        modprobe_check = run_command(f"modprobe -n -v {fs_name} 2>&1 | grep -E '(install /bin/(true|false)|not found)'")
        
        if lsmod_check.returncode != 0 and "install /bin/true" in modprobe_check.stdout:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Filesystem",
                status="Pass",
                message=f"CIS {cis_id}: {fs_name} filesystem is disabled",
                details=f"Unused filesystem {fs_name} is properly disabled"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Filesystem",
                status="Fail",
                message=f"CIS {cis_id}: {fs_name} filesystem is not disabled",
                details=f"Filesystem {fs_name} should be disabled if not needed",
                remediation=f"echo 'install {fs_name} /bin/true' | sudo tee -a /etc/modprobe.d/{fs_name}.conf"
            ))
    
    # 1.1.2-1.1.5 - Separate partitions for critical directories
    critical_partitions = [
        ("/tmp", "1.1.2", True),
        ("/var", "1.1.6", True),
        ("/var/tmp", "1.1.7", True),
        ("/var/log", "1.1.11", True),
        ("/var/log/audit", "1.1.12", True),
        ("/home", "1.1.13", True)
    ]
    
    for mount_point, cis_id, required in critical_partitions:
        result = run_command(f"findmnt -n {mount_point}")
        if result.returncode == 0:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Filesystem",
                status="Pass",
                message=f"CIS {cis_id}: Separate partition exists for {mount_point}",
                details=f"Directory {mount_point} is on a separate partition"
            ))
        else:
            status = "Fail" if required else "Warning"
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Filesystem",
                status=status,
                message=f"CIS {cis_id}: No separate partition for {mount_point}",
                details=f"Consider creating a separate partition for {mount_point}",
                remediation="Requires repartitioning - plan during system rebuild"
            ))
    
    # 1.1.3-1.1.5 - /tmp mount options
    tmp_options = [
        ("nodev", "1.1.3", "/tmp"),
        ("nosuid", "1.1.4", "/tmp"),
        ("noexec", "1.1.5", "/tmp"),
        ("nodev", "1.1.8", "/var/tmp"),
        ("nosuid", "1.1.9", "/var/tmp"),
        ("noexec", "1.1.10", "/var/tmp")
    ]
    
    for option, cis_id, mount_point in tmp_options:
        if check_mount_option(mount_point, option):
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Filesystem",
                status="Pass",
                message=f"CIS {cis_id}: {mount_point} mounted with {option} option",
                details=f"Mount option {option} provides security for {mount_point}"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Filesystem",
                status="Fail",
                message=f"CIS {cis_id}: {mount_point} not mounted with {option}",
                details=f"Add {option} option to {mount_point} in /etc/fstab",
                remediation=f"Edit /etc/fstab and add {option} to {mount_point} mount options, then: sudo mount -o remount {mount_point}"
            ))

def check_software_updates(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 1.2 - Configure Software Updates
    """
    print(f"[{MODULE_NAME}] Checking software updates configuration...")
    
    # 1.2.1 - Ensure package manager repositories are configured
    if command_exists("apt"):
        sources_result = run_command("apt-cache policy 2>/dev/null")
        if "release" in sources_result.stdout.lower():
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Software Updates",
                status="Pass",
                message="CIS 1.2.1: Package repositories are configured (apt)",
                details="APT repositories are properly configured"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Software Updates",
                status="Fail",
                message="CIS 1.2.1: Package repositories not properly configured",
                details="Check /etc/apt/sources.list and /etc/apt/sources.list.d/",
                remediation="Configure proper APT repositories in /etc/apt/sources.list"
            ))
    
    elif command_exists("yum") or command_exists("dnf"):
        pkg_manager = "dnf" if command_exists("dnf") else "yum"
        repos_result = run_command(f"{pkg_manager} repolist 2>/dev/null")
        if "repo" in repos_result.stdout.lower():
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Software Updates",
                status="Pass",
                message=f"CIS 1.2.1: Package repositories are configured ({pkg_manager})",
                details="YUM/DNF repositories are properly configured"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Software Updates",
                status="Fail",
                message="CIS 1.2.1: Package repositories not properly configured",
                details="Check /etc/yum.repos.d/",
                remediation="Configure proper YUM/DNF repositories in /etc/yum.repos.d/"
            ))
    
    # 1.2.2 - Ensure GPG keys are configured
    if command_exists("apt"):
        keys_result = run_command("apt-key list 2>/dev/null || ls -la /etc/apt/trusted.gpg.d/ 2>/dev/null")
        if keys_result.returncode == 0 and keys_result.stdout.strip():
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Software Updates",
                status="Pass",
                message="CIS 1.2.2: GPG keys are configured",
                details="Package signing keys are present"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Software Updates",
                status="Warning",
                message="CIS 1.2.2: GPG keys may not be configured",
                details="Verify package signing keys are installed",
                remediation="Import required GPG keys for your repositories"
            ))

def check_filesystem_integrity(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 1.3 - Filesystem Integrity Checking
    """
    print(f"[{MODULE_NAME}] Checking filesystem integrity tools...")
    
    # 1.3.1 - Ensure AIDE is installed
    if check_package_installed("aide") or check_package_installed("aide-common"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Integrity",
            status="Pass",
            message="CIS 1.3.1: AIDE is installed",
            details="Advanced Intrusion Detection Environment (AIDE) is available"
        ))
        
        # 1.3.2 - Ensure filesystem integrity is regularly checked
        cron_check = run_command("crontab -u root -l 2>/dev/null | grep aide || grep -r aide /etc/cron.* /etc/crontab 2>/dev/null")
        if cron_check.returncode == 0:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Integrity",
                status="Pass",
                message="CIS 1.3.2: Filesystem integrity checks are scheduled",
                details="AIDE is configured to run periodically"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Integrity",
                status="Fail",
                message="CIS 1.3.2: Filesystem integrity checks not scheduled",
                details="AIDE should run regularly via cron",
                remediation="echo '0 5 * * * /usr/bin/aide --check' | sudo crontab -"
            ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Integrity",
            status="Fail",
            message="CIS 1.3.1: AIDE is not installed",
            details="AIDE provides filesystem integrity monitoring",
            remediation="sudo apt-get install aide aide-common && sudo aideinit"
        ))

def check_secure_boot_settings(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 1.4 - Secure Boot Settings
    """
    print(f"[{MODULE_NAME}] Checking secure boot settings...")
    
    # 1.4.1 - Ensure bootloader password is set
    if os.path.exists("/boot/grub/grub.cfg"):
        grub_cfg = read_file_safe("/boot/grub/grub.cfg")
        if "password" in grub_cfg:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Boot",
                status="Pass",
                message="CIS 1.4.1: Bootloader password is configured",
                details="GRUB bootloader is password protected"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Boot",
                status="Fail",
                message="CIS 1.4.1: Bootloader password is not set",
                details="Bootloader should be password protected to prevent unauthorized boot parameter changes",
                remediation="Configure GRUB password using grub-mkpasswd-pbkdf2 and update /etc/grub.d/40_custom"
            ))
    
    # 1.4.2 - Ensure permissions on bootloader config are configured
    grub_files = ["/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"]
    for grub_file in grub_files:
        if os.path.exists(grub_file):
            perms = get_file_permissions(grub_file)
            stat_info = os.stat(grub_file)
            
            if perms and perms == "600" and stat_info.st_uid == 0 and stat_info.st_gid == 0:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CIS - Boot",
                    status="Pass",
                    message=f"CIS 1.4.2: Bootloader config {grub_file} has correct permissions",
                    details="File is owned by root:root with 600 permissions"
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CIS - Boot",
                    status="Fail",
                    message=f"CIS 1.4.2: Bootloader config {grub_file} has incorrect permissions",
                    details=f"Current permissions: {perms}, should be 600 owned by root:root",
                    remediation=f"sudo chown root:root {grub_file} && sudo chmod 600 {grub_file}"
                ))

def check_additional_process_hardening(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 1.5 - Additional Process Hardening
    """
    print(f"[{MODULE_NAME}] Checking process hardening settings...")
    
    # 1.5.1 - Ensure core dumps are restricted
    limits_check = run_command("grep -E '^\\s*\\*\\s+hard\\s+core\\s+0' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null")
    sysctl_check = run_command("sysctl fs.suid_dumpable 2>/dev/null")
    
    if limits_check.returncode == 0 and "fs.suid_dumpable = 0" in sysctl_check.stdout:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Hardening",
            status="Pass",
            message="CIS 1.5.1: Core dumps are restricted",
            details="Core dumps are disabled to prevent information disclosure"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Hardening",
            status="Fail",
            message="CIS 1.5.1: Core dumps are not properly restricted",
            details="Core dumps can contain sensitive information",
            remediation="echo '* hard core 0' | sudo tee -a /etc/security/limits.conf && echo 'fs.suid_dumpable = 0' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p"
        ))
    
    # 1.5.2 - Ensure address space layout randomization (ASLR) is enabled
    found, value = check_kernel_parameter("kernel.randomize_va_space")
    if found and value == "2":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Hardening",
            status="Pass",
            message="CIS 1.5.2: ASLR is enabled",
            details="Address Space Layout Randomization provides defense against memory attacks"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Hardening",
            status="Fail",
            message="CIS 1.5.2: ASLR is not enabled",
            details="ASLR should be set to 2 for full randomization",
            remediation="echo 'kernel.randomize_va_space = 2' | sudo tee -a /etc/sysctl.conf && sudo sysctl -p"
        ))
    
    # 1.5.3 - Ensure prelink is disabled
    if check_package_installed("prelink"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Hardening",
            status="Fail",
            message="CIS 1.5.3: prelink is installed",
            details="prelink can interfere with ASLR and should be removed",
            remediation="sudo prelink -ua && sudo apt-get remove prelink || sudo yum remove prelink"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Hardening",
            status="Pass",
            message="CIS 1.5.3: prelink is not installed",
            details="System does not have prelink installed"
        ))

def check_mandatory_access_control(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 1.6 - Mandatory Access Control
    """
    print(f"[{MODULE_NAME}] Checking mandatory access control...")
    
    # Check for SELinux (RHEL-based)
    if command_exists("getenforce"):
        selinux_status = run_command("getenforce").stdout.strip()
        
        # 1.6.1.1 - Ensure SELinux is installed
        if check_package_installed("libselinux"):
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Access Control",
                status="Pass",
                message="CIS 1.6.1.1: SELinux is installed",
                details="SELinux packages are present on the system"
            ))
        
        # 1.6.1.2 - Ensure SELinux is not disabled in bootloader
        grub_check = run_command("grep -E 'kernelopts=.*selinux=0|kernelopts=.*enforcing=0' /boot/grub2/grubenv 2>/dev/null")
        if grub_check.returncode != 0:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Access Control",
                status="Pass",
                message="CIS 1.6.1.2: SELinux is not disabled in bootloader",
                details="SELinux is not disabled via kernel parameters"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Access Control",
                status="Fail",
                message="CIS 1.6.1.2: SELinux is disabled in bootloader",
                details="SELinux should not be disabled in boot parameters",
                remediation="Remove selinux=0 and enforcing=0 from kernel parameters and reboot"
            ))
        
        # 1.6.1.3 - Ensure SELinux policy is configured
        policy_check = run_command("grep '^SELINUXTYPE=' /etc/selinux/config 2>/dev/null")
        if "targeted" in policy_check.stdout or "mls" in policy_check.stdout:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Access Control",
                status="Pass",
                message="CIS 1.6.1.3: SELinux policy is configured",
                details=f"SELinux policy: {policy_check.stdout.strip()}"
            ))
        
        # 1.6.1.4 - Ensure SELinux mode is enforcing
        if selinux_status == "Enforcing":
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Access Control",
                status="Pass",
                message="CIS 1.6.1.4: SELinux is in enforcing mode",
                details="SELinux is actively enforcing security policies"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Access Control",
                status="Fail",
                message=f"CIS 1.6.1.4: SELinux is in {selinux_status} mode",
                details="SELinux should be set to enforcing mode",
                remediation="sudo setenforce 1 && sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config"
            ))
    
    # Check for AppArmor (Debian/Ubuntu)
    elif command_exists("apparmor_status"):
        # 1.6.1.1 - Ensure AppArmor is installed
        if check_package_installed("apparmor"):
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Access Control",
                status="Pass",
                message="CIS 1.6.1.1: AppArmor is installed",
                details="AppArmor packages are present on the system"
            ))
        
        # 1.6.1.2 - Ensure AppArmor is enabled
        aa_status = run_command("apparmor_status 2>/dev/null")
        if "apparmor module is loaded" in aa_status.stdout.lower():
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Access Control",
                status="Pass",
                message="CIS 1.6.1.2: AppArmor is enabled",
                details="AppArmor module is loaded and active"
            ))
            
            # Check for profiles in enforce mode
            if "profiles are in enforce mode" in aa_status.stdout:
                match = re.search(r'(\d+) profiles are in enforce mode', aa_status.stdout)
                if match and int(match.group(1)) > 0:
                    results.append(AuditResult(
                        module=MODULE_NAME,
                        category="CIS - Access Control",
                        status="Pass",
                        message="CIS 1.6.1.3: AppArmor profiles are in enforce mode",
                        details=f"{match.group(1)} profiles are actively enforcing security policies"
                    ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Access Control",
                status="Fail",
                message="CIS 1.6.1.2: AppArmor is not enabled",
                details="AppArmor should be enabled for mandatory access control",
                remediation="sudo systemctl enable apparmor && sudo systemctl start apparmor"
            ))

def check_warning_banners(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 1.7 - Warning Banners
    """
    print(f"[{MODULE_NAME}] Checking warning banners...")
    
    banner_files = [
        ("/etc/motd", "1.7.1", "message of the day"),
        ("/etc/issue", "1.7.2", "local login warning"),
        ("/etc/issue.net", "1.7.3", "remote login warning")
    ]
    
    for banner_file, cis_id, description in banner_files:
        if os.path.exists(banner_file):
            perms = get_file_permissions(banner_file)
            stat_info = os.stat(banner_file)
            content = read_file_safe(banner_file)
            
            # Check permissions
            if perms and int(perms) <= 644 and stat_info.st_uid == 0 and stat_info.st_gid == 0:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CIS - Banners",
                    status="Pass",
                    message=f"CIS {cis_id}: {banner_file} has correct permissions",
                    details=f"Banner file for {description} is properly secured"
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CIS - Banners",
                    status="Fail",
                    message=f"CIS {cis_id}: {banner_file} has incorrect permissions",
                    details=f"Should be 644 or more restrictive, owned by root:root",
                    remediation=f"sudo chown root:root {banner_file} && sudo chmod 644 {banner_file}"
                ))
            
            # Check for inappropriate content (OS/version info)
            inappropriate_patterns = [r'\b(\\[a-z]|\\m|\\r|\\s|\\v)\b']
            has_inappropriate = any(re.search(pattern, content, re.IGNORECASE) for pattern in inappropriate_patterns)
            
            if not has_inappropriate:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CIS - Banners",
                    status="Pass",
                    message=f"CIS {cis_id}: {banner_file} does not contain OS information",
                    details="Banner does not leak system information"
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CIS - Banners",
                    status="Warning",
                    message=f"CIS {cis_id}: {banner_file} may contain OS information",
                    details="Remove escape sequences and OS information from banners",
                    remediation=f"Edit {banner_file} and remove \\m, \\r, \\s, \\v escape sequences"
                ))

# ============================================================================
# Section 2: Services
# ============================================================================

def check_service_clients(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 2.1 - Ensure Service Clients are not installed
    """
    print(f"[{MODULE_NAME}] Checking insecure service clients...")
    
    insecure_clients = [
        ("nis", "2.1.1", "NIS Client"),
        ("rsh-client", "2.1.2", "rsh client"),
        ("talk", "2.1.3", "talk client"),
        ("telnet", "2.1.4", "telnet client"),
        ("ldap-utils", "2.1.5", "LDAP client")
    ]
    
    for package, cis_id, description in insecure_clients:
        if not check_package_installed(package):
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Services",
                status="Pass",
                message=f"CIS {cis_id}: {description} is not installed",
                details=f"Insecure service client {package} is not present"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Services",
                status="Fail",
                message=f"CIS {cis_id}: {description} is installed",
                details=f"Remove insecure client {package}",
                remediation=f"sudo apt-get purge {package} || sudo yum remove {package}"
            ))

def check_time_synchronization(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 2.2 - Time Synchronization
    """
    print(f"[{MODULE_NAME}] Checking time synchronization...")
    
    # Check for systemd-timesyncd, chrony, or ntp
    time_services = [
        ("systemd-timesyncd", "systemd-timesyncd"),
        ("chronyd", "chrony"),
        ("ntpd", "ntp")
    ]
    
    time_sync_found = False
    for service, package in time_services:
        if check_service_enabled(service):
            time_sync_found = True
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Services",
                status="Pass",
                message=f"CIS 2.2.1: Time synchronization is enabled ({service})",
                details=f"Time synchronization service {service} is enabled and running"
            ))
            break
    
    if not time_sync_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Services",
            status="Fail",
            message="CIS 2.2.1: Time synchronization is not enabled",
            details="Enable systemd-timesyncd, chrony, or ntp for time synchronization",
            remediation="sudo systemctl enable --now systemd-timesyncd"
        ))

def check_special_purpose_services(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 2.3 - Ensure Special Purpose Services are not enabled
    """
    print(f"[{MODULE_NAME}] Checking special purpose services...")
    
    special_services = [
        ("autofs", "2.3.1", "Automounter"),
        ("avahi-daemon", "2.3.2", "Avahi Server"),
        ("cups", "2.3.3", "CUPS"),
        ("dhcpd", "2.3.4", "DHCP Server"),
        ("named", "2.3.5", "DNS Server"),
        ("vsftpd", "2.3.6", "FTP Server"),
        ("apache2", "2.3.7", "HTTP Server"),
        ("httpd", "2.3.7", "HTTP Server"),
        ("dovecot", "2.3.8", "IMAP/POP3 Server"),
        ("smbd", "2.3.9", "Samba"),
        ("squid", "2.3.10", "HTTP Proxy"),
        ("snmpd", "2.3.11", "SNMP Server"),
        ("rsync", "2.3.12", "rsync service"),
        ("nis", "2.3.13", "NIS Server")
    ]
    
    for service, cis_id, description in special_services:
        if not check_service_enabled(service):
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Services",
                status="Pass",
                message=f"CIS {cis_id}: {description} is not enabled",
                details=f"Service {service} is not enabled"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Services",
                status="Warning",
                message=f"CIS {cis_id}: {description} is enabled",
                details=f"Verify if {service} is required; disable if not needed",
                remediation=f"sudo systemctl disable --now {service}"
            ))

# ============================================================================
# Section 3: Network Configuration
# ============================================================================

def check_network_parameters(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 3.1-3.2 - Network Parameters
    """
    print(f"[{MODULE_NAME}] Checking network parameters...")
    
    network_params = [
        # Network Parameters (Host Only)
        ("net.ipv4.ip_forward", "0", "3.1.1", "IP forwarding"),
        ("net.ipv4.conf.all.send_redirects", "0", "3.1.2", "Send redirects (all)"),
        ("net.ipv4.conf.default.send_redirects", "0", "3.1.2", "Send redirects (default)"),
        
        # Network Parameters (Host and Router)
        ("net.ipv4.conf.all.accept_source_route", "0", "3.2.1", "Source routed packets (all)"),
        ("net.ipv4.conf.default.accept_source_route", "0", "3.2.1", "Source routed packets (default)"),
        ("net.ipv4.conf.all.accept_redirects", "0", "3.2.2", "ICMP redirects (all)"),
        ("net.ipv4.conf.default.accept_redirects", "0", "3.2.2", "ICMP redirects (default)"),
        ("net.ipv4.conf.all.secure_redirects", "0", "3.2.3", "Secure ICMP redirects (all)"),
        ("net.ipv4.conf.default.secure_redirects", "0", "3.2.3", "Secure ICMP redirects (default)"),
        ("net.ipv4.conf.all.log_martians", "1", "3.2.4", "Log Martians (all)"),
        ("net.ipv4.conf.default.log_martians", "1", "3.2.4", "Log Martians (default)"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1", "3.2.5", "Ignore ICMP broadcasts"),
        ("net.ipv4.icmp_ignore_bogus_error_responses", "1", "3.2.6", "Ignore bogus ICMP errors"),
        ("net.ipv4.conf.all.rp_filter", "1", "3.2.7", "Reverse path filtering (all)"),
        ("net.ipv4.conf.default.rp_filter", "1", "3.2.7", "Reverse path filtering (default)"),
        ("net.ipv4.tcp_syncookies", "1", "3.2.8", "TCP SYN Cookies"),
    ]
    
    for param, expected, cis_id, description in network_params:
        found, value = check_kernel_parameter(param)
        if found and value == expected:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Network",
                status="Pass",
                message=f"CIS {cis_id}: {description} is correctly configured",
                details=f"{param} = {value}"
            ))
        else:
            current = value if found else "not set"
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Network",
                status="Fail",
                message=f"CIS {cis_id}: {description} is not correctly configured",
                details=f"{param} = {current}, should be {expected}",
                remediation=f"echo '{param} = {expected}' | sudo tee -a /etc/sysctl.conf && sudo sysctl -w {param}={expected}"
            ))
    
    # IPv6 parameters
    ipv6_params = [
        ("net.ipv6.conf.all.accept_ra", "0", "3.2.9", "IPv6 router advertisements (all)"),
        ("net.ipv6.conf.default.accept_ra", "0", "3.2.9", "IPv6 router advertisements (default)"),
        ("net.ipv6.conf.all.accept_redirects", "0", "3.2.1", "IPv6 redirects (all)"),
        ("net.ipv6.conf.default.accept_redirects", "0", "3.2.1", "IPv6 redirects (default)"),
    ]
    
    for param, expected, cis_id, description in ipv6_params:
        found, value = check_kernel_parameter(param)
        if found and value == expected:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Network",
                status="Pass",
                message=f"CIS {cis_id}: {description} is correctly configured",
                details=f"{param} = {value}"
            ))
        else:
            current = value if found else "not set"
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Network",
                status="Fail",
                message=f"CIS {cis_id}: {description} is not correctly configured",
                details=f"{param} = {current}, should be {expected}",
                remediation=f"echo '{param} = {expected}' | sudo tee -a /etc/sysctl.conf && sudo sysctl -w {param}={expected}"
            ))

def check_uncommon_network_protocols(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 3.3 - Disable Uncommon Network Protocols
    """
    print(f"[{MODULE_NAME}] Checking uncommon network protocols...")
    
    protocols = [
        ("dccp", "3.3.1"),
        ("sctp", "3.3.2"),
        ("rds", "3.3.3"),
        ("tipc", "3.3.4")
    ]
    
    for protocol, cis_id in protocols:
        lsmod_check = run_command(f"lsmod | grep {protocol}")
        modprobe_check = run_command(f"modprobe -n -v {protocol} 2>&1 | grep -E '(install /bin/(true|false)|not found)'")
        
        if lsmod_check.returncode != 0 and ("install /bin/true" in modprobe_check.stdout or "not found" in modprobe_check.stdout):
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Network",
                status="Pass",
                message=f"CIS {cis_id}: {protocol.upper()} protocol is disabled",
                details=f"Uncommon protocol {protocol} is properly disabled"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Network",
                status="Fail",
                message=f"CIS {cis_id}: {protocol.upper()} protocol is not disabled",
                details=f"Disable uncommon protocol {protocol} if not needed",
                remediation=f"echo 'install {protocol} /bin/true' | sudo tee -a /etc/modprobe.d/{protocol}.conf"
            ))

def check_firewall_configuration(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 3.4 - Firewall Configuration
    """
    print(f"[{MODULE_NAME}] Checking firewall configuration...")
    
    # Check for firewall (ufw, firewalld, or iptables)
    firewall_found = False
    
    # Check UFW (Ubuntu/Debian)
    if command_exists("ufw"):
        ufw_status = run_command("ufw status")
        if "Status: active" in ufw_status.stdout:
            firewall_found = True
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Firewall",
                status="Pass",
                message="CIS 3.4.1: UFW firewall is enabled",
                details="Host-based firewall is active and configured"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Firewall",
                status="Fail",
                message="CIS 3.4.1: UFW firewall is not enabled",
                details="Enable UFW firewall for network protection",
                remediation="sudo ufw enable"
            ))
    
    # Check firewalld (RHEL/CentOS)
    elif check_service_enabled("firewalld"):
        firewall_found = True
        if check_service_active("firewalld"):
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Firewall",
                status="Pass",
                message="CIS 3.4.1: firewalld is enabled and active",
                details="Host-based firewall is running"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Firewall",
                status="Fail",
                message="CIS 3.4.1: firewalld is not active",
                details="Start firewalld service",
                remediation="sudo systemctl enable --now firewalld"
            ))
    
    # Check for iptables rules
    if not firewall_found:
        iptables_check = run_command("iptables -L -n")
        if iptables_check.returncode == 0 and len(iptables_check.stdout.split('\n')) > 8:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Firewall",
                status="Pass",
                message="CIS 3.4.1: iptables rules are configured",
                details="Firewall rules are present"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Firewall",
                status="Fail",
                message="CIS 3.4.1: No firewall detected",
                details="Install and configure a firewall (ufw, firewalld, or iptables)",
                remediation="sudo apt-get install ufw && sudo ufw enable"
            ))

# ============================================================================
# Section 4: Logging and Auditing
# ============================================================================

def check_system_accounting(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 4.1 - Configure System Accounting (auditd)
    """
    print(f"[{MODULE_NAME}] Checking system accounting (auditd)...")
    
    # 4.1.1.1 - Ensure auditd is installed
    if check_package_installed("auditd") or check_package_installed("audit"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Auditing",
            status="Pass",
            message="CIS 4.1.1.1: auditd is installed",
            details="System auditing package is present"
        ))
        
        # 4.1.1.2 - Ensure auditd service is enabled
        if check_service_enabled("auditd"):
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Auditing",
                status="Pass",
                message="CIS 4.1.1.2: auditd service is enabled",
                details="System auditing will start on boot"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Auditing",
                status="Fail",
                message="CIS 4.1.1.2: auditd service is not enabled",
                details="Enable auditd to ensure audit logging persists across reboots",
                remediation="sudo systemctl enable auditd"
            ))
        
        # 4.1.1.3 - Ensure auditing for processes that start prior to auditd is enabled
        grub_check = run_command("grep -E 'kernelopts=.*audit=1' /boot/grub2/grubenv /etc/default/grub 2>/dev/null")
        if grub_check.returncode == 0:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Auditing",
                status="Pass",
                message="CIS 4.1.1.3: Audit enabled for processes prior to auditd",
                details="Kernel parameter audit=1 is set"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Auditing",
                status="Fail",
                message="CIS 4.1.1.3: Audit not enabled for early boot processes",
                details="Add audit=1 to kernel parameters",
                remediation="Add 'audit=1' to GRUB_CMDLINE_LINUX in /etc/default/grub and run sudo update-grub"
            ))
        
        # 4.1.1.4 - Ensure audit_backlog_limit is sufficient
        backlog_check = run_command("grep -E 'kernelopts=.*audit_backlog_limit=([0-9]+)' /boot/grub2/grubenv /etc/default/grub 2>/dev/null")
        if backlog_check.returncode == 0:
            match = re.search(r'audit_backlog_limit=(\d+)', backlog_check.stdout)
            if match and int(match.group(1)) >= 8192:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CIS - Auditing",
                    status="Pass",
                    message="CIS 4.1.1.4: audit_backlog_limit is sufficient",
                    details=f"Backlog limit set to {match.group(1)}"
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CIS - Auditing",
                    status="Warning",
                    message="CIS 4.1.1.4: audit_backlog_limit may be insufficient",
                    details="Consider setting to 8192 or higher",
                    remediation="Add 'audit_backlog_limit=8192' to GRUB_CMDLINE_LINUX in /etc/default/grub"
                ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Auditing",
            status="Fail",
            message="CIS 4.1.1.1: auditd is not installed",
            details="Install auditd for system activity auditing",
            remediation="sudo apt-get install auditd audispd-plugins || sudo yum install audit"
        ))

def check_logging_configuration(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 4.2 - Configure Logging
    """
    print(f"[{MODULE_NAME}] Checking logging configuration...")
    
    # Check for rsyslog or journald
    if check_package_installed("rsyslog"):
        # 4.2.1.1 - Ensure rsyslog is installed
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Logging",
            status="Pass",
            message="CIS 4.2.1.1: rsyslog is installed",
            details="System logging package is present"
        ))
        
        # 4.2.1.2 - Ensure rsyslog Service is enabled
        if check_service_enabled("rsyslog"):
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Logging",
                status="Pass",
                message="CIS 4.2.1.2: rsyslog service is enabled",
                details="System logging will start on boot"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Logging",
                status="Fail",
                message="CIS 4.2.1.2: rsyslog service is not enabled",
                details="Enable rsyslog for system logging",
                remediation="sudo systemctl enable rsyslog"
            ))
        
        # 4.2.1.3 - Ensure rsyslog default file permissions configured
        rsyslog_conf = read_file_safe("/etc/rsyslog.conf")
        if "$FileCreateMode 0640" in rsyslog_conf:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Logging",
                status="Pass",
                message="CIS 4.2.1.3: rsyslog file permissions are configured",
                details="Log files will be created with secure permissions"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Logging",
                status="Fail",
                message="CIS 4.2.1.3: rsyslog file permissions not configured",
                details="Configure default log file permissions",
                remediation="echo '$FileCreateMode 0640' | sudo tee -a /etc/rsyslog.conf && sudo systemctl restart rsyslog"
            ))
    
    # Check journald configuration
    if os.path.exists("/etc/systemd/journald.conf"):
        journald_conf = read_file_safe("/etc/systemd/journald.conf")
        
        # Check for persistent storage
        if "Storage=persistent" in journald_conf:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Logging",
                status="Pass",
                message="CIS 4.2.2.1: journald is configured for persistent storage",
                details="Journal logs will persist across reboots"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Logging",
                status="Warning",
                message="CIS 4.2.2.1: journald persistent storage not configured",
                details="Configure journald for persistent storage",
                remediation="sudo sed -i 's/^#Storage=.*/Storage=persistent/' /etc/systemd/journald.conf && sudo systemctl restart systemd-journald"
            ))

# ============================================================================
# Section 5: Access, Authentication and Authorization
# ============================================================================

def check_cron_configuration(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 5.1 - Configure cron
    """
    print(f"[{MODULE_NAME}] Checking cron configuration...")
    
    # 5.1.1 - Ensure cron daemon is enabled
    cron_services = ["cron", "crond"]
    cron_enabled = False
    
    for service in cron_services:
        if check_service_enabled(service):
            cron_enabled = True
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - Cron",
                status="Pass",
                message=f"CIS 5.1.1: cron daemon ({service}) is enabled",
                details="Scheduled tasks service is enabled"
            ))
            break
    
    if not cron_enabled:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Cron",
            status="Fail",
            message="CIS 5.1.1: cron daemon is not enabled",
            details="Enable cron for scheduled tasks",
            remediation="sudo systemctl enable cron || sudo systemctl enable crond"
        ))
    
    # 5.1.2-5.1.8 - Check cron file permissions
    cron_files = [
        ("/etc/crontab", "5.1.2", "600"),
        ("/etc/cron.hourly", "5.1.3", "700"),
        ("/etc/cron.daily", "5.1.4", "700"),
        ("/etc/cron.weekly", "5.1.5", "700"),
        ("/etc/cron.monthly", "5.1.6", "700"),
        ("/etc/cron.d", "5.1.7", "700")
    ]
    
    for path, cis_id, expected_perms in cron_files:
        if os.path.exists(path):
            perms = get_file_permissions(path)
            stat_info = os.stat(path)
            
            if perms and perms <= expected_perms and stat_info.st_uid == 0 and stat_info.st_gid == 0:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CIS - Cron",
                    status="Pass",
                    message=f"CIS {cis_id}: {path} has correct permissions",
                    details=f"Permissions: {perms}, owned by root:root"
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CIS - Cron",
                    status="Fail",
                    message=f"CIS {cis_id}: {path} has incorrect permissions",
                    details=f"Should be {expected_perms} or more restrictive, owned by root:root",
                    remediation=f"sudo chown root:root {path} && sudo chmod {expected_perms} {path}"
                ))
    
    # 5.1.8 - Ensure at/cron is restricted to authorized users
    if os.path.exists("/etc/cron.deny") or os.path.exists("/etc/at.deny"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Cron",
            status="Fail",
            message="CIS 5.1.8: cron/at deny files exist",
            details="Remove deny files and use allow files instead",
            remediation="sudo rm /etc/cron.deny /etc/at.deny && sudo touch /etc/cron.allow /etc/at.allow && sudo chmod 600 /etc/cron.allow /etc/at.allow && sudo chown root:root /etc/cron.allow /etc/at.allow"
        ))
    elif os.path.exists("/etc/cron.allow") and os.path.exists("/etc/at.allow"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Cron",
            status="Pass",
            message="CIS 5.1.8: cron/at access is restricted via allow files",
            details="Using allow files for cron/at access control"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Cron",
            status="Warning",
            message="CIS 5.1.8: cron/at access control not configured",
            details="Configure cron.allow and at.allow files",
            remediation="sudo touch /etc/cron.allow /etc/at.allow && sudo chmod 600 /etc/cron.allow /etc/at.allow && sudo chown root:root /etc/cron.allow /etc/at.allow"
        ))

def check_ssh_configuration(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 5.2 - SSH Server Configuration (comprehensive)
    """
    print(f"[{MODULE_NAME}] Checking SSH server configuration...")
    
    sshd_config_path = "/etc/ssh/sshd_config"
    if not os.path.exists(sshd_config_path):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - SSH",
            status="Info",
            message="SSH configuration file not found",
            details=f"{sshd_config_path} does not exist"
        ))
        return
    
    sshd_config = read_file_safe(sshd_config_path)
    
    # SSH configuration checks
    ssh_checks = [
        ("Protocol 2", "5.2.1", "SSH Protocol is set to 2", "Protocol"),
        ("LogLevel (INFO|VERBOSE)", "5.2.2", "SSH LogLevel is appropriate", "LogLevel"),
        ("X11Forwarding no", "5.2.3", "SSH X11Forwarding is disabled", "X11Forwarding"),
        ("MaxAuthTries [1-4]", "5.2.4", "SSH MaxAuthTries is 4 or less", "MaxAuthTries"),
        ("IgnoreRhosts yes", "5.2.5", "SSH IgnoreRhosts is enabled", "IgnoreRhosts"),
        ("HostbasedAuthentication no", "5.2.6", "SSH HostbasedAuthentication is disabled", "HostbasedAuthentication"),
        ("PermitRootLogin no", "5.2.7", "SSH root login is disabled", "PermitRootLogin"),
        ("PermitEmptyPasswords no", "5.2.8", "SSH PermitEmptyPasswords is disabled", "PermitEmptyPasswords"),
        ("PermitUserEnvironment no", "5.2.9", "SSH PermitUserEnvironment is disabled", "PermitUserEnvironment"),
        ("ClientAliveInterval [1-9]\\d+", "5.2.12", "SSH ClientAliveInterval is configured", "ClientAliveInterval"),
        ("ClientAliveCountMax [0-3]", "5.2.13", "SSH ClientAliveCountMax is configured", "ClientAliveCountMax"),
        ("LoginGraceTime 60", "5.2.14", "SSH LoginGraceTime is set to 60 or less", "LoginGraceTime"),
        ("AllowUsers|AllowGroups|DenyUsers|DenyGroups", "5.2.15", "SSH access is limited", "Allow/Deny"),
        ("Banner /etc/issue.net", "5.2.16", "SSH Banner is configured", "Banner"),
    ]
    
    for pattern, cis_id, message, param in ssh_checks:
        regex = rf'^\s*{pattern}\s*'
        match = re.search(regex, sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if match:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - SSH",
                status="Pass",
                message=f"CIS {cis_id}: {message}",
                details=f"SSH {param} is properly configured"
            ))
        else:
            # Get recommended remediation based on parameter
            remediation_map = {
                "Protocol": "echo 'Protocol 2' | sudo tee -a /etc/ssh/sshd_config",
                "LogLevel": "echo 'LogLevel INFO' | sudo tee -a /etc/ssh/sshd_config",
                "X11Forwarding": "sudo sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config",
                "MaxAuthTries": "echo 'MaxAuthTries 4' | sudo tee -a /etc/ssh/sshd_config",
                "PermitRootLogin": "sudo sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                "PermitEmptyPasswords": "echo 'PermitEmptyPasswords no' | sudo tee -a /etc/ssh/sshd_config",
                "ClientAliveInterval": "echo 'ClientAliveInterval 300' | sudo tee -a /etc/ssh/sshd_config",
                "Banner": "echo 'Banner /etc/issue.net' | sudo tee -a /etc/ssh/sshd_config"
            }
            
            remediation = remediation_map.get(param, f"Configure {param} in /etc/ssh/sshd_config")
            remediation += " && sudo systemctl restart sshd"
            
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - SSH",
                status="Fail",
                message=f"CIS {cis_id}: {message.replace('is', 'is NOT')}",
                details=f"Configure SSH {param} according to CIS guidelines",
                remediation=remediation
            ))
    
    # 5.2.10 - Ensure only strong Ciphers are used
    cipher_match = re.search(r'^\s*Ciphers\s+(.+)', sshd_config, re.MULTILINE)
    weak_ciphers = ['3des', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'arcfour', 'blowfish', 'cast128']
    
    if cipher_match:
        ciphers = cipher_match.group(1).strip()
        has_weak = any(weak in ciphers.lower() for weak in weak_ciphers)
        
        if not has_weak:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - SSH",
                status="Pass",
                message="CIS 5.2.10: Only strong SSH ciphers are enabled",
                details="Weak ciphers are not configured"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="CIS - SSH",
                status="Fail",
                message="CIS 5.2.10: Weak SSH ciphers detected",
                details="Remove weak ciphers from SSH configuration",
                remediation="echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' | sudo tee -a /etc/ssh/sshd_config && sudo systemctl restart sshd"
            ))

def check_pam_configuration(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 5.3 - Configure PAM
    """
    print(f"[{MODULE_NAME}] Checking PAM configuration...")
    
    # 5.3.1 - Ensure password creation requirements are configured
    pam_password_files = ["/etc/pam.d/common-password", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
    pwquality_found = False
    
    for pam_file in pam_password_files:
        if os.path.exists(pam_file):
            content = read_file_safe(pam_file)
            if "pam_pwquality.so" in content or "pam_cracklib.so" in content:
                pwquality_found = True
                
                # Check for minimum requirements
                requirements = ['minlen=14', 'dcredit=-1', 'ucredit=-1', 'ocredit=-1', 'lcredit=-1']
                has_requirements = all(req in content for req in requirements)
                
                if has_requirements:
                    results.append(AuditResult(
                        module=MODULE_NAME,
                        category="CIS - PAM",
                        status="Pass",
                        message="CIS 5.3.1: Password requirements are properly configured",
                        details=f"Strong password requirements in {pam_file}"
                    ))
                else:
                    results.append(AuditResult(
                        module=MODULE_NAME,
                        category="CIS - PAM",
                        status="Warning",
                        message="CIS 5.3.1: Password requirements may be weak",
                        details="Review and strengthen password complexity requirements",
                        remediation=f"Edit {pam_file} and configure pam_pwquality.so with: minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1"
                    ))
                break
    
    if not pwquality_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - PAM",
            status="Fail",
            message="CIS 5.3.1: Password quality checking not configured",
            details="Install and configure pam_pwquality",
            remediation="sudo apt-get install libpam-pwquality && configure in PAM"
        ))
    
    # 5.3.2 - Ensure lockout for failed password attempts is configured
    pam_auth_files = ["/etc/pam.d/common-auth", "/etc/pam.d/system-auth", "/etc/pam.d/password-auth"]
    faillock_found = False
    
    for pam_file in pam_auth_files:
        if os.path.exists(pam_file):
            content = read_file_safe(pam_file)
            if "pam_faillock.so" in content or "pam_tally2.so" in content:
                faillock_found = True
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CIS - PAM",
                    status="Pass",
                    message="CIS 5.3.2: Account lockout is configured",
                    details=f"Failed login attempt lockout configured in {pam_file}"
                ))
                break
    
    if not faillock_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - PAM",
            status="Fail",
            message="CIS 5.3.2: Account lockout not configured",
            details="Configure pam_faillock to lock accounts after failed attempts",
            remediation="Configure pam_faillock.so in PAM with deny=5 unlock_time=900"
        ))

# ============================================================================
# Section 6: System Maintenance
# ============================================================================

def check_system_file_permissions(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 6.1 - System File Permissions
    """
    print(f"[{MODULE_NAME}] Checking system file permissions...")
    
    # Critical system files
    critical_files = [
        ("/etc/passwd", "6.1.2", "644"),
        ("/etc/shadow", "6.1.3", "000"),
        ("/etc/group", "6.1.4", "644"),
        ("/etc/gshadow", "6.1.5", "000"),
        ("/etc/passwd-", "6.1.6", "644"),
        ("/etc/shadow-", "6.1.7", "000"),
        ("/etc/group-", "6.1.8", "644"),
        ("/etc/gshadow-", "6.1.9", "000"),
    ]
    
    for path, cis_id, max_perms in critical_files:
        if os.path.exists(path):
            perms = get_file_permissions(path)
            stat_info = os.stat(path)
            
            if perms and perms <= max_perms and stat_info.st_uid == 0:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CIS - File Permissions",
                    status="Pass",
                    message=f"CIS {cis_id}: {path} has correct permissions",
                    details=f"Permissions: {perms}, owned by root"
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="CIS - File Permissions",
                    status="Fail",
                    message=f"CIS {cis_id}: {path} has incorrect permissions",
                    details=f"Should be {max_perms} or more restrictive, owned by root",
                    remediation=f"sudo chmod {max_perms} {path} && sudo chown root:root {path}"
                ))

def check_user_group_settings(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    CIS 6.2 - User and Group Settings
    """
    print(f"[{MODULE_NAME}] Checking user and group settings...")
    
    # 6.2.1 - Ensure accounts in /etc/passwd use shadowed passwords
    passwd_content = read_file_safe("/etc/passwd")
    unshadowed_accounts = []
    
    for line in passwd_content.split('\n'):
        if line and not line.startswith('#'):
            parts = line.split(':')
            if len(parts) >= 2 and parts[1] != 'x':
                unshadowed_accounts.append(parts[0])
    
    if not unshadowed_accounts:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Users",
            status="Pass",
            message="CIS 6.2.1: All accounts use shadowed passwords",
            details="No accounts with passwords in /etc/passwd"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Users",
            status="Fail",
            message="CIS 6.2.1: Accounts with unshadowed passwords found",
            details=f"Accounts: {', '.join(unshadowed_accounts)}",
            remediation="sudo pwck -q && sudo pwconv"
        ))
    
    # 6.2.2 - Ensure no legacy "+" entries exist in /etc/passwd
    if '+:' not in passwd_content:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Users",
            status="Pass",
            message="CIS 6.2.2: No legacy '+' entries in /etc/passwd",
            details="NIS legacy entries not present"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Users",
            status="Fail",
            message="CIS 6.2.2: Legacy '+' entries found in /etc/passwd",
            details="Remove NIS legacy entries",
            remediation="Remove lines containing '+:' from /etc/passwd"
        ))
    
    # 6.2.3 - Ensure root is the only UID 0 account
    uid_zero_accounts = []
    for line in passwd_content.split('\n'):
        if line and not line.startswith('#'):
            parts = line.split(':')
            if len(parts) >= 3 and parts[2] == '0' and parts[0] != 'root':
                uid_zero_accounts.append(parts[0])
    
    if not uid_zero_accounts:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Users",
            status="Pass",
            message="CIS 6.2.3: root is the only UID 0 account",
            details="No other accounts with UID 0"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Users",
            status="Fail",
            message="CIS 6.2.3: Multiple UID 0 accounts found",
            details=f"Accounts with UID 0: {', '.join(uid_zero_accounts)}",
            remediation=f"Review and remove UID 0 from: {', '.join(uid_zero_accounts)}"
        ))
    
    # 6.2.4 - Ensure root PATH Integrity
    root_path = os.environ.get('PATH', '')
    path_issues = []
    
    if root_path.startswith(':') or root_path.endswith(':') or '::' in root_path:
        path_issues.append("Empty directory in PATH")
    
    if '.' in root_path.split(':'):
        path_issues.append("Current directory (.) in PATH")
    
    if not path_issues:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Users",
            status="Pass",
            message="CIS 6.2.4: root PATH integrity verified",
            details="No PATH integrity issues found"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Users",
            status="Fail",
            message="CIS 6.2.4: root PATH integrity issues detected",
            details=f"Issues: {', '.join(path_issues)}",
            remediation="Remove empty directories and current directory from root's PATH"
        ))

# ============================================================================
# Main Module Entry Point
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """
    Main entry point for CIS Benchmark module
    
    Args:
        shared_data: Dictionary with shared data
        
    Returns:
        List of AuditResult objects
    """
    results = []
    
    print(f"\n[{MODULE_NAME}] Starting CIS Benchmark compliance checks...")
    print(f"[{MODULE_NAME}] Note: Some checks require root privileges for complete results")
    
    try:
        # Section 1: Initial Setup
        check_filesystem_configuration(results, shared_data)
        check_software_updates(results, shared_data)
        check_filesystem_integrity(results, shared_data)
        check_secure_boot_settings(results, shared_data)
        check_additional_process_hardening(results, shared_data)
        check_mandatory_access_control(results, shared_data)
        check_warning_banners(results, shared_data)
        
        # Section 2: Services
        check_service_clients(results, shared_data)
        check_time_synchronization(results, shared_data)
        check_special_purpose_services(results, shared_data)
        
        # Section 3: Network Configuration
        check_network_parameters(results, shared_data)
        check_uncommon_network_protocols(results, shared_data)
        check_firewall_configuration(results, shared_data)
        
        # Section 4: Logging and Auditing
        check_system_accounting(results, shared_data)
        check_logging_configuration(results, shared_data)
        
        # Section 5: Access, Authentication and Authorization
        check_cron_configuration(results, shared_data)
        check_ssh_configuration(results, shared_data)
        check_pam_configuration(results, shared_data)
        
        # Section 6: System Maintenance
        check_system_file_permissions(results, shared_data)
        check_user_group_settings(results, shared_data)
        
    except Exception as e:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="CIS - Error",
            status="Error",
            message=f"Module execution error: {str(e)}"
        ))
        import traceback
        traceback.print_exc()
    
    print(f"[{MODULE_NAME}] CIS Benchmark checks completed - {len(results)} checks performed")
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
    
    test_shared_data = {
        "hostname": socket.gethostname(),
        "os_version": f"{platform.system()} {platform.release()}",
        "scan_date": datetime.datetime.now(),
        "is_root": os.geteuid() == 0,
        "script_path": Path(__file__).parent.parent
    }
    
    test_results = run_checks(test_shared_data)
    
    print(f"\nGenerated {len(test_results)} results:")
    status_counts = {}
    for result in test_results:
        status_counts[result.status] = status_counts.get(result.status, 0) + 1
    
    print("\nSummary:")
    for status in ["Pass", "Fail", "Warning", "Info", "Error"]:
        count = status_counts.get(status, 0)
        if count > 0:
            print(f"  {status}: {count}")
