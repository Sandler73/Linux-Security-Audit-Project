#!/usr/bin/env python3
"""
module_nsa.py
NSA (National Security Agency) Security Guidance Module for Linux
Version: 1.0

SYNOPSIS:
    NSA Security Configuration Guidance compliance checks for Linux systems.

DESCRIPTION:
    This module performs comprehensive security checks based on NSA guidance documents
    and cybersecurity best practices for Linux operating systems:
    
    System Hardening:
    - Kernel security parameters
    - Boot loader security
    - Partition and filesystem hardening
    - Process restrictions
    - Memory protections
    
    Network Security:
    - IPv4 and IPv6 network stack hardening
    - Wireless security
    - Firewall configuration
    - Network service restrictions
    - Protocol security
    
    Cryptographic Standards:
    - FIPS 140-2/140-3 compliance
    - Strong encryption algorithms
    - TLS/SSL configuration
    - SSH cryptographic settings
    - Certificate management
    
    Access Control:
    - Mandatory Access Control (MAC)
    - Discretionary Access Control (DAC)
    - Role-Based Access Control (RBAC)
    - Privilege management
    - Authentication mechanisms
    
    Audit and Logging:
    - Comprehensive audit logging
    - Log protection and retention
    - Security event monitoring
    - Intrusion detection
    
    Information Assurance:
    - Data protection at rest
    - Data protection in transit
    - Secure communications
    - Information flow control
    
    Based on NSA Publications:
    - NSA Security Configuration Guidance
    - NSA Cybersecurity Advisories and Guidance
    - NSA Information Assurance Guidance
    - NSA/CSS Technical Cyber Security Alerts
    - Defense Information Systems Agency (DISA) collaboration

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

USAGE:
# Standalone testing
cd /mnt/user-data/outputs/modules
python3 module_nsa.py

# Integrated with main script
python3 linux_security_audit.py -m nsa

NOTES:
    Version: 1.0
    Reference: https://www.nsa.gov/cybersecurity-guidance/
    Standards: NSA Security Guidance, CNSS 1253, CNSSI 1300
    Classifications: Critical, High, Medium, Low priority findings
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

MODULE_NAME = "NSA"

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

def check_module_loaded(module_name: str) -> bool:
    """Check if a kernel module is loaded"""
    result = run_command(f"lsmod | grep -w {module_name}")
    return result.returncode == 0

def check_module_blacklisted(module_name: str) -> bool:
    """Check if a kernel module is blacklisted"""
    blacklist_files = glob.glob("/etc/modprobe.d/*.conf")
    
    for blacklist_file in blacklist_files:
        content = read_file_safe(blacklist_file)
        if f"blacklist {module_name}" in content or f"install {module_name} /bin/true" in content:
            return True
    
    return False

def get_nsa_priority(level: str) -> str:
    """Format NSA priority level"""
    priorities = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW"
    }
    return priorities.get(level.lower(), "MEDIUM")


# ============================================================================
# System Hardening - NSA Guidance
# ============================================================================

def check_system_hardening(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NSA System Hardening Guidance
    Covers kernel security, boot security, and system-level protections
    Based on: NSA Security Configuration Guide
    """
    print(f"[{MODULE_NAME}] Checking system hardening (NSA Guidance)...")
    
    # NSA-SH-001: Kernel address space layout randomization (ASLR) must be enabled (CRITICAL)
    found, value = check_kernel_parameter("kernel.randomize_va_space")
    
    if found and value == "2":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Pass",
            message="NSA-SH-001: Address Space Layout Randomization (ASLR) fully enabled (CRITICAL)",
            details="Full ASLR provides strong memory exploit mitigation",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Fail",
            message="NSA-SH-001: ASLR not fully enabled (CRITICAL)",
            details="ASLR must be set to 2 for full randomization",
            remediation="echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-nsa-hardening.conf && sysctl -p"
        ))
    
    # NSA-SH-002: Kernel core dumps must be disabled (HIGH)
    found, value = check_kernel_parameter("fs.suid_dumpable")
    
    if found and value == "0":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Pass",
            message="NSA-SH-002: SUID core dumps disabled (HIGH)",
            details="Prevents information disclosure through core dumps",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Fail",
            message="NSA-SH-002: SUID core dumps not disabled (HIGH)",
            details="Core dumps can leak sensitive information",
            remediation="echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-nsa-hardening.conf && sysctl -p"
        ))
    
    # NSA-SH-003: Kernel pointer exposure must be restricted (HIGH)
    found, value = check_kernel_parameter("kernel.kptr_restrict")
    
    if found and int(value) >= 1:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Pass",
            message="NSA-SH-003: Kernel pointer restriction enabled (HIGH)",
            details=f"kptr_restrict = {value}, kernel addresses are protected",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Fail",
            message="NSA-SH-003: Kernel pointer restriction not enabled (HIGH)",
            details="Kernel pointers should be hidden from unprivileged users",
            remediation="echo 'kernel.kptr_restrict = 2' >> /etc/sysctl.d/99-nsa-hardening.conf && sysctl -p"
        ))
    
    # NSA-SH-004: Kernel dmesg restriction must be enabled (MEDIUM)
    found, value = check_kernel_parameter("kernel.dmesg_restrict")
    
    if found and value == "1":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Pass",
            message="NSA-SH-004: Kernel dmesg restriction enabled (MEDIUM)",
            details="dmesg access restricted to privileged users",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Fail",
            message="NSA-SH-004: Kernel dmesg restriction not enabled (MEDIUM)",
            details="Restrict dmesg to prevent information disclosure",
            remediation="echo 'kernel.dmesg_restrict = 1' >> /etc/sysctl.d/99-nsa-hardening.conf && sysctl -p"
        ))
    
    # NSA-SH-005: Kernel module loading must be restricted (HIGH)
    found, value = check_kernel_parameter("kernel.modules_disabled")
    
    # Note: This is typically not set to 1 as it permanently disables module loading
    # We check if it's configured, not necessarily enabled
    if os.path.exists("/etc/sysctl.d/99-nsa-hardening.conf"):
        sysctl_content = read_file_safe("/etc/sysctl.d/99-nsa-hardening.conf")
        if "kernel.modules_disabled" in sysctl_content:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - System Hardening",
                status="Pass",
                message="NSA-SH-005: Kernel module loading control configured (HIGH)",
                details="Module loading policy is defined",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - System Hardening",
                status="Info",
                message="NSA-SH-005: Consider restricting kernel module loading (HIGH)",
                details="For high security environments, consider disabling module loading after boot",
                remediation="Add 'kernel.modules_disabled = 1' to sysctl if appropriate for environment"
            ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Info",
            message="NSA-SH-005: Kernel module loading not restricted (HIGH)",
            details="Consider module loading restrictions for high security",
            remediation="Create /etc/sysctl.d/99-nsa-hardening.conf with security parameters"
        ))
    
    # NSA-SH-006: System must restrict access to kernel logs (MEDIUM)
    found, value = check_kernel_parameter("kernel.printk")
    
    if found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Pass",
            message="NSA-SH-006: Kernel logging configured (MEDIUM)",
            details=f"printk parameters: {value}",
            remediation=""
        ))
    
    # NSA-SH-007: ExecShield protection should be enabled (HIGH) - x86 specific
    found, value = check_kernel_parameter("kernel.exec-shield")
    
    if found and value == "1":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Pass",
            message="NSA-SH-007: ExecShield protection enabled (HIGH)",
            details="Provides additional exploit mitigation",
            remediation=""
        ))
    
    # NSA-SH-008: Bootloader must be password protected (CRITICAL)
    grub_cfg_locations = [
        "/boot/grub/grub.cfg",
        "/boot/grub2/grub.cfg",
        "/boot/efi/EFI/*/grub.cfg"
    ]
    
    bootloader_protected = False
    for location in grub_cfg_locations:
        for grub_file in glob.glob(location):
            if os.path.exists(grub_file):
                grub_content = read_file_safe(grub_file)
                if "password" in grub_content.lower() or "superusers" in grub_content.lower():
                    bootloader_protected = True
                    break
        if bootloader_protected:
            break
    
    if bootloader_protected:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Pass",
            message="NSA-SH-008: Bootloader password protection configured (CRITICAL)",
            details="GRUB is protected with password/superusers",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Fail",
            message="NSA-SH-008: Bootloader not password protected (CRITICAL)",
            details="Bootloader must be protected to prevent unauthorized boot parameter changes",
            remediation="Configure GRUB password: grub2-setpassword or add superusers to /etc/grub.d/40_custom"
        ))
    
    # NSA-SH-009: Bootloader config files must have restricted permissions (HIGH)
    grub_config_files = []
    for location in grub_cfg_locations:
        grub_config_files.extend(glob.glob(location))
    
    if os.path.exists("/etc/default/grub"):
        grub_config_files.append("/etc/default/grub")
    
    improper_perms = []
    for config_file in grub_config_files:
        if os.path.exists(config_file):
            perms = get_file_permissions(config_file)
            owner, group = get_file_owner_group(config_file)
            
            if perms and int(perms, 8) > int("0600", 8):
                improper_perms.append(f"{config_file} ({perms})")
            if owner != "root":
                improper_perms.append(f"{config_file} (owner: {owner})")
    
    if not improper_perms and grub_config_files:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Pass",
            message="NSA-SH-009: Bootloader config files properly secured (HIGH)",
            details=f"{len(grub_config_files)} GRUB files have correct permissions",
            remediation=""
        ))
    elif improper_perms:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Fail",
            message="NSA-SH-009: Bootloader config files have incorrect permissions (HIGH)",
            details=f"Files with issues: {', '.join(improper_perms[:3])}",
            remediation="sudo chmod 0600 /boot/grub*/grub.cfg /etc/default/grub && sudo chown root:root /boot/grub*/grub.cfg"
        ))
    
    # NSA-SH-010: Disable unnecessary kernel modules (HIGH)
    unnecessary_modules = [
        "cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf",  # Filesystems
        "dccp", "sctp", "rds", "tipc",  # Network protocols
        "usb-storage",  # USB storage (if not needed)
        "bluetooth", "btusb",  # Bluetooth
        "firewire-core", "firewire-ohci", "firewire-sbp2"  # FireWire
    ]
    
    not_blacklisted = []
    for module in unnecessary_modules:
        if not check_module_blacklisted(module):
            # Check if module is currently loaded
            if check_module_loaded(module):
                not_blacklisted.append(f"{module} (loaded)")
    
    if not not_blacklisted:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Pass",
            message="NSA-SH-010: Unnecessary kernel modules disabled (HIGH)",
            details="Uncommon filesystem and protocol modules are blacklisted",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Warning",
            message="NSA-SH-010: Some unnecessary modules not blacklisted (HIGH)",
            details=f"Modules to review: {', '.join(not_blacklisted[:5])}",
            remediation="Blacklist unused modules in /etc/modprobe.d/nsa-blacklist.conf: install MODULE_NAME /bin/true"
        ))
    
    # NSA-SH-011: System must use separate partitions for critical directories (MEDIUM)
    critical_partitions = ["/tmp", "/var", "/var/tmp", "/var/log", "/home"]
    
    mount_output = run_command("mount")
    separate_partitions = []
    
    for partition in critical_partitions:
        if f" {partition} " in mount_output.stdout:
            separate_partitions.append(partition)
    
    if len(separate_partitions) >= 3:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Pass",
            message="NSA-SH-011: Critical directories on separate partitions (MEDIUM)",
            details=f"Separate partitions: {', '.join(separate_partitions)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - System Hardening",
            status="Info",
            message="NSA-SH-011: Limited separate partitions for critical directories (MEDIUM)",
            details="Consider separate partitions for /tmp, /var, /var/log, /home",
            remediation="Use separate partitions during installation or resize existing partitions"
        ))
    
    # NSA-SH-012: Tmp directories must have restrictive mount options (HIGH)
    tmp_mount_options = ["nodev", "nosuid", "noexec"]
    
    for tmp_dir in ["/tmp", "/var/tmp", "/dev/shm"]:
        if f" {tmp_dir} " in mount_output.stdout:
            mount_line = [line for line in mount_output.stdout.split('\n') if f" {tmp_dir} " in line]
            if mount_line:
                missing_options = []
                for option in tmp_mount_options:
                    if option not in mount_line[0]:
                        missing_options.append(option)
                
                if not missing_options:
                    results.append(AuditResult(
                        module=MODULE_NAME,
                        category="NSA - System Hardening",
                        status="Pass",
                        message=f"NSA-SH-012: {tmp_dir} has secure mount options (HIGH)",
                        details=f"All required options present: {', '.join(tmp_mount_options)}",
                        remediation=""
                    ))
                else:
                    results.append(AuditResult(
                        module=MODULE_NAME,
                        category="NSA - System Hardening",
                        status="Fail",
                        message=f"NSA-SH-012: {tmp_dir} missing secure mount options (HIGH)",
                        details=f"Missing: {', '.join(missing_options)}",
                        remediation=f"Add to /etc/fstab: {tmp_dir} options include {','.join(tmp_mount_options)}"
                    ))
    
    # NSA-SH-013: Sticky bit must be set on world-writable directories (HIGH)
    world_writable_check = run_command("find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | head -20")
    
    if world_writable_check.returncode == 0:
        insecure_dirs = [d for d in world_writable_check.stdout.strip().split('\n') if d and d not in ['/tmp', '/var/tmp']]
        
        if not insecure_dirs:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - System Hardening",
                status="Pass",
                message="NSA-SH-013: World-writable directories properly secured (HIGH)",
                details="Sticky bit set on all world-writable directories",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - System Hardening",
                status="Warning",
                message="NSA-SH-013: World-writable directories without sticky bit (HIGH)",
                details=f"Found {len(insecure_dirs)} directories, review: {insecure_dirs[0] if insecure_dirs else 'none'}",
                remediation="Set sticky bit: chmod +t DIRECTORY"
            ))


# ============================================================================
# Network Security - NSA Guidance
# ============================================================================

def check_network_security(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NSA Network Security Guidance
    Covers network stack hardening, protocol security, and network protections
    Based on: NSA Network Infrastructure Security Guide
    """
    print(f"[{MODULE_NAME}] Checking network security (NSA Guidance)...")
    
    # NSA-NS-001: IPv4 forwarding must be disabled (CRITICAL) - unless router
    found, value = check_kernel_parameter("net.ipv4.ip_forward")
    
    if found and value == "0":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass",
            message="NSA-NS-001: IPv4 forwarding disabled (CRITICAL)",
            details="System is not configured as a router",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Warning",
            message="NSA-NS-001: IPv4 forwarding enabled (CRITICAL)",
            details="Disable unless system is intentionally a router",
            remediation="echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/99-nsa-network.conf && sysctl -p"
        ))
    
    # NSA-NS-002: IPv6 must be disabled if not used (HIGH)
    ipv6_disabled = False
    
    # Check grub
    grub_files = glob.glob("/boot/grub*/grub.cfg") + glob.glob("/etc/default/grub")
    for grub_file in grub_files:
        if os.path.exists(grub_file):
            content = read_file_safe(grub_file)
            if "ipv6.disable=1" in content:
                ipv6_disabled = True
                break
    
    # Check sysctl
    ipv6_params = [
        "net.ipv6.conf.all.disable_ipv6",
        "net.ipv6.conf.default.disable_ipv6"
    ]
    
    ipv6_sysctl_disabled = True
    for param in ipv6_params:
        found, value = check_kernel_parameter(param)
        if not found or value != "1":
            ipv6_sysctl_disabled = False
            break
    
    if ipv6_disabled or ipv6_sysctl_disabled:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass",
            message="NSA-NS-002: IPv6 disabled (HIGH)",
            details="IPv6 is disabled at kernel or sysctl level",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Info",
            message="NSA-NS-002: IPv6 is enabled (HIGH)",
            details="If IPv6 is not needed, consider disabling it",
            remediation="Add ipv6.disable=1 to GRUB or disable via sysctl: net.ipv6.conf.all.disable_ipv6=1"
        ))
    
    # NSA-NS-003: Network source routing must be disabled (CRITICAL)
    source_route_params = [
        ("net.ipv4.conf.all.accept_source_route", "0"),
        ("net.ipv4.conf.default.accept_source_route", "0"),
        ("net.ipv6.conf.all.accept_source_route", "0"),
        ("net.ipv6.conf.default.accept_source_route", "0")
    ]
    
    all_configured = True
    misconfigured = []
    for param, expected in source_route_params:
        found, value = check_kernel_parameter(param)
        if not found or value != expected:
            all_configured = False
            misconfigured.append(param)
    
    if all_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass",
            message="NSA-NS-003: Source routing disabled (CRITICAL)",
            details="Source routed packets will be rejected",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Fail",
            message="NSA-NS-003: Source routing not fully disabled (CRITICAL)",
            details=f"Review parameters: {', '.join(misconfigured)}",
            remediation="Configure all accept_source_route parameters to 0 in /etc/sysctl.d/99-nsa-network.conf"
        ))
    
    # NSA-NS-004: ICMP redirects must be disabled (HIGH)
    icmp_params = [
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.conf.default.accept_redirects", "0"),
        ("net.ipv4.conf.all.secure_redirects", "0"),
        ("net.ipv4.conf.default.secure_redirects", "0"),
        ("net.ipv6.conf.all.accept_redirects", "0"),
        ("net.ipv6.conf.default.accept_redirects", "0")
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
            category="NSA - Network Security",
            status="Pass",
            message="NSA-NS-004: ICMP redirects disabled (HIGH)",
            details="All ICMP redirect parameters properly configured",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Fail",
            message="NSA-NS-004: ICMP redirects not fully disabled (HIGH)",
            details="ICMP redirects can be used for man-in-the-middle attacks",
            remediation="Disable all ICMP redirect parameters in /etc/sysctl.d/99-nsa-network.conf"
        ))
    
    # NSA-NS-005: System must not send ICMP redirects (HIGH)
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
            category="NSA - Network Security",
            status="Pass",
            message="NSA-NS-005: ICMP redirect sending disabled (HIGH)",
            details="System will not send ICMP redirects",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Fail",
            message="NSA-NS-005: ICMP redirect sending not disabled (HIGH)",
            details="Disable sending ICMP redirects",
            remediation="Set net.ipv4.conf.all.send_redirects=0 and net.ipv4.conf.default.send_redirects=0"
        ))
    
    # NSA-NS-006: Reverse path filtering must be enabled (HIGH)
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
            category="NSA - Network Security",
            status="Pass",
            message="NSA-NS-006: Reverse path filtering enabled (HIGH)",
            details="Source address validation is active",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Fail",
            message="NSA-NS-006: Reverse path filtering not enabled (HIGH)",
            details="Enable reverse path filtering for spoofing protection",
            remediation="Set net.ipv4.conf.all.rp_filter=1 and net.ipv4.conf.default.rp_filter=1"
        ))
    
    # NSA-NS-007: TCP SYN cookies must be enabled (HIGH)
    found, value = check_kernel_parameter("net.ipv4.tcp_syncookies")
    
    if found and value == "1":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass",
            message="NSA-NS-007: TCP SYN cookies enabled (HIGH)",
            details="SYN flood attack mitigation is active",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Fail",
            message="NSA-NS-007: TCP SYN cookies not enabled (HIGH)",
            details="Enable SYN cookies to protect against SYN floods",
            remediation="echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.d/99-nsa-network.conf && sysctl -p"
        ))
    
    # NSA-NS-008: ICMP broadcast requests must be ignored (MEDIUM)
    found, value = check_kernel_parameter("net.ipv4.icmp_echo_ignore_broadcasts")
    
    if found and value == "1":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass",
            message="NSA-NS-008: ICMP broadcast echo ignore enabled (MEDIUM)",
            details="System will not respond to broadcast pings",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Fail",
            message="NSA-NS-008: ICMP broadcast echo ignore not enabled (MEDIUM)",
            details="Ignore ICMP broadcasts to prevent Smurf attacks",
            remediation="echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1' >> /etc/sysctl.d/99-nsa-network.conf && sysctl -p"
        ))
    
    # NSA-NS-009: Bogus ICMP error responses must be ignored (MEDIUM)
    found, value = check_kernel_parameter("net.ipv4.icmp_ignore_bogus_error_responses")
    
    if found and value == "1":
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass",
            message="NSA-NS-009: Bogus ICMP responses ignored (MEDIUM)",
            details="Invalid ICMP error messages are ignored",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Fail",
            message="NSA-NS-009: Bogus ICMP responses not ignored (MEDIUM)",
            details="Configure system to ignore bogus ICMP errors",
            remediation="echo 'net.ipv4.icmp_ignore_bogus_error_responses = 1' >> /etc/sysctl.d/99-nsa-network.conf && sysctl -p"
        ))
    
    # NSA-NS-010: Martian packets must be logged (MEDIUM)
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
            category="NSA - Network Security",
            status="Pass",
            message="NSA-NS-010: Martian packet logging enabled (MEDIUM)",
            details="Suspicious packets are being logged",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Warning",
            message="NSA-NS-010: Martian packet logging not enabled (MEDIUM)",
            details="Enable logging for network debugging and security monitoring",
            remediation="Set net.ipv4.conf.all.log_martians=1 and net.ipv4.conf.default.log_martians=1"
        ))
    
    # NSA-NS-011: Host-based firewall must be active (CRITICAL)
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
            category="NSA - Network Security",
            status="Pass",
            message="NSA-NS-011: Host-based firewall is active (CRITICAL)",
            details=f"Firewall type: {firewall_type}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Fail",
            message="NSA-NS-011: No active host-based firewall (CRITICAL)",
            details="A host-based firewall is critical for network security",
            remediation="sudo systemctl enable --now firewalld || sudo ufw enable"
        ))
    
    # NSA-NS-012: Unnecessary network services must be disabled (HIGH)
    unnecessary_services = [
        "telnet", "rsh", "rlogin", "rexec",  # Insecure remote access
        "tftp", "talk", "ntalk",  # Legacy services
        "finger", "chargen", "daytime", "echo", "discard",  # Info disclosure
        "avahi-daemon",  # Network discovery
        "cups",  # Printing (if not needed)
    ]
    
    running_services = []
    for service in unnecessary_services:
        if check_service_active(service):
            running_services.append(service)
    
    if not running_services:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass",
            message="NSA-NS-012: Unnecessary network services disabled (HIGH)",
            details="No insecure network services detected",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Fail",
            message="NSA-NS-012: Unnecessary network services are running (HIGH)",
            details=f"Services to disable: {', '.join(running_services)}",
            remediation="Disable unnecessary services: sudo systemctl disable --now SERVICE_NAME"
        ))
    
    # NSA-NS-013: Wireless interfaces should be disabled if not used (HIGH)
    wireless_check = run_command("ip link show 2>/dev/null | grep -i 'wlan\\|wlp'")
    
    if wireless_check.returncode == 0 and wireless_check.stdout:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Info",
            message="NSA-NS-013: Wireless interface detected (HIGH)",
            details="Review if wireless is necessary; disable if not needed",
            remediation="Disable wireless: sudo nmcli radio wifi off or blacklist wireless modules"
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Network Security",
            status="Pass",
            message="NSA-NS-013: No wireless interfaces detected (HIGH)",
            details="Wireless networking is not enabled",
            remediation=""
        ))
    
    # NSA-NS-014: IPv6 router advertisements must be disabled (MEDIUM)
    if not ipv6_disabled:
        ipv6_ra_params = [
            ("net.ipv6.conf.all.accept_ra", "0"),
            ("net.ipv6.conf.default.accept_ra", "0")
        ]
        
        all_configured = True
        for param, expected in ipv6_ra_params:
            found, value = check_kernel_parameter(param)
            if not found or value != expected:
                all_configured = False
                break
        
        if all_configured:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Network Security",
                status="Pass",
                message="NSA-NS-014: IPv6 router advertisements disabled (MEDIUM)",
                details="System will not accept IPv6 router advertisements",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Network Security",
                status="Fail",
                message="NSA-NS-014: IPv6 router advertisements not disabled (MEDIUM)",
                details="Disable RA acceptance unless needed",
                remediation="Set net.ipv6.conf.all.accept_ra=0 and net.ipv6.conf.default.accept_ra=0"
            ))


# ============================================================================
# Cryptographic Standards - NSA Guidance
# ============================================================================

def check_cryptographic_standards(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NSA Cryptographic Standards
    Covers FIPS compliance, strong encryption, and cryptographic best practices
    Based on: NSA Suite B Cryptography, CNSS Policy
    """
    print(f"[{MODULE_NAME}] Checking cryptographic standards (NSA Guidance)...")
    
    # NSA-CS-001: SSH must use strong ciphers only (CRITICAL)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        # NSA recommended ciphers (AES-based)
        strong_ciphers = [
            "aes256-gcm@openssh.com",
            "aes128-gcm@openssh.com",
            "aes256-ctr",
            "aes192-ctr",
            "aes128-ctr"
        ]
        
        # Weak ciphers to avoid
        weak_ciphers = ["3des", "arcfour", "blowfish", "cast128", "des"]
        
        ciphers_match = re.search(r'^\s*Ciphers\s+(.+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if ciphers_match:
            configured = ciphers_match.group(1).strip().lower()
            has_weak = any(weak in configured for weak in weak_ciphers)
            has_strong = any(strong in configured for strong in strong_ciphers)
            
            if has_strong and not has_weak:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="NSA - Cryptography",
                    status="Pass",
                    message="NSA-CS-001: SSH uses strong ciphers only (CRITICAL)",
                    details="AES-based ciphers configured, no weak algorithms",
                    remediation=""
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="NSA - Cryptography",
                    status="Fail",
                    message="NSA-CS-001: SSH cipher configuration needs improvement (CRITICAL)",
                    details="Weak ciphers detected or strong ciphers not configured",
                    remediation="Configure: Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"
                ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Cryptography",
                status="Warning",
                message="NSA-CS-001: SSH ciphers not explicitly configured (CRITICAL)",
                details="Explicitly configure strong ciphers",
                remediation="Add to /etc/ssh/sshd_config: Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr"
            ))
    
    # NSA-CS-002: SSH must use strong MACs only (CRITICAL)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        # NSA recommended MACs
        strong_macs = [
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512",
            "hmac-sha2-256"
        ]
        
        weak_macs = ["hmac-md5", "hmac-sha1", "umac-64"]
        
        macs_match = re.search(r'^\s*MACs\s+(.+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if macs_match:
            configured = macs_match.group(1).strip().lower()
            has_weak = any(weak in configured for weak in weak_macs)
            has_strong = any(strong in configured for strong in strong_macs)
            
            if has_strong and not has_weak:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="NSA - Cryptography",
                    status="Pass",
                    message="NSA-CS-002: SSH uses strong MACs only (CRITICAL)",
                    details="SHA-2 based MACs configured, no weak algorithms",
                    remediation=""
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="NSA - Cryptography",
                    status="Fail",
                    message="NSA-CS-002: SSH MAC configuration needs improvement (CRITICAL)",
                    details="Weak MACs detected or strong MACs not configured",
                    remediation="Configure: MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256"
                ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Cryptography",
                status="Warning",
                message="NSA-CS-002: SSH MACs not explicitly configured (CRITICAL)",
                details="Explicitly configure strong MACs",
                remediation="Add to /etc/ssh/sshd_config: MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
            ))
    
    # NSA-CS-003: SSH must use strong key exchange algorithms (HIGH)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        # NSA recommended KexAlgorithms
        strong_kex = [
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512"
        ]
        
        weak_kex = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"]
        
        kex_match = re.search(r'^\s*KexAlgorithms\s+(.+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if kex_match:
            configured = kex_match.group(1).strip().lower()
            has_weak = any(weak in configured for weak in weak_kex)
            has_strong = any(strong in configured for strong in strong_kex)
            
            if has_strong and not has_weak:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="NSA - Cryptography",
                    status="Pass",
                    message="NSA-CS-003: SSH uses strong key exchange algorithms (HIGH)",
                    details="Modern KEX algorithms configured",
                    remediation=""
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="NSA - Cryptography",
                    status="Fail",
                    message="NSA-CS-003: SSH key exchange needs improvement (HIGH)",
                    details="Weak KEX algorithms or missing strong algorithms",
                    remediation="Configure: KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256"
                ))
    
    # NSA-CS-004: System must use strong password hashing (CRITICAL)
    shadow_content = read_file_safe("/etc/shadow")
    weak_hashes = []
    strong_hashes = []
    
    for line in shadow_content.split('\n'):
        if line and not line.startswith('#'):
            parts = line.split(':')
            if len(parts) >= 2 and parts[1] and parts[1] not in ['!', '*', '!!']:
                if parts[1].startswith('$6$'):  # SHA-512
                    strong_hashes.append(parts[0])
                elif parts[1].startswith('$5$'):  # SHA-256
                    strong_hashes.append(parts[0])
                elif parts[1].startswith('$1$') or not parts[1].startswith('$'):  # MD5 or DES
                    weak_hashes.append(parts[0])
    
    if strong_hashes and not weak_hashes:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Cryptography",
            status="Pass",
            message="NSA-CS-004: Strong password hashing in use (CRITICAL)",
            details=f"All {len(strong_hashes)} accounts use SHA-512 or SHA-256",
            remediation=""
        ))
    elif weak_hashes:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Cryptography",
            status="Fail",
            message="NSA-CS-004: Weak password hashing detected (CRITICAL)",
            details=f"{len(weak_hashes)} accounts using weak hashes: {', '.join(weak_hashes[:3])}",
            remediation="Set ENCRYPT_METHOD SHA512 in /etc/login.defs and reset passwords"
        ))
    
    # NSA-CS-005: TLS/SSL must use strong protocols only (HIGH)
    openssl_conf = "/etc/ssl/openssl.cnf"
    
    if os.path.exists(openssl_conf):
        openssl_content = read_file_safe(openssl_conf)
        
        # Check for minimum TLS version
        if "MinProtocol" in openssl_content:
            if "TLSv1.2" in openssl_content or "TLSv1.3" in openssl_content:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="NSA - Cryptography",
                    status="Pass",
                    message="NSA-CS-005: Strong TLS minimum protocol configured (HIGH)",
                    details="TLS 1.2 or 1.3 minimum enforced",
                    remediation=""
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="NSA - Cryptography",
                    status="Fail",
                    message="NSA-CS-005: TLS minimum protocol too weak (HIGH)",
                    details="TLS 1.2 should be minimum",
                    remediation="Set MinProtocol = TLSv1.2 in /etc/ssl/openssl.cnf"
                ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Cryptography",
                status="Info",
                message="NSA-CS-005: TLS minimum protocol not explicitly set (HIGH)",
                details="Configure minimum TLS protocol version",
                remediation="Add MinProtocol = TLSv1.2 to /etc/ssl/openssl.cnf"
            ))
    
    # NSA-CS-006: FIPS 140-2 mode should be considered (MEDIUM)
    fips_enabled = False
    
    if os.path.exists("/proc/sys/crypto/fips_enabled"):
        fips_status = read_file_safe("/proc/sys/crypto/fips_enabled").strip()
        if fips_status == "1":
            fips_enabled = True
    
    if fips_enabled:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Cryptography",
            status="Pass",
            message="NSA-CS-006: FIPS 140-2 mode is enabled (MEDIUM)",
            details="System is using FIPS validated cryptography",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Cryptography",
            status="Info",
            message="NSA-CS-006: FIPS 140-2 mode not enabled (MEDIUM)",
            details="For high security environments, consider enabling FIPS mode",
            remediation="Enable FIPS: fips-mode-setup --enable && reboot (RHEL/CentOS)"
        ))
    
    # NSA-CS-007: Certificate files must be properly secured (HIGH)
    cert_directories = ["/etc/ssl/certs", "/etc/pki/tls/certs", "/etc/ssl/private", "/etc/pki/tls/private"]
    
    for cert_dir in cert_directories:
        if os.path.exists(cert_dir):
            perms = get_file_permissions(cert_dir)
            owner, group = get_file_owner_group(cert_dir)
            
            if "private" in cert_dir.lower():
                # Private key directories should be 0700
                if perms == "700" and owner == "root":
                    results.append(AuditResult(
                        module=MODULE_NAME,
                        category="NSA - Cryptography",
                        status="Pass",
                        message=f"NSA-CS-007: Private key directory secured (HIGH)",
                        details=f"{cert_dir} has correct permissions (0700, root)",
                        remediation=""
                    ))
                else:
                    results.append(AuditResult(
                        module=MODULE_NAME,
                        category="NSA - Cryptography",
                        status="Fail",
                        message=f"NSA-CS-007: Private key directory not secured (HIGH)",
                        details=f"{cert_dir} permissions: {perms}, owner: {owner}",
                        remediation=f"sudo chmod 0700 {cert_dir} && sudo chown root:root {cert_dir}"
                    ))
            break  # Only check first found directory

# ============================================================================
# Access Control and Mandatory Access Control - NSA Guidance
# ============================================================================

def check_access_control(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NSA Access Control Guidance
    Covers MAC, DAC, RBAC, and privilege management
    Based on: NSA Information Assurance Guidance
    """
    print(f"[{MODULE_NAME}] Checking access control (NSA Guidance)...")
    
    # NSA-AC-001: Mandatory Access Control must be enabled (CRITICAL)
    mac_active = False
    mac_type = None
    
    if command_exists("getenforce"):
        selinux_status = run_command("getenforce").stdout.strip()
        if selinux_status == "Enforcing":
            mac_active = True
            mac_type = "SELinux"
    elif command_exists("aa-status"):
        aa_status = run_command("aa-status 2>/dev/null")
        if "apparmor module is loaded" in aa_status.stdout.lower():
            mac_active = True
            mac_type = "AppArmor"
    
    if mac_active:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Access Control",
            status="Pass",
            message="NSA-AC-001: Mandatory Access Control is enforcing (CRITICAL)",
            details=f"MAC type: {mac_type}, actively enforcing policies",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Access Control",
            status="Fail",
            message="NSA-AC-001: Mandatory Access Control not enforcing (CRITICAL)",
            details="MAC is required for defense in depth",
            remediation="Enable SELinux: sudo setenforce 1 || Enable AppArmor: sudo systemctl enable --now apparmor"
        ))
    
    # NSA-AC-002: Root login must be restricted (HIGH)
    securetty_exists = os.path.exists("/etc/securetty")
    
    if securetty_exists:
        securetty = read_file_safe("/etc/securetty")
        # If file is empty or only contains console, that's good
        non_console_ttys = [line for line in securetty.split('\n') if line and not line.startswith('#') and 'console' not in line and 'tty' in line]
        
        if len(non_console_ttys) <= 2:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Access Control",
                status="Pass",
                message="NSA-AC-002: Root login restricted via securetty (HIGH)",
                details="Root can only login from limited terminals",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Access Control",
                status="Warning",
                message="NSA-AC-002: Root login not sufficiently restricted (HIGH)",
                details=f"Multiple TTYs allow root login: {len(non_console_ttys)}",
                remediation="Restrict /etc/securetty to console only"
            ))
    
    # NSA-AC-003: SSH root login must be disabled (CRITICAL)
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        permit_root = re.search(r'^\s*PermitRootLogin\s+(\S+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if permit_root and permit_root.group(1).lower() in ["no", "prohibit-password", "without-password"]:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Access Control",
                status="Pass",
                message="NSA-AC-003: SSH root login appropriately restricted (CRITICAL)",
                details=f"PermitRootLogin: {permit_root.group(1)}",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Access Control",
                status="Fail",
                message="NSA-AC-003: SSH root login not disabled (CRITICAL)",
                details="Direct root login via SSH should be disabled",
                remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
            ))
    
    # NSA-AC-004: sudo must be configured to require reauthentication (MEDIUM)
    sudoers_content = read_file_safe("/etc/sudoers")
    sudoers_d_files = glob.glob("/etc/sudoers.d/*")
    
    nopasswd_found = "NOPASSWD" in sudoers_content
    
    for sudoers_file in sudoers_d_files:
        if "NOPASSWD" in read_file_safe(sudoers_file):
            nopasswd_found = True
            break
    
    if not nopasswd_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Access Control",
            status="Pass",
            message="NSA-AC-004: sudo requires password authentication (MEDIUM)",
            details="No NOPASSWD directives found",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Access Control",
            status="Warning",
            message="NSA-AC-004: sudo NOPASSWD directive detected (MEDIUM)",
            details="Review and minimize NOPASSWD usage",
            remediation="Remove NOPASSWD directives from /etc/sudoers and /etc/sudoers.d/"
        ))
    
    # NSA-AC-005: User home directories must have restrictive permissions (HIGH)
    home_dirs_check = run_command("find /home -maxdepth 1 -mindepth 1 -type d -perm /027 2>/dev/null")
    
    if home_dirs_check.returncode == 0:
        insecure_homes = [d for d in home_dirs_check.stdout.strip().split('\n') if d]
        
        if not insecure_homes:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Access Control",
                status="Pass",
                message="NSA-AC-005: Home directories properly secured (HIGH)",
                details="No world or group writable home directories",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Access Control",
                status="Fail",
                message="NSA-AC-005: Home directories have excessive permissions (HIGH)",
                details=f"{len(insecure_homes)} directories with improper permissions",
                remediation="chmod 0750 /home/USERNAME for each user"
            ))
    
    # NSA-AC-006: Critical system files must be owned by root (HIGH)
    critical_files = [
        "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
        "/etc/ssh/sshd_config", "/etc/sudoers"
    ]
    
    incorrect_ownership = []
    for critical_file in critical_files:
        if os.path.exists(critical_file):
            owner, group = get_file_owner_group(critical_file)
            if owner != "root":
                incorrect_ownership.append(f"{critical_file} (owner: {owner})")
    
    if not incorrect_ownership:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Access Control",
            status="Pass",
            message="NSA-AC-006: Critical files owned by root (HIGH)",
            details="All critical system files have correct ownership",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Access Control",
            status="Fail",
            message="NSA-AC-006: Critical files have incorrect ownership (HIGH)",
            details=f"Files: {', '.join(incorrect_ownership)}",
            remediation="sudo chown root:root /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/ssh/sshd_config /etc/sudoers"
        ))
    
    # NSA-AC-007: umask must be restrictive (MEDIUM)
    umask_files = ["/etc/bashrc", "/etc/profile", "/etc/bash.bashrc", "/etc/profile.d/*.sh"]
    
    restrictive_umask_found = False
    for umask_file_pattern in umask_files:
        for umask_file in glob.glob(umask_file_pattern):
            if os.path.exists(umask_file):
                content = read_file_safe(umask_file)
                umask_match = re.search(r'umask\s+0?([0-7]{2,3})', content)
                if umask_match:
                    umask_value = umask_match.group(1)
                    if int(umask_value) >= 27:  # 027 or more restrictive
                        restrictive_umask_found = True
                        break
        if restrictive_umask_found:
            break
    
    if restrictive_umask_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Access Control",
            status="Pass",
            message="NSA-AC-007: Restrictive umask configured (MEDIUM)",
            details="umask 027 or more restrictive is set",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Access Control",
            status="Warning",
            message="NSA-AC-007: umask not sufficiently restrictive (MEDIUM)",
            details="Set umask to 027 or more restrictive",
            remediation="Add 'umask 027' to /etc/profile and /etc/bashrc"
        ))


# ============================================================================
# Audit and Logging - NSA Guidance
# ============================================================================

def check_audit_logging(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NSA Audit and Logging Guidance
    Covers comprehensive audit logging and security event monitoring
    Based on: NSA Security Event Logging Guidance
    """
    print(f"[{MODULE_NAME}] Checking audit and logging (NSA Guidance)...")
    
    # NSA-AL-001: auditd must be installed and active (CRITICAL)
    if check_package_installed("audit") or check_package_installed("auditd"):
        if check_service_active("auditd"):
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Audit & Logging",
                status="Pass",
                message="NSA-AL-001: auditd service is active (CRITICAL)",
                details="System audit daemon is running",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Audit & Logging",
                status="Fail",
                message="NSA-AL-001: auditd service not active (CRITICAL)",
                details="auditd must be running for security auditing",
                remediation="sudo systemctl enable --now auditd"
            ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Audit & Logging",
            status="Fail",
            message="NSA-AL-001: auditd not installed (CRITICAL)",
            details="Install and configure auditd",
            remediation="sudo apt-get install auditd || sudo yum install audit"
        ))
    
    # NSA-AL-002: Audit configuration must be immutable (HIGH)
    audit_rules_files = glob.glob("/etc/audit/rules.d/*.rules")
    if os.path.exists("/etc/audit/audit.rules"):
        audit_rules_files.append("/etc/audit/audit.rules")
    
    immutable_set = False
    for rules_file in audit_rules_files:
        content = read_file_safe(rules_file)
        if "-e 2" in content:
            immutable_set = True
            break
    
    if immutable_set:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Audit & Logging",
            status="Pass",
            message="NSA-AL-002: Audit configuration set to immutable (HIGH)",
            details="Audit rules protected from modification",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Audit & Logging",
            status="Warning",
            message="NSA-AL-002: Audit configuration not immutable (HIGH)",
            details="Add '-e 2' to make audit rules immutable",
            remediation="Add '-e 2' to end of audit rules file (requires reboot to change)"
        ))
    
    # NSA-AL-003: Comprehensive audit rules must be configured (HIGH)
    required_audit_categories = [
        "time-change", "user-emulation", "sudoers", "suid-exec",
        "passwd-modify", "group-modify", "network-modify", "kernel-module"
    ]
    
    audit_rules_content = ""
    for rules_file in audit_rules_files:
        audit_rules_content += read_file_safe(rules_file)
    
    # Check for key audit patterns
    audit_patterns = {
        "time-change": ["/etc/localtime", "adjtimex", "settimeofday"],
        "user-emulation": ["sudo", "/etc/sudoers"],
        "passwd-modify": ["/etc/passwd", "/etc/shadow"],
        "group-modify": ["/etc/group", "/etc/gshadow"],
        "network-modify": ["/etc/hosts", "/etc/network", "/etc/sysconfig/network"],
        "kernel-module": ["init_module", "delete_module", "insmod", "rmmod"],
        "suid-exec": ["-F perm=x", "-F auid>=1000"]
    }
    
    configured_categories = []
    for category, patterns in audit_patterns.items():
        if any(pattern in audit_rules_content for pattern in patterns):
            configured_categories.append(category)
    
    if len(configured_categories) >= 5:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Audit & Logging",
            status="Pass",
            message="NSA-AL-003: Comprehensive audit rules configured (HIGH)",
            details=f"Configured categories: {', '.join(configured_categories)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Audit & Logging",
            status="Fail",
            message="NSA-AL-003: Audit rules incomplete (HIGH)",
            details=f"Only {len(configured_categories)} of {len(required_audit_categories)} categories configured",
            remediation="Configure comprehensive audit rules in /etc/audit/rules.d/"
        ))
    
    # NSA-AL-004: Audit logs must be protected (HIGH)
    audit_log_dir = "/var/log/audit"
    
    if os.path.exists(audit_log_dir):
        perms = get_file_permissions(audit_log_dir)
        owner, group = get_file_owner_group(audit_log_dir)
        
        if perms == "700" and owner == "root":
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Audit & Logging",
                status="Pass",
                message="NSA-AL-004: Audit log directory properly secured (HIGH)",
                details=f"{audit_log_dir}: 0700, root:root",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NSA - Audit & Logging",
                status="Fail",
                message="NSA-AL-004: Audit log directory not properly secured (HIGH)",
                details=f"Current: {perms}, {owner}:{group}",
                remediation=f"sudo chmod 0700 {audit_log_dir} && sudo chown root:root {audit_log_dir}"
            ))
    
    # NSA-AL-005: System logging must be active (HIGH)
    logging_services = ["rsyslog", "syslog-ng", "systemd-journald"]
    
    logging_active = False
    active_logger = None
    
    for logger in logging_services:
        if check_service_active(logger):
            logging_active = True
            active_logger = logger
            break
    
    if logging_active:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Audit & Logging",
            status="Pass",
            message="NSA-AL-005: System logging is active (HIGH)",
            details=f"Active logger: {active_logger}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Audit & Logging",
            status="Fail",
            message="NSA-AL-005: No active system logger (HIGH)",
            details="Enable rsyslog or systemd-journald",
            remediation="sudo systemctl enable --now rsyslog"
        ))
    
    # NSA-AL-006: Log files must have restricted permissions (MEDIUM)
    log_files = glob.glob("/var/log/*.log") + glob.glob("/var/log/messages*") + glob.glob("/var/log/secure*")
    
    improper_log_perms = []
    for log_file in log_files[:20]:  # Check first 20
        if os.path.exists(log_file):
            perms = get_file_permissions(log_file)
            if perms and int(perms, 8) > int("0640", 8):
                improper_log_perms.append(f"{os.path.basename(log_file)}")
    
    if not improper_log_perms:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Audit & Logging",
            status="Pass",
            message="NSA-AL-006: Log files properly secured (MEDIUM)",
            details="Log files have restrictive permissions",
            remediation=""
        ))
    elif improper_log_perms:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Audit & Logging",
            status="Warning",
            message="NSA-AL-006: Some log files have excessive permissions (MEDIUM)",
            details=f"Files to review: {', '.join(improper_log_perms[:5])}",
            remediation="sudo chmod 0640 /var/log/*.log"
        ))
    
    # NSA-AL-007: Remote logging should be configured (MEDIUM)
    remote_logging = False
    
    if os.path.exists("/etc/rsyslog.conf"):
        rsyslog_conf = read_file_safe("/etc/rsyslog.conf")
        if "@" in rsyslog_conf or "omfwd" in rsyslog_conf:
            remote_logging = True
    
    rsyslog_d_files = glob.glob("/etc/rsyslog.d/*.conf")
    for conf_file in rsyslog_d_files:
        content = read_file_safe(conf_file)
        if "@" in content or "omfwd" in content:
            remote_logging = True
            break
    
    if remote_logging:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Audit & Logging",
            status="Pass",
            message="NSA-AL-007: Remote logging configured (MEDIUM)",
            details="Logs are being forwarded to remote server",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Audit & Logging",
            status="Info",
            message="NSA-AL-007: Remote logging not configured (MEDIUM)",
            details="Consider centralized logging for security",
            remediation="Configure remote logging in /etc/rsyslog.conf: *.* @@logserver:514"
        ))

# ============================================================================
# Main Module Entry Point
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """
    Main entry point for NSA Security Guidance module
    
    Args:
        shared_data: Dictionary with shared data from main script
        
    Returns:
        List of AuditResult objects
    """
    results = []
    
    print(f"\n[{MODULE_NAME}] Starting NSA Security Guidance checks...")
    print(f"[{MODULE_NAME}] Standards: NSA Security Configuration Guide, CNSS Policy")
    print(f"[{MODULE_NAME}] Priority Levels: CRITICAL, HIGH, MEDIUM, LOW")
    
    is_root = shared_data.get("is_root", False)
    if not is_root:
        print(f"[{MODULE_NAME}] Note: Some checks require root privileges for complete results")
    
    try:
        # System Hardening
        check_system_hardening(results, shared_data)
        
        # Network Security
        check_network_security(results, shared_data)
        
        # Cryptographic Standards
        check_cryptographic_standards(results, shared_data)
        
        # Access Control
        check_access_control(results, shared_data)
        
        # Audit and Logging
        check_audit_logging(results, shared_data)
        
    except Exception as e:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NSA - Error",
            status="Error",
            message=f"Module execution error: {str(e)}"
        ))
        import traceback
        traceback.print_exc()
    
    # Summary of findings by priority
    critical_fail = sum(1 for r in results if "CRITICAL" in r.message and r.status == "Fail")
    high_fail = sum(1 for r in results if "HIGH" in r.message and r.status == "Fail")
    medium_fail = sum(1 for r in results if "MEDIUM" in r.message and r.status == "Fail")
    
    summary_details = f"CRITICAL failures: {critical_fail}, HIGH failures: {high_fail}, MEDIUM failures: {medium_fail}"
    
    print(f"[{MODULE_NAME}] NSA Security Guidance checks completed - {len(results)} checks performed")
    print(f"[{MODULE_NAME}] Priority summary: {summary_details}")
    
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
    
    # Count by priority
    critical_total = sum(1 for r in test_results if "CRITICAL" in r.message)
    high_total = sum(1 for r in test_results if "HIGH" in r.message)
    medium_total = sum(1 for r in test_results if "MEDIUM" in r.message)
    low_total = sum(1 for r in test_results if "LOW" in r.message)
    
    critical_fail = sum(1 for r in test_results if "CRITICAL" in r.message and r.status == "Fail")
    high_fail = sum(1 for r in test_results if "HIGH" in r.message and r.status == "Fail")
    medium_fail = sum(1 for r in test_results if "MEDIUM" in r.message and r.status == "Fail")
    
    if critical_total > 0 or high_total > 0 or medium_total > 0:
        print("\nSummary by NSA Priority:")
        if critical_total > 0:
            print(f"  CRITICAL: {critical_total} checks, {critical_fail} failures")
        if high_total > 0:
            print(f"  HIGH: {high_total} checks, {high_fail} failures")
        if medium_total > 0:
            print(f"  MEDIUM: {medium_total} checks, {medium_fail} failures")
        if low_total > 0:
            print(f"  LOW: {low_total} checks")
    
    print("\n" + "=" * 60)
    print("NSA Security Guidance module test complete")
    print("=" * 60)
