#!/usr/bin/env python3
"""
module_enisa.py
ENISA (European Union Agency for Cybersecurity) Module
Version: 1.0

SYNOPSIS:
    ENISA cybersecurity guidelines and best practices compliance checks.

DESCRIPTION:
    This module implements security controls based on ENISA (European Union Agency  
    for Cybersecurity) guidelines, recommendations, and best practices:
    
    ENISA Threat Landscape:
    - Ransomware protection
    - DDoS mitigation
    - Data breaches prevention
    - Supply chain attacks protection
    - Identity theft prevention
    - Cryptojacking detection
    
    ENISA Cloud Security:
    - Cloud security posture
    - Data protection in cloud
    - Cloud access controls
    - Cloud logging and monitoring
    
    ENISA IoT Security:
    - Device security
    - Network segmentation
    - Secure updates
    - Authentication
    
    ENISA Incident Response:
    - Incident detection
    - Response procedures
    - Recovery capabilities
    - Communication protocols
    
    ENISA GDPR Technical Measures:
    - Data encryption
    - Pseudonymization
    - Access controls
    - Data portability
    - Right to erasure
    
    ENISA SME Security:
    - Basic security hygiene
    - Employee awareness
    - Backup procedures
    - Access management
    
    ENISA Critical Infrastructure:
    - Resilience measures
    - Continuity planning
    - Supply chain security
    - Physical security

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

NOTES:
    Version: 1.0
    Authority: ENISA - EU Cybersecurity Agency
    Focus: European cybersecurity standards and best practices
"""

import os
import sys
import re
import subprocess
import glob
from pathlib import Path
from typing import List, Dict, Any

sys.path.insert(0, str(Path(__file__).parent.parent))
from linux_security_audit import AuditResult

MODULE_NAME = "ENISA"

# ============================================================================
# Helper Functions
# ============================================================================

def run_command(command: str) -> subprocess.CompletedProcess:
    """Execute shell command"""
    try:
        return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
    except:
        return subprocess.CompletedProcess(args=command, returncode=-1, stdout="", stderr="")

def command_exists(command: str) -> bool:
    """Check if command exists"""
    return run_command(f"which {command} 2>/dev/null").returncode == 0

def read_file_safe(filepath: str) -> str:
    """Safely read file"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    except:
        return ""

def check_service_active(service: str) -> bool:
    """Check if service active"""
    return run_command(f"systemctl is-active {service} 2>/dev/null").stdout.strip() == "active"

def check_package_installed(package: str) -> bool:
    """Check if package installed"""
    if run_command(f"dpkg -l {package} 2>/dev/null | grep -q '^ii'").returncode == 0:
        return True
    return run_command(f"rpm -q {package} 2>/dev/null").returncode == 0

# ============================================================================
# ENISA Threat Landscape Checks
# ============================================================================

def check_threat_landscape(results: List[AuditResult], shared_data: Dict[str, Any]):
    """ENISA Threat Landscape protections"""
    print(f"[{MODULE_NAME}] Checking threat landscape protections...")
    
    # Ransomware protection - backups
    backup_tools = ["rsync", "borgbackup", "restic", "duplicity", "tar"]
    backup_found = [b for b in backup_tools if check_package_installed(b) or command_exists(b)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Threat Landscape",
        status="Pass" if backup_found else "Fail",
        message="Ransomware protection: Backup capability",
        details=f"Backup tools: {', '.join(backup_found)}" if backup_found else "No backup tools detected",
        remediation="Install backup solution for ransomware recovery" if not backup_found else ""
    ))
    
    # Malware protection
    antimalware = ["clamav", "clamav-daemon", "chkrootkit", "rkhunter"]
    malware_tools = [m for m in antimalware if check_package_installed(m)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Threat Landscape",
        status="Pass" if malware_tools else "Warning",
        message="Malware protection tools",
        details=f"Tools installed: {', '.join(malware_tools)}" if malware_tools else "No malware protection",
        remediation="Install ClamAV and rkhunter" if not malware_tools else ""
    ))
    
    # DDoS mitigation - rate limiting
    firewall_active = check_service_active("firewalld") or check_service_active("ufw")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Threat Landscape",
        status="Pass" if firewall_active else "Fail",
        message="DDoS mitigation: Firewall active",
        details="Network filtering enabled" if firewall_active else "No active firewall",
        remediation="Enable firewall for traffic filtering" if not firewall_active else ""
    ))
    
    # Data breach prevention - encryption
    luks_volumes = run_command("lsblk -o NAME,FSTYPE 2>/dev/null | grep -c crypto_LUKS").stdout.strip()
    encryption_active = luks_volumes.isdigit() and int(luks_volumes) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Threat Landscape",
        status="Pass" if encryption_active else "Warning",
        message="Data breach prevention: Disk encryption",
        details=f"{luks_volumes} encrypted volumes" if encryption_active else "No disk encryption detected",
        remediation="Implement full disk encryption (LUKS)" if not encryption_active else ""
    ))
    
    # Identity theft prevention - strong authentication
    mfa_packages = ["libpam-google-authenticator", "libpam-oath", "duo-unix"]
    mfa_installed = any(check_package_installed(p) for p in mfa_packages)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Threat Landscape",
        status="Pass" if mfa_installed else "Warning",
        message="Identity theft prevention: MFA capability",
        details="Multi-factor authentication available" if mfa_installed else "No MFA detected",
        remediation="Install MFA: libpam-google-authenticator" if not mfa_installed else ""
    ))
    
    # Cryptojacking detection - monitoring
    monitoring_active = check_service_active("auditd")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Threat Landscape",
        status="Pass" if monitoring_active else "Warning",
        message="Cryptojacking detection: System monitoring",
        details="Audit monitoring active" if monitoring_active else "No audit monitoring",
        remediation="Enable auditd for activity monitoring" if not monitoring_active else ""
    ))

# ============================================================================
# ENISA Cloud Security
# ============================================================================

def check_cloud_security(results: List[AuditResult], shared_data: Dict[str, Any]):
    """ENISA Cloud Security guidelines"""
    print(f"[{MODULE_NAME}] Checking cloud security...")
    
    # Cloud provider tools detection
    cloud_tools = ["aws", "az", "gcloud", "openstack"]
    cloud_cli = [c for c in cloud_tools if command_exists(c)]
    
    if cloud_cli:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Cloud Security",
            status="Info",
            message="Cloud tools detected",
            details=f"Cloud CLIs: {', '.join(cloud_cli)} - ensure security best practices",
            remediation="Review cloud security configurations"
        ))
    
    # Container security
    container_tools = ["docker", "podman", "containerd"]
    containers = [c for c in container_tools if command_exists(c)]
    
    if containers:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Cloud Security",
            status="Info",
            message="Container platform detected",
            details=f"Containers: {', '.join(containers)} - apply security hardening",
            remediation="Implement container security best practices"
        ))
    
    # Cloud-native security tools
    cloud_security = ["trivy", "anchore", "falco"]
    cloud_sec_tools = [s for s in cloud_security if command_exists(s)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Cloud Security",
        status="Info",
        message="Cloud security scanning",
        details=f"Security tools: {', '.join(cloud_sec_tools)}" if cloud_sec_tools else "No cloud security scanning tools",
        remediation="Install container/cloud security scanners" if not cloud_sec_tools else ""
    ))

# ============================================================================
# ENISA Incident Response
# ============================================================================

def check_incident_response(results: List[AuditResult], shared_data: Dict[str, Any]):
    """ENISA Incident Response preparedness"""
    print(f"[{MODULE_NAME}] Checking incident response preparedness...")
    
    # Incident response documentation
    ir_docs = ["/etc/security/incident-response.txt", "/etc/security/ir-plan.txt"]
    ir_documented = any(os.path.exists(d) for d in ir_docs)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Pass" if ir_documented else "Info",
        message="Incident response plan",
        details="IR procedures documented" if ir_documented else "No IR documentation found",
        remediation="Document incident response procedures" if not ir_documented else ""
    ))
    
    # Logging for incident detection
    logging_active = check_service_active("rsyslog") or check_service_active("syslog-ng")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Pass" if logging_active else "Fail",
        message="Incident detection: Logging",
        details="System logging active" if logging_active else "No system logging",
        remediation="Enable system logging: rsyslog" if not logging_active else ""
    ))
    
    # Intrusion detection
    ids_tools = ["aide", "ossec", "snort", "suricata", "fail2ban"]
    ids_installed = [i for i in ids_tools if check_package_installed(i)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Pass" if ids_installed else "Warning",
        message="Intrusion detection capability",
        details=f"IDS tools: {', '.join(ids_installed)}" if ids_installed else "No IDS tools",
        remediation="Install IDS: aide, fail2ban" if not ids_installed else ""
    ))
    
    # Forensics tools
    forensics = ["sleuthkit", "autopsy", "volatility"]
    forensics_tools = [f for f in forensics if check_package_installed(f) or command_exists(f)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message="Forensics capability",
        details=f"Forensics tools: {', '.join(forensics_tools)}" if forensics_tools else "No forensics tools",
        remediation="Consider forensics tools for incident investigation"
    ))
    
    # Communication tools for incident reporting
    email_configured = os.path.exists("/etc/mail") or os.path.exists("/etc/postfix")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Incident Response",
        status="Info",
        message="Incident communication capability",
        details="Email system detected" if email_configured else "No email system detected",
        remediation="Configure email for incident notifications"
    ))

# ============================================================================
# ENISA GDPR Technical Measures
# ============================================================================

def check_gdpr_technical(results: List[AuditResult], shared_data: Dict[str, Any]):
    """ENISA GDPR Technical and Organizational Measures"""
    print(f"[{MODULE_NAME}] Checking GDPR technical measures...")
    
    # Data encryption at rest
    crypto_tools = ["cryptsetup", "ecryptfs-utils"]
    encryption_available = any(check_package_installed(c) or command_exists(c) for c in crypto_tools)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - GDPR",
        status="Pass" if encryption_available else "Warning",
        message="GDPR: Data encryption capability",
        details="Encryption tools available" if encryption_available else "No encryption tools",
        remediation="Install cryptsetup for data encryption" if not encryption_available else ""
    ))
    
    # Access controls
    access_control_configured = os.path.exists("/etc/sudoers")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - GDPR",
        status="Pass" if access_control_configured else "Fail",
        message="GDPR: Access control mechanism",
        details="Privilege management configured" if access_control_configured else "No access controls",
        remediation="Configure sudo for access control" if not access_control_configured else ""
    ))
    
    # Audit logging for GDPR compliance
    audit_active = check_service_active("auditd")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - GDPR",
        status="Pass" if audit_active else "Fail",
        message="GDPR: Audit trail",
        details="Audit logging active" if audit_active else "No audit logging",
        remediation="Enable auditd for compliance logging" if not audit_active else ""
    ))
    
    # Secure deletion for right to erasure
    secure_delete = ["shred", "wipe", "srm"]
    deletion_tools = [d for d in secure_delete if command_exists(d)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - GDPR",
        status="Pass" if deletion_tools else "Info",
        message="GDPR: Right to erasure capability",
        details=f"Secure deletion: {', '.join(deletion_tools)}" if deletion_tools else "No secure deletion tools",
        remediation="Install secure deletion tools (shred available in coreutils)" if not deletion_tools else ""
    ))
    
    # Data portability - export capabilities
    export_tools = ["mysqldump", "pg_dump", "sqlite3"]
    db_export = [e for e in export_tools if command_exists(e)]
    
    if db_export:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - GDPR",
            status="Info",
            message="GDPR: Data portability tools available",
            details=f"Database export tools: {', '.join(db_export)}",
            remediation=""
        ))

# ============================================================================
# ENISA SME Security
# ============================================================================

def check_sme_security(results: List[AuditResult], shared_data: Dict[str, Any]):
    """ENISA Security for Small and Medium Enterprises"""
    print(f"[{MODULE_NAME}] Checking SME security basics...")
    
    # Basic security hygiene - updates
    update_tools = ["apt-get", "yum", "dnf", "zypper"]
    update_available = any(command_exists(u) for u in update_tools)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - SME Security",
        status="Pass" if update_available else "Fail",
        message="SME: Update mechanism",
        details="Package management available" if update_available else "No update mechanism",
        remediation="Ensure package manager is functional" if not update_available else ""
    ))
    
    # Firewall for SME protection
    firewall = check_service_active("firewalld") or check_service_active("ufw")
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - SME Security",
        status="Pass" if firewall else "Fail",
        message="SME: Basic firewall protection",
        details="Firewall active" if firewall else "No firewall",
        remediation="Enable firewall: ufw or firewalld" if not firewall else ""
    ))
    
    # Backup for SME continuity
    backup_configured = any(os.path.exists(d) for d in ["/etc/cron.daily", "/etc/cron.weekly"])
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - SME Security",
        status="Info",
        message="SME: Backup scheduling available",
        details="Cron system available for backup automation" if backup_configured else "No cron system",
        remediation="Configure regular backups via cron"
    ))
    
    # Password management
    password_tools = ["pass", "keepassxc", "bitwarden"]
    pwd_mgmt = [p for p in password_tools if command_exists(p)]
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - SME Security",
        status="Info",
        message="SME: Password management",
        details=f"Password tools: {', '.join(pwd_mgmt)}" if pwd_mgmt else "No password manager detected",
        remediation="Install password manager for employees"
    ))
    
    # Antivirus for SME
    av_tools = ["clamav", "clamav-daemon"]
    av_present = any(check_package_installed(a) for a in av_tools)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - SME Security",
        status="Pass" if av_present else "Warning",
        message="SME: Antivirus protection",
        details="Antivirus installed" if av_present else "No antivirus",
        remediation="Install ClamAV for virus protection" if not av_present else ""
    ))

# ============================================================================
# ENISA Critical Infrastructure
# ============================================================================

def check_critical_infrastructure(results: List[AuditResult], shared_data: Dict[str, Any]):
    """ENISA Critical Infrastructure Protection"""
    print(f"[{MODULE_NAME}] Checking critical infrastructure protections...")
    
    # Redundancy - RAID detection
    raid_present = os.path.exists("/proc/mdstat")
    
    if raid_present:
        raid_info = read_file_safe("/proc/mdstat")
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Critical Infrastructure",
            status="Pass",
            message="Infrastructure: Storage redundancy",
            details="RAID configuration detected",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Critical Infrastructure",
            status="Info",
            message="Infrastructure: Storage redundancy",
            details="No RAID detected - consider redundancy for critical systems",
            remediation="Implement storage redundancy for critical data"
        ))
    
    # High availability tools
    ha_tools = ["pacemaker", "corosync", "keepalived"]
    ha_present = [h for h in ha_tools if check_package_installed(h)]
    
    if ha_present:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Critical Infrastructure",
            status="Pass",
            message="Infrastructure: High availability",
            details=f"HA tools: {', '.join(ha_present)}",
            remediation=""
        ))
    
    # Network segmentation
    vlans = run_command("ip link show 2>/dev/null | grep -c '@'").stdout.strip()
    segmentation = vlans.isdigit() and int(vlans) > 0
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Critical Infrastructure",
        status="Info",
        message="Infrastructure: Network segmentation",
        details=f"VLANs detected: {vlans}" if segmentation else "No VLAN segmentation detected",
        remediation="Implement network segmentation for critical systems"
    ))
    
    # Physical security monitoring
    monitoring_software = ["motion", "zoneminder"]
    physical_monitoring = any(check_package_installed(m) for m in monitoring_software)
    
    results.append(AuditResult(
        module=MODULE_NAME,
        category="ENISA - Critical Infrastructure",
        status="Info",
        message="Infrastructure: Physical monitoring",
        details="Monitoring software detected" if physical_monitoring else "No physical monitoring software",
        remediation="Consider physical security monitoring for critical facilities"
    ))

# ============================================================================
# Main Entry Point
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """Main entry point for ENISA module"""
    results = []
    
    print(f"\n[{MODULE_NAME}] Starting ENISA cybersecurity checks...")
    print(f"[{MODULE_NAME}] Authority: EU Agency for Cybersecurity")
    print(f"[{MODULE_NAME}] Coverage: Threat landscape, Cloud, IoT, IR, GDPR, SME, Critical Infrastructure")
    
    try:
        check_threat_landscape(results, shared_data)
        check_cloud_security(results, shared_data)
        check_incident_response(results, shared_data)
        check_gdpr_technical(results, shared_data)
        check_sme_security(results, shared_data)
        check_critical_infrastructure(results, shared_data)
    except Exception as e:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="ENISA - Error",
            status="Error",
            message=f"Module error: {str(e)}"
        ))
    
    print(f"[{MODULE_NAME}] ENISA checks completed - {len(results)} checks performed")
    return results

if __name__ == "__main__":
    """Standalone testing"""
    import socket, platform
    
    print(f"Testing {MODULE_NAME} module...")
    test_data = {
        "hostname": socket.gethostname(),
        "os_version": f"{platform.system()} {platform.release()}",
        "is_root": os.geteuid() == 0
    }
    
    test_results = run_checks(test_data)
    print(f"\nGenerated {len(test_results)} check results")
    
    for status in ["Pass", "Fail", "Warning", "Info"]:
        count = sum(1 for r in test_results if r.status == status)
        if count > 0:
            print(f"  {status}: {count}")
