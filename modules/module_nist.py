#!/usr/bin/env python3
"""
module_nist.py
NIST Cybersecurity Framework Module for Linux
Version: 1.0

SYNOPSIS:
    NIST Cybersecurity Framework alignment checks for Linux systems.

DESCRIPTION:
    This module performs comprehensive checks aligned with the NIST Cybersecurity
    Framework Core Functions and Categories:
    
    IDENTIFY (ID):
    - ID.AM: Asset Management
    - ID.BE: Business Environment  
    - ID.GV: Governance
    - ID.RA: Risk Assessment
    - ID.RM: Risk Management Strategy
    - ID.SC: Supply Chain Risk Management
    
    PROTECT (PR):
    - PR.AC: Identity Management and Access Control
    - PR.AT: Awareness and Training
    - PR.DS: Data Security
    - PR.IP: Information Protection Processes and Procedures
    - PR.MA: Maintenance
    - PR.PT: Protective Technology
    
    DETECT (DE):
    - DE.AE: Anomalies and Events
    - DE.CM: Security Continuous Monitoring
    - DE.DP: Detection Processes
    
    RESPOND (RS):
    - RS.RP: Response Planning
    - RS.CO: Communications
    - RS.AN: Analysis
    - RS.MI: Mitigation
    - RS.IM: Improvements
    
    RECOVER (RC):
    - RC.RP: Recovery Planning
    - RC.IM: Improvements
    - RC.CO: Communications
    
    Based on NIST Cybersecurity Framework Version 1.1 and 2.0
    Also incorporates guidance from:
    - NIST SP 800-53 Rev 5 (Security and Privacy Controls)
    - NIST SP 800-171 Rev 2 (Protecting Controlled Unclassified Information)
    - NIST SP 800-123 (Guide to General Server Security)
    - NIST SP 800-137 (Information Security Continuous Monitoring)

PARAMETERS:
    shared_data : Dictionary containing shared data from main script

USAGE:
# Standalone testing
cd /mnt/user-data/outputs/modules
python3 module_nist.py

# Integrated with main script
python3 linux_security_audit.py -m nist

NOTES:
    Version: 1.0
    Reference: https://www.nist.gov/cyberframework
    Framework: NIST CSF 1.1 / 2.0, SP 800-53 Rev 5, SP 800-171 Rev 2
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

MODULE_NAME = "NIST"

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

def check_kernel_parameter(parameter: str) -> Tuple[bool, str]:
    """Check kernel parameter value"""
    result = run_command(f"sysctl {parameter} 2>/dev/null")
    if result.returncode == 0:
        match = re.search(r'=\s*(.+)', result.stdout)
        if match:
            return True, match.group(1).strip()
    return False, ""

# ============================================================================
# IDENTIFY (ID) Function - Asset Management
# ============================================================================

def check_asset_management(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST ID.AM - Asset Management
    Physical devices and systems, software platforms, applications are managed
    Maps to: NIST SP 800-53 CM-8, PM-5
    """
    print(f"[{MODULE_NAME}] Checking asset management (ID.AM)...")
    
    # ID.AM-1: Physical devices and systems within organization are inventoried
    inventory_tools = [
        ("dmidecode", "Hardware inventory tool"),
        ("lshw", "Hardware lister"),
        ("lsblk", "Block device listing"),
        ("lsusb", "USB device listing"),
        ("lspci", "PCI device listing"),
        ("inxi", "System information tool")
    ]
    
    available_tools = []
    for tool, description in inventory_tools:
        if command_exists(tool):
            available_tools.append(f"{tool} ({description})")
    
    if len(available_tools) >= 3:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Asset Management)",
            status="Pass",
            message="ID.AM-1: Asset inventory tools available",
            details=f"Hardware inventory capability: {', '.join(available_tools)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Asset Management)",
            status="Info",
            message="ID.AM-1: Limited asset inventory tools",
            details="Install additional inventory tools for comprehensive asset management",
            remediation="sudo apt-get install dmidecode lshw inxi || sudo yum install dmidecode lshw inxi"
        ))
    
    # ID.AM-2: Software platforms and applications are inventoried
    if command_exists("dpkg") or command_exists("rpm"):
        pkg_manager = "dpkg" if command_exists("dpkg") else "rpm"
        pkg_count_cmd = "dpkg -l | grep '^ii' | wc -l" if pkg_manager == "dpkg" else "rpm -qa | wc -l"
        pkg_count = run_command(pkg_count_cmd)
        
        if pkg_count.returncode == 0:
            count = pkg_count.stdout.strip()
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Identify (Asset Management)",
                status="Pass",
                message="ID.AM-2: Software inventory is maintained",
                details=f"Package manager tracking {count} installed packages ({pkg_manager})",
                remediation=""
            ))
    
    # ID.AM-3: Organizational communication and data flows are mapped
    network_tools = ["ss", "netstat", "ip", "traceroute", "nmap", "tcpdump"]
    available_net_tools = [tool for tool in network_tools if command_exists(tool)]
    
    if len(available_net_tools) >= 3:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Asset Management)",
            status="Pass",
            message="ID.AM-3: Network flow mapping tools available",
            details=f"Network analysis capabilities: {', '.join(available_net_tools)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Asset Management)",
            status="Info",
            message="ID.AM-3: Limited network mapping capabilities",
            details="Install network analysis tools for flow mapping",
            remediation="sudo apt-get install iproute2 net-tools traceroute nmap || sudo yum install iproute net-tools traceroute nmap"
        ))
    
    # ID.AM-4: External information systems are catalogued
    ssh_config_exists = os.path.exists("/etc/ssh/sshd_config")
    vpn_configs = len(glob.glob("/etc/openvpn/*.conf")) + len(glob.glob("/etc/wireguard/*.conf"))
    
    if ssh_config_exists or vpn_configs > 0:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Asset Management)",
            status="Info",
            message="ID.AM-4: External information systems detected",
            details=f"Remote access configured: SSH={ssh_config_exists}, VPN configs={vpn_configs}",
            remediation="Document and maintain inventory of all external system connections"
        ))
    
    # ID.AM-5: Resources are prioritized based on classification, criticality, and business value
    classification_files = [
        "/etc/security/classification",
        "/etc/system-classification",
        "/etc/issue",
        "/etc/issue.net"
    ]
    
    classification_found = False
    for clf_file in classification_files:
        if os.path.exists(clf_file):
            content = read_file_safe(clf_file)
            if content and len(content) > 10:
                classification_found = True
                break
    
    if classification_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Asset Management)",
            status="Pass",
            message="ID.AM-5: System classification is documented",
            details="Classification information found in banner files",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Asset Management)",
            status="Info",
            message="ID.AM-5: System classification not documented",
            details="Document system classification, criticality, and business value",
            remediation="Create classification banners in /etc/issue and /etc/issue.net"
        ))
    
    # ID.AM-6: Cybersecurity roles and responsibilities are established
    security_groups = ["sudo", "wheel", "adm", "security", "audit"]
    existing_groups = []
    
    group_content = read_file_safe("/etc/group")
    for group in security_groups:
        if f"{group}:" in group_content:
            existing_groups.append(group)
    
    if len(existing_groups) >= 2:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Asset Management)",
            status="Pass",
            message="ID.AM-6: Security administrative groups exist",
            details=f"Security groups configured: {', '.join(existing_groups)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Asset Management)",
            status="Info",
            message="ID.AM-6: Limited security group structure",
            details="Define security roles via system groups",
            remediation="Create security groups: sudo groupadd security && sudo groupadd audit"
        ))

def check_business_environment(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST ID.BE - Business Environment
    Organization's mission, objectives, stakeholders, and activities are understood
    Maps to: NIST SP 800-53 PM-8, SA-2
    """
    print(f"[{MODULE_NAME}] Checking business environment (ID.BE)...")
    
    # ID.BE-1: Organization's role in supply chain is identified and communicated
    # Check for system purpose documentation
    purpose_docs = [
        "/etc/system-purpose",
        "/etc/motd",
        "/etc/issue",
        "/etc/security/purpose.txt"
    ]
    
    purpose_found = any(os.path.exists(doc) and len(read_file_safe(doc)) > 20 for doc in purpose_docs)
    
    if purpose_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Business Environment)",
            status="Pass",
            message="ID.BE-1: System purpose is documented",
            details="System role and purpose documentation exists",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Business Environment)",
            status="Info",
            message="ID.BE-1: System purpose not documented",
            details="Document system purpose and organizational role",
            remediation="Create /etc/system-purpose with system role description"
        ))
    
    # ID.BE-2: Organization's place in critical infrastructure is identified
    # Check for critical system indicators
    critical_indicators = [
        ("/var/www", "Web server"),
        ("/etc/mysql", "Database server"),
        ("/etc/postgresql", "Database server"),
        ("/etc/nginx", "Web server"),
        ("/etc/apache2", "Web server")
    ]
    
    critical_services = []
    for path, service in critical_indicators:
        if os.path.exists(path):
            critical_services.append(service)
    
    if critical_services:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Business Environment)",
            status="Info",
            message="ID.BE-2: Critical infrastructure components detected",
            details=f"Critical services: {', '.join(set(critical_services))}",
            remediation="Document criticality level and dependencies"
        ))
    
    # ID.BE-3: Priorities for organizational mission, objectives, and activities are established
    # Check for service priorities (systemd)
    priority_services = run_command("systemctl list-dependencies --before critical.target 2>/dev/null | head -20")
    
    if priority_services.returncode == 0 and priority_services.stdout:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Business Environment)",
            status="Pass",
            message="ID.BE-3: Service dependencies are configured",
            details="Systemd service priorities and dependencies established",
            remediation=""
        ))
    
    # ID.BE-4: Dependencies and critical functions for delivery of services are established
    # Check for documented dependencies
    if os.path.exists("/etc/systemd/system"):
        service_count = len(glob.glob("/etc/systemd/system/*.service"))
        
        if service_count > 0:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Identify (Business Environment)",
                status="Pass",
                message="ID.BE-4: Service dependencies tracked via systemd",
                details=f"{service_count} custom service configurations with dependencies",
                remediation=""
            ))
    
    # ID.BE-5: Resilience requirements to support delivery of services are established
    # Check for high availability configurations
    ha_indicators = [
        ("pacemaker", "HA cluster manager"),
        ("corosync", "HA communication"),
        ("keepalived", "VRRP for HA"),
        ("haproxy", "Load balancer")
    ]
    
    ha_found = []
    for package, description in ha_indicators:
        if check_package_installed(package):
            ha_found.append(f"{package} ({description})")
    
    if ha_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Business Environment)",
            status="Pass",
            message="ID.BE-5: High availability components detected",
            details=f"Resilience mechanisms: {', '.join(ha_found)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Business Environment)",
            status="Info",
            message="ID.BE-5: No HA components detected",
            details="Consider HA solutions based on criticality",
            remediation="Evaluate need for keepalived, pacemaker, or similar HA solutions"
        ))

def check_governance(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST ID.GV - Governance
    Policies, procedures, and processes to manage and monitor regulatory,
    legal, risk, environmental, and operational requirements
    Maps to: NIST SP 800-53 PM series (Program Management)
    """
    print(f"[{MODULE_NAME}] Checking governance (ID.GV)...")
    
    # ID.GV-1: Organizational cybersecurity policy is established and communicated
    policy_locations = [
        "/etc/security/policy",
        "/etc/security/security-policy.txt",
        "/usr/share/doc/security-policy",
        "/etc/security/README"
    ]
    
    policy_found = any(os.path.exists(loc) for loc in policy_locations)
    
    if policy_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Governance)",
            status="Pass",
            message="ID.GV-1: Security policy documentation exists",
            details="Organizational security policy is documented",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Governance)",
            status="Info",
            message="ID.GV-1: Security policy not found",
            details="Document organizational security policy",
            remediation="Create /etc/security/policy with security policies"
        ))
    
    # ID.GV-2: Coordinated with relevant stakeholders
    # Check for contact information
    if os.path.exists("/etc/security/contacts") or os.path.exists("/etc/security/CONTACTS"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Governance)",
            status="Pass",
            message="ID.GV-2: Security contacts documented",
            details="Stakeholder contact information available",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Governance)",
            status="Info",
            message="ID.GV-2: Security contacts not documented",
            details="Document security team contact information",
            remediation="Create /etc/security/contacts with security team contacts"
        ))
    
    # ID.GV-3: Legal and regulatory requirements are understood and managed
    compliance_docs = [
        "/etc/security/compliance",
        "/etc/security/regulations.txt",
        "/usr/share/doc/compliance"
    ]
    
    compliance_found = any(os.path.exists(doc) for doc in compliance_docs)
    
    if compliance_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Governance)",
            status="Pass",
            message="ID.GV-3: Compliance documentation exists",
            details="Regulatory requirements documented",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Governance)",
            status="Info",
            message="ID.GV-3: Compliance documentation not found",
            details="Document applicable regulatory requirements",
            remediation="Create /etc/security/compliance with applicable regulations"
        ))
    
    # ID.GV-4: Governance and risk management processes address cybersecurity risks
    # Check for risk assessment documentation
    risk_docs = [
        "/etc/security/risk-assessment",
        "/etc/security/risk-register",
        "/etc/security/threats.txt"
    ]
    
    risk_found = any(os.path.exists(doc) for doc in risk_docs)
    
    if risk_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Governance)",
            status="Pass",
            message="ID.GV-4: Risk management documentation exists",
            details="Risk assessment and management processes documented",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Governance)",
            status="Info",
            message="ID.GV-4: Risk management not documented",
            details="Document risk management processes",
            remediation="Create /etc/security/risk-assessment with risk management approach"
        ))

def check_risk_assessment(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST ID.RA - Risk Assessment
    Understanding cybersecurity risk to organizational operations, assets, individuals
    Maps to: NIST SP 800-53 RA series (Risk Assessment), PM-16
    """
    print(f"[{MODULE_NAME}] Checking risk assessment (ID.RA)...")
    
    # ID.RA-1: Asset vulnerabilities are identified and documented
    vuln_tools = [
        ("lynis", "System auditing tool"),
        ("openvas", "Vulnerability scanner"),
        ("nmap", "Network scanner"),
        ("nikto", "Web vulnerability scanner"),
        ("chkrootkit", "Rootkit detector"),
        ("rkhunter", "Rootkit hunter"),
        ("clamav", "Antivirus scanner")
    ]
    
    available_vuln_tools = []
    for tool, description in vuln_tools:
        if check_package_installed(tool) or command_exists(tool):
            available_vuln_tools.append(f"{tool} ({description})")
    
    if available_vuln_tools:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Assessment)",
            status="Pass",
            message="ID.RA-1: Vulnerability assessment tools installed",
            details=f"Available tools: {', '.join(available_vuln_tools)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Assessment)",
            status="Warning",
            message="ID.RA-1: No vulnerability assessment tools found",
            details="Install vulnerability scanning tools for risk assessment",
            remediation="sudo apt-get install lynis chkrootkit rkhunter clamav || sudo yum install lynis chkrootkit rkhunter clamav"
        ))
    
    # ID.RA-2: Cyber threat intelligence is received from information sharing forums
    threat_intel_indicators = [
        "/etc/snort/rules",
        "/etc/suricata/rules",
        "/var/lib/clamav",
        "/etc/fail2ban/filter.d",
        "/etc/security/threat-intel"
    ]
    
    threat_intel_found = []
    for indicator in threat_intel_indicators:
        if os.path.exists(indicator):
            threat_intel_found.append(indicator)
    
    if threat_intel_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Assessment)",
            status="Pass",
            message="ID.RA-2: Threat intelligence systems detected",
            details=f"Threat intel feeds configured: {len(threat_intel_found)} sources",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Assessment)",
            status="Info",
            message="ID.RA-2: No threat intelligence feeds detected",
            details="Consider implementing threat intelligence feeds",
            remediation="sudo apt-get install fail2ban clamav || sudo yum install fail2ban clamav"
        ))
    
    # ID.RA-3: Threats, both internal and external, are identified and documented
    if check_service_active("auditd") or check_service_active("rsyslog"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Assessment)",
            status="Pass",
            message="ID.RA-3: Security event logging is active",
            details="Threat identification capability through audit logs",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Assessment)",
            status="Fail",
            message="ID.RA-3: Security event logging is not active",
            details="Enable auditd or rsyslog for threat identification",
            remediation="sudo systemctl enable --now auditd"
        ))
    
    # ID.RA-4: Potential business impacts and likelihoods are identified
    # Check for business impact documentation
    impact_docs = [
        "/etc/security/business-impact",
        "/etc/security/impact-analysis.txt"
    ]
    
    impact_found = any(os.path.exists(doc) for doc in impact_docs)
    
    if impact_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Assessment)",
            status="Pass",
            message="ID.RA-4: Business impact analysis documented",
            details="Business impact documentation exists",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Assessment)",
            status="Info",
            message="ID.RA-4: Business impact not documented",
            details="Document potential business impacts",
            remediation="Create /etc/security/business-impact with impact analysis"
        ))
    
    # ID.RA-5: Threats, vulnerabilities, likelihoods, and impacts used to determine risk
    if available_vuln_tools:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Assessment)",
            status="Pass",
            message="ID.RA-5: Risk assessment capabilities exist",
            details="Risk determination tools available",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Assessment)",
            status="Info",
            message="ID.RA-5: Limited risk assessment capability",
            details="Implement risk assessment methodology",
            remediation="Install vulnerability assessment tools and document risk methodology"
        ))
    
    # ID.RA-6: Risk responses are identified and prioritized
    # Check for risk treatment plan
    if os.path.exists("/etc/security/risk-treatment") or os.path.exists("/etc/security/risk-response"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Assessment)",
            status="Pass",
            message="ID.RA-6: Risk response planning documented",
            details="Risk treatment and response plan exists",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Assessment)",
            status="Info",
            message="ID.RA-6: Risk response not documented",
            details="Document risk response and treatment plans",
            remediation="Create /etc/security/risk-treatment with response strategies"
        ))

def check_risk_management_strategy(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST ID.RM - Risk Management Strategy
    Organization's priorities, constraints, risk tolerances, and assumptions
    Maps to: NIST SP 800-53 PM-9, PM-16
    """
    print(f"[{MODULE_NAME}] Checking risk management strategy (ID.RM)...")
    
    # ID.RM-1: Risk management processes are established, managed, and agreed to
    risk_mgmt_docs = [
        "/etc/security/risk-management",
        "/etc/security/risk-policy.txt"
    ]
    
    risk_mgmt_found = any(os.path.exists(doc) for doc in risk_mgmt_docs)
    
    if risk_mgmt_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Management)",
            status="Pass",
            message="ID.RM-1: Risk management processes documented",
            details="Risk management framework exists",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Management)",
            status="Info",
            message="ID.RM-1: Risk management not documented",
            details="Document risk management processes and framework",
            remediation="Create /etc/security/risk-management with RM framework"
        ))
    
    # ID.RM-2: Organizational risk tolerance is determined and expressed
    # Check for risk tolerance documentation
    if os.path.exists("/etc/security/risk-tolerance"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Management)",
            status="Pass",
            message="ID.RM-2: Risk tolerance is documented",
            details="Organizational risk tolerance defined",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Management)",
            status="Info",
            message="ID.RM-2: Risk tolerance not documented",
            details="Define and document organizational risk tolerance",
            remediation="Create /etc/security/risk-tolerance with tolerance levels"
        ))
    
    # ID.RM-3: Organization's determination of risk tolerance is informed by its role in CI
    # This is largely organizational - check for critical infrastructure designation
    if os.path.exists("/etc/security/ci-designation"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Risk Management)",
            status="Pass",
            message="ID.RM-3: Critical infrastructure role documented",
            details="CI designation informs risk management",
            remediation=""
        ))

def check_supply_chain_risk_management(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST ID.SC - Supply Chain Risk Management
    Organization's priorities, constraints, risk tolerances, and assumptions
    Maps to: NIST SP 800-53 SR series (Supply Chain Risk Management), SA-12
    """
    print(f"[{MODULE_NAME}] Checking supply chain risk management (ID.SC)...")
    
    # ID.SC-1: Cyber supply chain risk management processes identified, established
    # Check for package signature verification
    if command_exists("apt"):
        apt_check = run_command("apt-key list 2>/dev/null | grep -c 'pub'")
        if apt_check.returncode == 0 and apt_check.stdout.strip():
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Identify (Supply Chain)",
                status="Pass",
                message="ID.SC-1: Package signature verification (APT keys)",
                details=f"APT package verification with {apt_check.stdout.strip()} keys configured",
                remediation=""
            ))
    elif command_exists("rpm"):
        rpm_check = run_command("rpm -qa gpg-pubkey* | wc -l")
        if rpm_check.returncode == 0 and rpm_check.stdout.strip():
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Identify (Supply Chain)",
                status="Pass",
                message="ID.SC-1: Package signature verification (RPM GPG)",
                details=f"RPM package verification with {rpm_check.stdout.strip()} keys",
                remediation=""
            ))
    
    # ID.SC-2: Suppliers and third-party partners identified, prioritized, and assessed
    # Check for vendor/supplier documentation
    if os.path.exists("/etc/security/suppliers") or os.path.exists("/etc/security/vendors"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Supply Chain)",
            status="Pass",
            message="ID.SC-2: Supplier documentation exists",
            details="Third-party suppliers and vendors documented",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Supply Chain)",
            status="Info",
            message="ID.SC-2: Supplier documentation not found",
            details="Document third-party suppliers and dependencies",
            remediation="Create /etc/security/suppliers with vendor information"
        ))
    
    # ID.SC-3: Contracts with suppliers and third-party partners used to implement appropriate measures
    # Check for contract/SLA documentation
    if os.path.exists("/etc/security/contracts") or os.path.exists("/etc/security/sla"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Supply Chain)",
            status="Pass",
            message="ID.SC-3: Contract documentation exists",
            details="Supplier contracts and SLAs documented",
            remediation=""
        ))
    
    # ID.SC-4: Suppliers and third-party partners routinely assessed using audits, tests
    # Check for assessment documentation
    if os.path.exists("/etc/security/vendor-assessments"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Supply Chain)",
            status="Pass",
            message="ID.SC-4: Vendor assessment documentation exists",
            details="Supplier assessment records maintained",
            remediation=""
        ))
    
    # ID.SC-5: Response and recovery planning includes suppliers and third-party providers
    # Check for supplier incident response plan
    ir_plan = read_file_safe("/etc/security/incident-response.txt")
    if "supplier" in ir_plan.lower() or "vendor" in ir_plan.lower() or "third-party" in ir_plan.lower():
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Identify (Supply Chain)",
            status="Pass",
            message="ID.SC-5: Supplier IR coordination documented",
            details="Incident response includes supplier coordination",
            remediation=""
        ))

# ============================================================================
# PROTECT (PR) Function - Access Control
# ============================================================================

def check_access_control(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST PR.AC - Identity Management and Access Control
    Access to physical and logical assets limited to authorized users
    Maps to: NIST SP 800-53 AC series (Access Control), IA series (Identification and Authentication)
    """
    print(f"[{MODULE_NAME}] Checking access control (PR.AC)...")
    
    # PR.AC-1: Identities and credentials issued, managed, verified, revoked, audited
    login_defs = read_file_safe("/etc/login.defs")
    
    pass_max_days = re.search(r'PASS_MAX_DAYS\s+(\d+)', login_defs)
    pass_min_days = re.search(r'PASS_MIN_DAYS\s+(\d+)', login_defs)
    pass_min_len = re.search(r'PASS_MIN_LEN\s+(\d+)', login_defs)
    pass_warn_age = re.search(r'PASS_WARN_AGE\s+(\d+)', login_defs)
    
    if pass_max_days and int(pass_max_days.group(1)) <= 90:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Access Control)",
            status="Pass",
            message="PR.AC-1: Password aging policy configured",
            details=f"PASS_MAX_DAYS set to {pass_max_days.group(1)} days",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Access Control)",
            status="Fail",
            message="PR.AC-1: Password aging policy not configured",
            details="PASS_MAX_DAYS should be 90 or less per NIST guidelines",
            remediation="sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs"
        ))
    
    if pass_min_len and int(pass_min_len.group(1)) >= 12:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Access Control)",
            status="Pass",
            message="PR.AC-1: Password minimum length configured",
            details=f"PASS_MIN_LEN set to {pass_min_len.group(1)} characters",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Access Control)",
            status="Fail",
            message="PR.AC-1: Password minimum length insufficient",
            details="PASS_MIN_LEN should be at least 12 characters",
            remediation="sudo sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 12/' /etc/login.defs"
        ))
    
    # PR.AC-2: Physical access to assets is managed and protected
    # Check for screen lock timeout
    screen_lock_timeout = None
    
    # Check GNOME settings
    if os.path.exists("/etc/dconf/db/local.d"):
        dconf_files = glob.glob("/etc/dconf/db/local.d/*")
        for dconf_file in dconf_files:
            content = read_file_safe(dconf_file)
            if "idle-delay" in content or "lock-delay" in content:
                screen_lock_timeout = "configured"
                break
    
    if screen_lock_timeout:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Access Control)",
            status="Pass",
            message="PR.AC-2: Screen lock timeout configured",
            details="Physical access protection via screen lock",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Access Control)",
            status="Warning",
            message="PR.AC-2: Screen lock timeout not detected",
            details="Configure automatic screen lock for physical security",
            remediation="Configure screen lock timeout through desktop environment settings"
        ))
    
    # PR.AC-3: Remote access is managed
    if os.path.exists("/etc/ssh/sshd_config"):
        sshd_config = read_file_safe("/etc/ssh/sshd_config")
        
        password_auth = re.search(r'^\s*PasswordAuthentication\s+(yes|no)', sshd_config, re.MULTILINE | re.IGNORECASE)
        pubkey_auth = re.search(r'^\s*PubkeyAuthentication\s+(yes|no)', sshd_config, re.MULTILINE | re.IGNORECASE)
        permit_root = re.search(r'^\s*PermitRootLogin\s+(\S+)', sshd_config, re.MULTILINE | re.IGNORECASE)
        
        if password_auth and password_auth.group(1).lower() == "no":
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Access Control)",
                status="Pass",
                message="PR.AC-3: SSH password authentication disabled",
                details="Key-based authentication enforced for remote access",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Access Control)",
                status="Warning",
                message="PR.AC-3: SSH password authentication enabled",
                details="Consider disabling password authentication",
                remediation="sudo sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && sudo systemctl restart sshd"
            ))
        
        if permit_root and permit_root.group(1).lower() == "no":
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Access Control)",
                status="Pass",
                message="PR.AC-3: SSH root login disabled",
                details="Direct root login via SSH is disabled",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Access Control)",
                status="Fail",
                message="PR.AC-3: SSH root login is enabled",
                details="Disable direct root login via SSH",
                remediation="sudo sed -i 's/^.*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && sudo systemctl restart sshd"
            ))
    
    # PR.AC-4: Access permissions and authorizations are managed
    if os.path.exists("/etc/sudoers"):
        sudoers_perms = get_file_permissions("/etc/sudoers")
        if sudoers_perms and sudoers_perms == "440":
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Access Control)",
                status="Pass",
                message="PR.AC-4: Sudo configuration properly secured",
                details="/etc/sudoers has correct permissions (440)",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Access Control)",
                status="Fail",
                message="PR.AC-4: Sudo configuration has incorrect permissions",
                details=f"Current permissions: {sudoers_perms}, should be 440",
                remediation="sudo chmod 440 /etc/sudoers"
            ))
    
    # Check for sudoers.d usage
    if os.path.exists("/etc/sudoers.d"):
        sudoers_d_files = os.listdir("/etc/sudoers.d")
        if sudoers_d_files:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Access Control)",
                status="Pass",
                message="PR.AC-4: Modular sudo configuration in use",
                details=f"{len(sudoers_d_files)} sudoers.d configuration files",
                remediation=""
            ))
    
    # PR.AC-5: Network integrity is protected (network segmentation)
    firewall_active = False
    
    if command_exists("ufw"):
        ufw_status = run_command("ufw status")
        if "Status: active" in ufw_status.stdout:
            firewall_active = True
            
            # Check for rules
            rule_count = run_command("ufw status numbered | grep -c '\\[' 2>/dev/null")
            if rule_count.returncode == 0:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="NIST - Protect (Access Control)",
                    status="Pass",
                    message="PR.AC-5: UFW firewall active with rules",
                    details=f"Network segmentation via UFW with {rule_count.stdout.strip()} rules",
                    remediation=""
                ))
    
    if check_service_active("firewalld"):
        firewall_active = True
        zone_check = run_command("firewall-cmd --get-active-zones 2>/dev/null")
        if zone_check.returncode == 0:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Access Control)",
                status="Pass",
                message="PR.AC-5: firewalld active with zones",
                details="Network segmentation via firewalld zones",
                remediation=""
            ))
    
    if not firewall_active:
        iptables_check = run_command("iptables -L -n 2>/dev/null | grep -v '^Chain' | grep -v '^target' | wc -l")
        if iptables_check.returncode == 0 and int(iptables_check.stdout.strip()) > 0:
            firewall_active = True
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Access Control)",
                status="Pass",
                message="PR.AC-5: iptables rules configured",
                details="Network protection via iptables",
                remediation=""
            ))
    
    if not firewall_active:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Access Control)",
            status="Fail",
            message="PR.AC-5: No active firewall detected",
            details="Enable firewall for network protection and segmentation",
            remediation="sudo ufw enable || sudo systemctl enable --now firewalld"
        ))
    
    # PR.AC-6: Identities are proofed and bound to credentials
    # Check for multi-factor authentication
    mfa_indicators = [
        "/etc/pam.d/google-authenticator",
        "/etc/security/pam_oath.conf",
        "/lib/security/pam_google_authenticator.so",
        "/lib/security/pam_oath.so",
        "/lib/x86_64-linux-gnu/security/pam_google_authenticator.so"
    ]
    
    mfa_found = any(os.path.exists(indicator) for indicator in mfa_indicators)
    
    if mfa_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Access Control)",
            status="Pass",
            message="PR.AC-6: Multi-factor authentication is configured",
            details="MFA enhances identity proofing",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Access Control)",
            status="Info",
            message="PR.AC-6: Multi-factor authentication not detected",
            details="Consider implementing MFA for enhanced security",
            remediation="sudo apt-get install libpam-google-authenticator || sudo yum install google-authenticator"
        ))
    
    # PR.AC-7: Users, devices, and other assets are authenticated
    if os.path.exists("/etc/ssl/certs"):
        cert_count = len([f for f in os.listdir("/etc/ssl/certs") if os.path.isfile(os.path.join("/etc/ssl/certs", f))])
        
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Access Control)",
            status="Pass",
            message="PR.AC-7: Certificate infrastructure available",
            details=f"SSL/TLS certificate store present with {cert_count} certificates",
            remediation=""
        ))

def check_awareness_training(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST PR.AT - Awareness and Training
    Organization's personnel and partners provided cybersecurity awareness education
    Maps to: NIST SP 800-53 AT series (Awareness and Training)
    """
    print(f"[{MODULE_NAME}] Checking awareness and training (PR.AT)...")
    
    # PR.AT-1: All users are informed and trained
    # Check for login banner/MOTD
    motd_content = read_file_safe("/etc/motd")
    issue_content = read_file_safe("/etc/issue")
    
    has_security_message = False
    for content in [motd_content, issue_content]:
        if any(keyword in content.lower() for keyword in ["security", "authorized", "monitor", "audit", "policy"]):
            has_security_message = True
            break
    
    if has_security_message:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Awareness & Training)",
            status="Pass",
            message="PR.AT-1: Security awareness banner present",
            details="Login banners communicate security expectations",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Awareness & Training)",
            status="Info",
            message="PR.AT-1: No security awareness banner",
            details="Add security awareness messaging to login banners",
            remediation="Add security policy notice to /etc/motd and /etc/issue"
        ))
    
    # PR.AT-2: Privileged users understand roles and responsibilities
    # Check for sudo lecture
    sudoers_content = read_file_safe("/etc/sudoers")
    
    if "lecture" not in sudoers_content or "lecture_file" in sudoers_content:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Awareness & Training)",
            status="Pass",
            message="PR.AT-2: Sudo lecture enabled",
            details="Privileged users receive responsibility reminder",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Awareness & Training)",
            status="Info",
            message="PR.AT-2: Sudo lecture not configured",
            details="Configure sudo to display security lecture",
            remediation="Add 'Defaults lecture=always' to /etc/sudoers"
        ))
    
    # PR.AT-3: Third-party stakeholders understand roles and responsibilities
    # Check for partner/vendor documentation
    if os.path.exists("/etc/security/third-party-responsibilities"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Awareness & Training)",
            status="Pass",
            message="PR.AT-3: Third-party responsibilities documented",
            details="Stakeholder security roles documented",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Awareness & Training)",
            status="Info",
            message="PR.AT-3: Third-party responsibilities not documented",
            details="Document security expectations for third parties",
            remediation="Create /etc/security/third-party-responsibilities"
        ))
    
    # PR.AT-4: Senior executives understand roles and responsibilities
    # Check for executive briefing documentation
    if os.path.exists("/etc/security/executive-briefing") or os.path.exists("/etc/security/leadership-responsibilities"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Awareness & Training)",
            status="Pass",
            message="PR.AT-4: Executive responsibilities documented",
            details="Leadership security roles defined",
            remediation=""
        ))
    
    # PR.AT-5: Physical and cybersecurity personnel understand roles and responsibilities
    # Check for security team documentation
    if os.path.exists("/etc/security/team-roles") or os.path.exists("/etc/security/responsibilities"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Awareness & Training)",
            status="Pass",
            message="PR.AT-5: Security team roles documented",
            details="Security personnel responsibilities defined",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Awareness & Training)",
            status="Info",
            message="PR.AT-5: Security team roles not documented",
            details="Document security team roles and responsibilities",
            remediation="Create /etc/security/team-roles with role definitions"
        ))

# Due to length constraints, I'll continue with the remaining PROTECT, DETECT, RESPOND, and RECOVER functions in the next part...
# Let me complete the file now:

def check_data_security(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST PR.DS - Data Security
    Information and records managed consistent with organization's risk strategy
    Maps to: NIST SP 800-53 MP series (Media Protection), SC-28 (Protection of Information at Rest)
    """
    print(f"[{MODULE_NAME}] Checking data security (PR.DS)...")
    
    # PR.DS-1: Data-at-rest is protected
    luks_check = run_command("blkid | grep -i crypto_luks")
    dm_crypt_check = run_command("lsblk -o NAME,FSTYPE | grep -i crypt")
    
    if luks_check.returncode == 0 or dm_crypt_check.returncode == 0:
        encrypted_devices = luks_check.stdout.count('\n') if luks_check.returncode == 0 else dm_crypt_check.stdout.count('\n')
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Pass",
            message="PR.DS-1: Disk encryption detected (data-at-rest)",
            details=f"LUKS/dm-crypt encryption on {encrypted_devices} device(s)",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Warning",
            message="PR.DS-1: No disk encryption detected",
            details="Consider implementing full disk encryption",
            remediation="Use LUKS during installation or encrypt with cryptsetup"
        ))
    
    # PR.DS-2: Data-in-transit is protected
    openssl_installed = command_exists("openssl")
    
    if openssl_installed:
        # Check OpenSSL version
        openssl_version = run_command("openssl version")
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Pass",
            message="PR.DS-2: SSL/TLS capability available",
            details=f"OpenSSL installed: {openssl_version.stdout.strip()}",
            remediation=""
        ))
        
        # Check for strong ciphers configuration
        if os.path.exists("/etc/ssl/openssl.cnf"):
            openssl_conf = read_file_safe("/etc/ssl/openssl.cnf")
            if "MinProtocol" in openssl_conf and "TLSv1.2" in openssl_conf:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="NIST - Protect (Data Security)",
                    status="Pass",
                    message="PR.DS-2: Strong TLS protocols configured",
                    details="Minimum TLS 1.2 enforced",
                    remediation=""
                ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Fail",
            message="PR.DS-2: SSL/TLS tools not available",
            details="Install OpenSSL for data-in-transit protection",
            remediation="sudo apt-get install openssl || sudo yum install openssl"
        ))
    
    # PR.DS-3: Assets formally managed throughout removal, transfers, disposition
    secure_delete_tools = ["shred", "wipe", "scrub", "dd"]
    available_tools = [tool for tool in secure_delete_tools if command_exists(tool)]
    
    if available_tools:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Pass",
            message="PR.DS-3: Secure deletion tools available",
            details=f"Data sanitization: {', '.join(available_tools)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Info",
            message="PR.DS-3: Limited secure deletion capability",
            details="Install secure deletion tools",
            remediation="sudo apt-get install secure-delete || sudo yum install wipe"
        ))
    
    # PR.DS-4: Adequate capacity to ensure availability is maintained
    df_check = run_command("df -h / | tail -1")
    if df_check.returncode == 0:
        match = re.search(r'(\d+)%', df_check.stdout)
        if match:
            usage = int(match.group(1))
            if usage < 80:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="NIST - Protect (Data Security)",
                    status="Pass",
                    message="PR.DS-4: Root filesystem has adequate capacity",
                    details=f"Root filesystem {usage}% used",
                    remediation=""
                ))
            elif usage < 90:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="NIST - Protect (Data Security)",
                    status="Warning",
                    message="PR.DS-4: Root filesystem capacity concern",
                    details=f"Root filesystem {usage}% used - monitor closely",
                    remediation="Clean up unnecessary files or expand filesystem"
                ))
            else:
                results.append(AuditResult(
                    module=MODULE_NAME,
                    category="NIST - Protect (Data Security)",
                    status="Fail",
                    message="PR.DS-4: Root filesystem critically low on space",
                    details=f"Root filesystem {usage}% used - immediate action required",
                    remediation="Free up space immediately or expand filesystem"
                ))
    
    # PR.DS-5: Protections against data leaks are implemented
    dlp_indicators = [
        ("aide", "File integrity monitoring"),
        ("auditd", "System call auditing"),
        ("apparmor", "MAC enforcement"),
        ("selinux", "MAC enforcement")
    ]
    
    dlp_found = []
    for tool, description in dlp_indicators:
        if check_package_installed(tool) or check_service_active(tool):
            dlp_found.append(f"{tool} ({description})")
    
    if dlp_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Pass",
            message="PR.DS-5: Data leak protection mechanisms present",
            details=f"Active protections: {', '.join(dlp_found)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Warning",
            message="PR.DS-5: Limited data leak protection",
            details="Implement file integrity monitoring and access controls",
            remediation="sudo apt-get install aide auditd || sudo yum install aide audit"
        ))
    
    # PR.DS-6: Integrity checking mechanisms verify software, firmware, information
    if command_exists("debsums"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Pass",
            message="PR.DS-6: Package integrity verification available (Debian)",
            details="debsums can verify installed package integrity",
            remediation=""
        ))
    elif command_exists("rpm"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Pass",
            message="PR.DS-6: Package integrity verification available (RPM)",
            details="rpm -V can verify installed package integrity",
            remediation=""
        ))
    
    # PR.DS-7: Development and testing environments separate from production
    hostname = shared_data.get("hostname", "unknown")
    env_indicators = ["dev", "test", "staging", "prod", "production"]
    
    hostname_has_env = any(indicator in hostname.lower() for indicator in env_indicators)
    
    if hostname_has_env:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Info",
            message="PR.DS-7: Environment designation in hostname",
            details=f"Hostname '{hostname}' indicates environment separation",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Info",
            message="PR.DS-7: Environment designation not detected",
            details="Consider naming conventions: hostname-{dev|test|prod}.domain.com",
            remediation="Use descriptive hostnames indicating environment"
        ))
    
    # PR.DS-8: Integrity checking mechanisms verify hardware
    hw_monitor_tools = ["smartctl", "sensors", "ipmitool"]
    hw_tools_available = [tool for tool in hw_monitor_tools if command_exists(tool)]
    
    if hw_tools_available:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Pass",
            message="PR.DS-8: Hardware integrity monitoring available",
            details=f"Hardware monitoring: {', '.join(hw_tools_available)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Data Security)",
            status="Info",
            message="PR.DS-8: Hardware monitoring tools not detected",
            details="Install tools for hardware health monitoring",
            remediation="sudo apt-get install smartmontools lm-sensors || sudo yum install smartmontools lm_sensors"
        ))

def check_information_protection_processes(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST PR.IP - Information Protection Processes and Procedures
    Security policies, processes, and procedures maintained and used
    Maps to: NIST SP 800-53 various controls across families
    """
    print(f"[{MODULE_NAME}] Checking information protection processes (PR.IP)...")
    
    # PR.IP-1: Baseline configuration created and maintained
    # Check for configuration management
    if check_package_installed("ansible") or check_package_installed("puppet") or check_package_installed("chef"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Pass",
            message="PR.IP-1: Configuration management tool installed",
            details="Baseline configuration management capability present",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Info",
            message="PR.IP-1: No configuration management tool detected",
            details="Consider Ansible, Puppet, or Chef for baseline management",
            remediation="sudo apt-get install ansible || sudo yum install ansible"
        ))
    
    # PR.IP-2: System development life cycle managed
    # Check for development tools and processes
    if os.path.exists("/etc/security/sdlc"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Pass",
            message="PR.IP-2: SDLC documentation exists",
            details="System development lifecycle documented",
            remediation=""
        ))
    
    # PR.IP-3: Configuration change control processes in place
    # Check for version control
    vcs_tools = ["git", "svn", "hg"]
    vcs_found = [tool for tool in vcs_tools if command_exists(tool)]
    
    if vcs_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Pass",
            message="PR.IP-3: Version control available",
            details=f"Change control via: {', '.join(vcs_found)}",
            remediation=""
        ))
    
    # PR.IP-4: Backups of information conducted, maintained, and tested
    backup_tools = ["restic", "borgbackup", "duplicity", "rsnapshot", "bacula", "amanda"]
    backup_found = []
    
    for tool in backup_tools:
        if check_package_installed(tool) or command_exists(tool):
            backup_found.append(tool)
    
    if backup_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Pass",
            message="PR.IP-4: Backup solution detected",
            details=f"Backup capability: {', '.join(backup_found)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Warning",
            message="PR.IP-4: No backup solution detected",
            details="Implement backup solution for data protection",
            remediation="sudo apt-get install restic || sudo yum install restic"
        ))
    
    # PR.IP-5: Policy and regulations regarding physical operating environment met
    # Check for physical security documentation
    if os.path.exists("/etc/security/physical-security"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Pass",
            message="PR.IP-5: Physical security policy documented",
            details="Physical operating environment requirements documented",
            remediation=""
        ))
    
    # PR.IP-6: Data is destroyed according to policy
    # Secure deletion capability already checked in PR.DS-3
    
    # PR.IP-7: Protection processes improved
    # Check for security assessment history
    if os.path.exists("/var/log/security-assessments") or os.path.exists("/etc/security/assessments"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Pass",
            message="PR.IP-7: Security assessment records maintained",
            details="Protection process improvement tracking exists",
            remediation=""
        ))
    
    # PR.IP-8: Effectiveness of protection technologies shared
    # Check for information sharing mechanisms
    if os.path.exists("/etc/security/sharing-agreements") or os.path.exists("/etc/security/isac"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Pass",
            message="PR.IP-8: Information sharing documented",
            details="Protection technology effectiveness sharing mechanisms exist",
            remediation=""
        ))
    
    # PR.IP-9: Response and recovery plans in place and managed
    # Check for incident response plans
    ir_plans = [
        "/etc/security/incident-response.txt",
        "/etc/security/ir-plan",
        "/etc/security/drp"
    ]
    
    ir_found = any(os.path.exists(plan) for plan in ir_plans)
    
    if ir_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Pass",
            message="PR.IP-9: Incident response plan exists",
            details="Response and recovery plans documented",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Info",
            message="PR.IP-9: Incident response plan not found",
            details="Document incident response and recovery plans",
            remediation="Create /etc/security/incident-response.txt with IR procedures"
        ))
    
    # PR.IP-10: Response and recovery plans are tested
    if os.path.exists("/etc/security/test-results") or os.path.exists("/var/log/drp-tests"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Pass",
            message="PR.IP-10: Plan testing documentation exists",
            details="Response/recovery plan test results maintained",
            remediation=""
        ))
    
    # PR.IP-11: Cybersecurity included in HR practices
    # Check for security training requirements
    if os.path.exists("/etc/security/hr-security-requirements"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Pass",
            message="PR.IP-11: Security HR practices documented",
            details="Cybersecurity integrated into HR processes",
            remediation=""
        ))
    
    # PR.IP-12: Vulnerability management plan developed and implemented
    # Vulnerability tools already checked in ID.RA-1
    vuln_mgmt_plan = os.path.exists("/etc/security/vulnerability-management")
    
    if vuln_mgmt_plan:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Pass",
            message="PR.IP-12: Vulnerability management plan exists",
            details="Vulnerability management process documented",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Info Protection)",
            status="Info",
            message="PR.IP-12: Vulnerability management plan not found",
            details="Document vulnerability management process",
            remediation="Create /etc/security/vulnerability-management with VM procedures"
        ))

def check_maintenance(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST PR.MA - Maintenance
    Maintenance and repairs of industrial control and information system components performed
    Maps to: NIST SP 800-53 MA series (Maintenance)
    """
    print(f"[{MODULE_NAME}] Checking maintenance (PR.MA)...")
    
    # PR.MA-1: Maintenance and repair performed and logged
    # Check for maintenance logging
    if os.path.exists("/var/log/maintenance") or os.path.exists("/etc/security/maintenance-log"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Maintenance)",
            status="Pass",
            message="PR.MA-1: Maintenance logging configured",
            details="Maintenance and repair activities are logged",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Maintenance)",
            status="Info",
            message="PR.MA-1: Maintenance logging not configured",
            details="Establish maintenance logging procedures",
            remediation="Create /var/log/maintenance for tracking maintenance activities"
        ))
    
    # PR.MA-2: Remote maintenance approved, logged, and performed securely
    # SSH already checked in PR.AC-3, verify remote access logging
    if check_service_active("auditd"):
        # Check if SSH connections are being audited
        audit_rules = run_command("auditctl -l 2>/dev/null | grep -i ssh")
        if audit_rules.returncode == 0:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Maintenance)",
                status="Pass",
                message="PR.MA-2: Remote maintenance auditing configured",
                details="SSH remote access is being audited",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Maintenance)",
                status="Info",
                message="PR.MA-2: Remote maintenance auditing not configured",
                details="Add SSH auditing rules to auditd",
                remediation="Add SSH audit rules: auditctl -w /usr/sbin/sshd -p x -k remote_access"
            ))

def check_protective_technology(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST PR.PT - Protective Technology
    Technical security solutions managed to ensure security and resilience
    Maps to: NIST SP 800-53 various technical controls
    """
    print(f"[{MODULE_NAME}] Checking protective technology (PR.PT)...")
    
    # PR.PT-1: Audit/log records determined, documented, implemented, reviewed
    logging_services = ["rsyslog", "syslog-ng", "systemd-journald"]
    active_logging = []
    
    for service in logging_services:
        if check_service_active(service):
            active_logging.append(service)
    
    if active_logging:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Protective Tech)",
            status="Pass",
            message="PR.PT-1: System logging is active",
            details=f"Active logging: {', '.join(active_logging)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Protective Tech)",
            status="Fail",
            message="PR.PT-1: No active logging service detected",
            details="Enable rsyslog or systemd-journald",
            remediation="sudo systemctl enable --now rsyslog"
        ))
    
    # PR.PT-2: Removable media is protected and its use restricted
    if check_package_installed("usbguard"):
        if check_service_active("usbguard"):
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Protective Tech)",
                status="Pass",
                message="PR.PT-2: USB device protection active",
                details="USBGuard service is running",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Protective Tech)",
                status="Warning",
                message="PR.PT-2: USB protection installed but inactive",
                details="USBGuard is installed but not running",
                remediation="sudo systemctl enable --now usbguard"
            ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Protective Tech)",
            status="Info",
            message="PR.PT-2: No USB protection mechanism detected",
            details="Consider USBGuard for removable media control",
            remediation="sudo apt-get install usbguard || sudo yum install usbguard"
        ))
    
    # PR.PT-3: Principle of least functionality incorporated
    # Count enabled services
    all_services = run_command("systemctl list-unit-files --type=service --state=enabled 2>/dev/null | grep -v '^UNIT' | wc -l")
    
    if all_services.returncode == 0:
        service_count = int(all_services.stdout.strip()) if all_services.stdout.strip().isdigit() else 0
        
        if service_count < 50:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Protective Tech)",
                status="Pass",
                message="PR.PT-3: Minimal services configuration",
                details=f"{service_count} enabled services indicates least functionality",
                remediation=""
            ))
        elif service_count < 100:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Protective Tech)",
                status="Info",
                message="PR.PT-3: Review enabled services",
                details=f"{service_count} services enabled - review and disable unnecessary ones",
                remediation="Use 'systemctl list-unit-files --type=service --state=enabled' to review"
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Protect (Protective Tech)",
                status="Warning",
                message="PR.PT-3: Many services enabled",
                details=f"{service_count} services enabled - reduce attack surface",
                remediation="Disable unnecessary services to follow least functionality principle"
            ))
    
    # PR.PT-4: Communications and control networks are protected
    # Network hardening parameters
    network_params = [
        ("net.ipv4.conf.all.rp_filter", "1"),
        ("net.ipv4.tcp_syncookies", "1"),
        ("net.ipv4.conf.all.accept_source_route", "0"),
        ("net.ipv4.icmp_echo_ignore_broadcasts", "1")
    ]
    
    all_configured = True
    misconfigured = []
    
    for param, expected in network_params:
        found, value = check_kernel_parameter(param)
        if not found or value != expected:
            all_configured = False
            misconfigured.append(param)
    
    if all_configured:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Protective Tech)",
            status="Pass",
            message="PR.PT-4: Network hardening parameters configured",
            details="All network protection parameters properly set",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Protective Tech)",
            status="Warning",
            message="PR.PT-4: Network hardening incomplete",
            details=f"Review: {', '.join(misconfigured)}",
            remediation="Configure sysctl parameters for network protection"
        ))
    
    # PR.PT-5: Mechanisms implemented to achieve resilience requirements
    # Backup solutions already checked in PR.IP-4
    # Check for redundancy/HA
    ha_found = any(check_package_installed(pkg) for pkg in ["pacemaker", "keepalived", "haproxy"])
    
    if ha_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Protect (Protective Tech)",
            status="Pass",
            message="PR.PT-5: Resilience mechanisms detected",
            details="High availability components installed",
            remediation=""
        ))

# ============================================================================
# DETECT (DE), RESPOND (RS), RECOVER (RC) Functions
# ============================================================================

def check_anomalies_and_events(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST DE.AE - Anomalies and Events
    Anomalous activity detected and impact understood
    Maps to: NIST SP 800-53 AU-6, SI-4
    """
    print(f"[{MODULE_NAME}] Checking anomaly detection (DE.AE)...")
    
    # DE.AE-1: Baseline of network operations established
    netmon_tools = ["iftop", "nethogs", "iptraf-ng", "vnstat"]
    available_netmon = [tool for tool in netmon_tools if command_exists(tool)]
    
    if available_netmon:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Anomalies)",
            status="Pass",
            message="DE.AE-1: Network monitoring tools available",
            details=f"Baseline capability: {', '.join(available_netmon)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Anomalies)",
            status="Info",
            message="DE.AE-1: Network monitoring tools not found",
            details="Install network monitoring for baseline establishment",
            remediation="sudo apt-get install vnstat iftop || sudo yum install vnstat iftop"
        ))
    
    # DE.AE-2: Detected events analyzed
    ids_systems = [
        ("snort", "Network IDS"),
        ("suricata", "Network IDS/IPS"),
        ("aide", "Host IDS"),
        ("ossec", "Host IDS"),
        ("fail2ban", "Intrusion prevention")
    ]
    
    ids_found = []
    for system, description in ids_systems:
        if check_package_installed(system) or check_service_active(system):
            ids_found.append(f"{system} ({description})")
    
    if ids_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Anomalies)",
            status="Pass",
            message="DE.AE-2: Intrusion detection system present",
            details=f"Event analysis: {', '.join(ids_found)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Anomalies)",
            status="Warning",
            message="DE.AE-2: No intrusion detection system found",
            details="Install IDS/IPS for event analysis",
            remediation="sudo apt-get install fail2ban aide || sudo yum install fail2ban aide"
        ))
    
    # DE.AE-3: Event data collected and correlated
    if check_service_active("rsyslog"):
        rsyslog_conf = read_file_safe("/etc/rsyslog.conf")
        remote_logging = "@" in rsyslog_conf or 'action(type="omfwd"' in rsyslog_conf
        
        if remote_logging:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Detect (Anomalies)",
                status="Pass",
                message="DE.AE-3: Centralized logging configured",
                details="Remote log forwarding detected",
                remediation=""
            ))
        else:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Detect (Anomalies)",
                status="Info",
                message="DE.AE-3: Local logging only",
                details="Consider centralized logging for event correlation",
                remediation="Configure rsyslog to forward logs: *.* @logserver:514"
            ))
    
    # DE.AE-4: Impact of events determined
    # DE.AE-5: Incident alert thresholds established
    if check_service_active("fail2ban"):
        fail2ban_conf = read_file_safe("/etc/fail2ban/jail.local")
        if not fail2ban_conf:
            fail2ban_conf = read_file_safe("/etc/fail2ban/jail.conf")
        
        maxretry = re.search(r'maxretry\s*=\s*(\d+)', fail2ban_conf)
        
        if maxretry:
            results.append(AuditResult(
                module=MODULE_NAME,
                category="NIST - Detect (Anomalies)",
                status="Pass",
                message="DE.AE-4/5: Alert thresholds configured",
                details=f"fail2ban maxretry set to {maxretry.group(1)}",
                remediation=""
            ))

def check_continuous_monitoring(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST DE.CM - Security Continuous Monitoring
    Information system and assets monitored to identify events
    Maps to: NIST SP 800-53 SI-4, CA-7, AU-6
    """
    print(f"[{MODULE_NAME}] Checking continuous monitoring (DE.CM)...")
    
    # DE.CM-1: Network monitored for cybersecurity events
    if check_service_active("auditd"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Monitoring)",
            status="Pass",
            message="DE.CM-1: System auditing is active",
            details="auditd provides continuous system monitoring",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Monitoring)",
            status="Fail",
            message="DE.CM-1: System auditing is not active",
            details="Enable auditd for security monitoring",
            remediation="sudo systemctl enable --now auditd"
        ))
    
    # DE.CM-2: Physical environment monitored
    # DE.CM-3: Personnel activity monitored
    if os.path.exists("/var/log/auth.log") or os.path.exists("/var/log/secure"):
        log_file = "/var/log/auth.log" if os.path.exists("/var/log/auth.log") else "/var/log/secure"
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Monitoring)",
            status="Pass",
            message="DE.CM-3: User authentication logging active",
            details=f"Personnel activity logged in {log_file}",
            remediation=""
        ))
    
    # DE.CM-4: Malicious code detected
    av_solutions = [
        ("clamav", "ClamAV antivirus"),
        ("rkhunter", "Rootkit hunter"),
        ("chkrootkit", "Rootkit checker")
    ]
    
    av_found = []
    for av, description in av_solutions:
        if check_package_installed(av):
            av_found.append(f"{av} ({description})")
    
    if av_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Monitoring)",
            status="Pass",
            message="DE.CM-4: Malware detection installed",
            details=f"Detection: {', '.join(av_found)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Monitoring)",
            status="Warning",
            message="DE.CM-4: No malware detection found",
            details="Install antivirus/antimalware solution",
            remediation="sudo apt-get install clamav clamav-daemon rkhunter || sudo yum install clamav rkhunter"
        ))
    
    # DE.CM-5: Unauthorized mobile code detected
    # DE.CM-6: External service provider activity monitored
    # DE.CM-7: Monitoring for unauthorized personnel, connections, devices, software
    if check_package_installed("aide"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Monitoring)",
            status="Pass",
            message="DE.CM-7: File integrity monitoring available",
            details="AIDE provides monitoring for unauthorized changes",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Monitoring)",
            status="Info",
            message="DE.CM-7: File integrity monitoring not installed",
            details="Install AIDE for detecting unauthorized changes",
            remediation="sudo apt-get install aide && sudo aideinit"
        ))
    
    # DE.CM-8: Vulnerability scans performed
    vuln_scanners = ["lynis", "openvas", "nmap"]
    scanners_found = [tool for tool in vuln_scanners if command_exists(tool)]
    
    if scanners_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Monitoring)",
            status="Pass",
            message="DE.CM-8: Vulnerability scanning tools available",
            details=f"Scanners: {', '.join(scanners_found)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Monitoring)",
            status="Info",
            message="DE.CM-8: No vulnerability scanners detected",
            details="Install vulnerability scanning tools",
            remediation="sudo apt-get install lynis nmap || sudo yum install lynis nmap"
        ))

def check_detection_processes(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST DE.DP - Detection Processes
    Detection processes and procedures maintained and tested
    Maps to: NIST SP 800-53 IR-4, AU-6
    """
    print(f"[{MODULE_NAME}] Checking detection processes (DE.DP)...")
    
    # DE.DP-1: Roles and responsibilities for detection defined
    if os.path.exists("/etc/security/detection-roles"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Detect (Processes)",
            status="Pass",
            message="DE.DP-1: Detection roles documented",
            details="Detection responsibilities defined",
            remediation=""
        ))
    
    # DE.DP-2: Detection activities comply with requirements
    # DE.DP-3: Detection processes tested
    # DE.DP-4: Event detection information communicated
    # DE.DP-5: Detection processes continuously improved

def check_response_planning(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST RS.RP/RS.CO/RS.AN/RS.MI/RS.IM - Response activities
    Response processes and procedures executed and maintained
    Maps to: NIST SP 800-53 IR series (Incident Response)
    """
    print(f"[{MODULE_NAME}] Checking response capabilities (RS)...")
    
    # RS.RP-1: Response plan is executed
    ir_docs = [
        "/etc/security/incident-response.txt",
        "/etc/security/ir-plan"
    ]
    
    ir_found = any(os.path.exists(doc) for doc in ir_docs)
    
    if ir_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Respond",
            status="Pass",
            message="RS.RP-1: Incident response plan exists",
            details="Response plan documentation found",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Respond",
            status="Info",
            message="RS.RP-1: Incident response plan not found",
            details="Create and document incident response plan",
            remediation="Create /etc/security/incident-response.txt with IR procedures"
        ))
    
    # RS.AN-1: Notifications investigated
    # RS.MI-3: Newly identified vulnerabilities mitigated or documented
    update_services = ["unattended-upgrades", "dnf-automatic", "yum-cron"]
    update_found = [svc for svc in update_services if check_package_installed(svc)]
    
    if update_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Respond",
            status="Pass",
            message="RS.MI-3: Automatic updates configured",
            details=f"Update service: {', '.join(update_found)}",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Respond",
            status="Warning",
            message="RS.MI-3: No automatic updates configured",
            details="Configure automatic security updates",
            remediation="sudo apt-get install unattended-upgrades || sudo yum install dnf-automatic"
        ))

def check_recovery_planning(results: List[AuditResult], shared_data: Dict[str, Any]):
    """
    NIST RC.RP/RC.IM/RC.CO - Recovery activities
    Recovery processes and procedures executed and maintained
    Maps to: NIST SP 800-53 CP series (Contingency Planning)
    """
    print(f"[{MODULE_NAME}] Checking recovery capabilities (RC)...")
    
    # RC.RP-1: Recovery plan executed
    recovery_docs = [
        "/etc/security/recovery-plan",
        "/etc/security/drp",
        "/etc/security/disaster-recovery.txt"
    ]
    
    recovery_found = any(os.path.exists(doc) for doc in recovery_docs)
    
    if recovery_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Recover",
            status="Pass",
            message="RC.RP-1: Recovery plan documentation exists",
            details="Disaster recovery plan documented",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Recover",
            status="Info",
            message="RC.RP-1: Recovery plan not found",
            details="Create and document recovery plan",
            remediation="Create /etc/security/recovery-plan with DRP procedures"
        ))
    
    # RC.RP-1: Recovery capability
    backup_found = any(command_exists(tool) for tool in ["restic", "borgbackup", "tar", "rsync"])
    
    if backup_found:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Recover",
            status="Pass",
            message="RC.RP-1: Recovery capability available",
            details="Backup/restore tools present for recovery",
            remediation=""
        ))
    else:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Recover",
            status="Warning",
            message="RC.RP-1: Limited recovery capability",
            details="Install backup tools for recovery operations",
            remediation="sudo apt-get install restic || sudo yum install restic"
        ))
    
    # RC.IM-1/2: Recovery plans incorporate lessons learned
    if os.path.exists("/etc/security/lessons-learned"):
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Recover",
            status="Pass",
            message="RC.IM-1: Lessons learned documentation exists",
            details="Recovery improvement tracking in place",
            remediation=""
        ))

# ============================================================================
# Main Module Entry Point
# ============================================================================

def run_checks(shared_data: Dict[str, Any]) -> List[AuditResult]:
    """
    Main entry point for NIST Cybersecurity Framework module
    
    Args:
        shared_data: Dictionary with shared data
        
    Returns:
        List of AuditResult objects
    """
    results = []
    
    print(f"\n[{MODULE_NAME}] Starting NIST Cybersecurity Framework checks...")
    print(f"[{MODULE_NAME}] Framework: NIST CSF 1.1/2.0, SP 800-53 Rev 5, SP 800-171 Rev 2")
    
    try:
        # IDENTIFY Function
        check_asset_management(results, shared_data)
        check_business_environment(results, shared_data)
        check_governance(results, shared_data)
        check_risk_assessment(results, shared_data)
        check_risk_management_strategy(results, shared_data)
        check_supply_chain_risk_management(results, shared_data)
        
        # PROTECT Function
        check_access_control(results, shared_data)
        check_awareness_training(results, shared_data)
        check_data_security(results, shared_data)
        check_information_protection_processes(results, shared_data)
        check_maintenance(results, shared_data)
        check_protective_technology(results, shared_data)
        
        # DETECT Function
        check_anomalies_and_events(results, shared_data)
        check_continuous_monitoring(results, shared_data)
        check_detection_processes(results, shared_data)
        
        # RESPOND Function
        check_response_planning(results, shared_data)
        
        # RECOVER Function
        check_recovery_planning(results, shared_data)
        
    except Exception as e:
        results.append(AuditResult(
            module=MODULE_NAME,
            category="NIST - Error",
            status="Error",
            message=f"Module execution error: {str(e)}"
        ))
        import traceback
        traceback.print_exc()
    
    print(f"[{MODULE_NAME}] NIST Cybersecurity Framework checks completed - {len(results)} checks performed")
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
