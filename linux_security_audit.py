#!/usr/bin/env python3
"""
linux_security_audit.py
Comprehensive Linux Security Audit Script
Version: 1.1
GitHub: https://github.com/Sandler73/Linux-Security-Audit-Project.git

SYNOPSIS:
    Comprehensive module-based Linux security audit script supporting multiple compliance frameworks.

DESCRIPTION:
    This script audits Linux systems against multiple security frameworks including:
    - Core Security (baseline checks)
    - CIS Benchmarks
    - CISA Best Practices
    - DISA STIGs
    - ENISA Cybersecurity Guidelines
    - ISO/IEC 27001 Information Security Management
    - NIST Cybersecurity Framework
    - NSA Cybersecurity Guidance
    
    Features:
    - Multi-format output (HTML, CSV, JSON, XML, Console)
    - Interactive HTML reports with filtering, sorting, and export
    - Automated and interactive remediation
    - Selective issue remediation from exported JSON
    - Dark/Light theme support in HTML reports
    - Comprehensive logging and statistics

PARAMETERS:
    --modules, -m          : Comma-separated list of modules (Core,CIS,NIST,STIG,NSA,CISA,All)
    --output-format, -f    : Output format (HTML,CSV,JSON,XML,Console)
    --output-path, -o      : Path for output file
    --remediate            : Interactively remediate failed checks
    --remediate-fail       : Remediate only FAIL status issues
    --remediate-warning    : Remediate only WARNING status issues
    --remediate-info       : Remediate only INFO status issues
    --auto-remediate       : Automatically remediate without prompting
    --remediation-file     : JSON file with specific issues to remediate

EXAMPLES:
    python3 linux_security_audit.py
        Run all modules with default HTML output
    
    python3 linux_security_audit.py -m Core,NIST,CISA -f CSV
        Run specific modules and output to CSV
    
    python3 linux_security_audit.py -f XML
        Generate XML report suitable for SIEM ingestion
    
    python3 linux_security_audit.py --remediate-fail --auto-remediate
        Automatically remediate all FAIL status issues with safety confirmations
    
    python3 linux_security_audit.py --auto-remediate --remediation-file selected-issues.json
        Automatically remediate only specific issues from exported JSON file

NOTES:
    Requires: Linux (Ubuntu/Debian/RHEL/CentOS/Fedora), Python 3.6+
    Run with sudo/root for complete results and remediation capabilities
    
    REMEDIATION WORKFLOW:
    1. Run audit: python3 linux_security_audit.py
    2. Review HTML report and select specific issues to fix
    3. Export selected issues to JSON using "Export Selected" button
    4. Run auto-remediation: python3 linux_security_audit.py --auto-remediate --remediation-file Selected-Report.json
"""

import os
import sys
import json
import csv
import argparse
import subprocess
import platform
import socket
import datetime
import time
import html
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Tuple
from dataclasses import dataclass, asdict, field

# ============================================================================
# Configuration
# ============================================================================
SCRIPT_VERSION = "1.0"
SCRIPT_PATH = Path(__file__).parent.absolute()
VALID_STATUS_VALUES = ["Pass", "Fail", "Warning", "Info", "Error"]

# ============================================================================
# Data Classes
# ============================================================================
@dataclass
class AuditResult:
    """Represents a single audit check result"""
    module: str
    category: str
    status: str
    message: str
    details: str = ""
    remediation: str = ""
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)
    
    def validate(self) -> Tuple[bool, List[str]]:
        """Validate the result object"""
        issues = []
        
        if not self.module:
            issues.append("Missing: module")
        if not self.category:
            issues.append("Missing: category")
        if not self.message:
            issues.append("Missing: message")
        if not self.status:
            issues.append("Missing: status")
        elif self.status not in VALID_STATUS_VALUES:
            issues.append(f"Invalid Status: '{self.status}'")
        
        return len(issues) == 0, issues

@dataclass
class ExecutionInfo:
    """Information about the audit execution"""
    hostname: str
    os_version: str
    scan_date: str
    duration: str
    modules_run: List[str]
    total_checks: int
    pass_count: int
    fail_count: int
    warning_count: int
    info_count: int
    error_count: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)

@dataclass
class ModuleStatistics:
    """Statistics for a single module"""
    total: int
    passed: int
    failed: int
    warnings: int
    info: int
    errors: int

class Statistics:
    """Global statistics tracker"""
    def __init__(self):
        self.validation_issues: List[Dict[str, Any]] = []
        self.normalized_results: int = 0
        self.module_stats: Dict[str, ModuleStatistics] = {}
    
    def add_validation_issue(self, module: str, issues: List[str]):
        """Add validation issues"""
        self.validation_issues.append({
            "module": module,
            "issues": "; ".join(issues),
            "timestamp": datetime.datetime.now().isoformat()
        })
    
    def increment_normalized(self):
        """Increment normalized results counter"""
        self.normalized_results += 1

# Global statistics instance
statistics = Statistics()

# ============================================================================
# Color Output Functions
# ============================================================================
class Colors:
    """ANSI color codes for terminal output"""
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    GRAY = '\033[90m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def print_colored(text: str, color: str = Colors.WHITE, bold: bool = False):
    """Print colored text to console"""
    style = Colors.BOLD if bold else ""
    print(f"{style}{color}{text}{Colors.RESET}")

def print_banner():
    """Display the script banner"""
    print()
    print_colored("=" * 100, Colors.CYAN)
    print_colored(f"                     Linux Security Audit Script v{SCRIPT_VERSION}", Colors.CYAN)
    print_colored("                  Comprehensive Multi-Framework Security Assessment", Colors.CYAN)
    print_colored("=" * 100, Colors.CYAN)
    print_colored("\nSupported Frameworks:", Colors.WHITE, bold=True)
    print_colored("  - Core Security Baseline", Colors.GRAY)
    print_colored("  - CIS Benchmarks", Colors.GRAY)
    print_colored("  - CISA Best Practices", Colors.GRAY)
    print_colored("  - DISA STIGs", Colors.GRAY)
    print_colored("  - ENISA Cybersecurity Guidelines", Colors.GRAY)
    print_colored("  - ISO/IEC 27001 Information Security Management", Colors.GRAY)
    print_colored("  - NIST Cybersecurity Framework", Colors.GRAY)
    print_colored("  - NSA Cybersecurity Guidance", Colors.GRAY)
    print_colored("\n" + "=" * 100 + "\n", Colors.CYAN)

# ============================================================================
# Prerequisites Check
# ============================================================================
def check_prerequisites(require_root: bool = False) -> Tuple[bool, bool]:
    """
    Check system prerequisites
    
    Args:
        require_root: If True, return False when not running as root
        
    Returns:
        Tuple of (prerequisites_met: bool, is_root: bool)
    """
    print_colored("[*] Checking prerequisites...", Colors.YELLOW)
    
    # Check Python version
    py_version = sys.version_info
    if py_version.major < 3 or (py_version.major == 3 and py_version.minor < 6):
        print_colored(f"[!] Python 3.6+ required. Current: {py_version.major}.{py_version.minor}", Colors.RED)
        return False, False
    print_colored(f"[+] Python version: {py_version.major}.{py_version.minor}.{py_version.micro}", Colors.GREEN)
    
    # Check if running as root
    is_root = os.geteuid() == 0
    if not is_root:
        print_colored("[!] INFO: Not running as root/sudo", Colors.CYAN)
        print_colored("    Some checks may be limited or unavailable", Colors.CYAN)
        print_colored("    Remediation features will be disabled", Colors.CYAN)
        if require_root:
            print_colored("[!] ERROR: Remediation requires root privileges", Colors.RED)
            print_colored("    Run with: sudo python3 linux_security_audit.py --remediate", Colors.YELLOW)
            return False, False
    else:
        print_colored("[+] Running with root privileges", Colors.GREEN)
        print_colored("    All checks and remediation available", Colors.GREEN)
    
    # Check OS
    os_info = f"{platform.system()} {platform.release()}"
    print_colored(f"[+] Operating System: {os_info}", Colors.GREEN)
    
    # Check for required commands
    required_commands = ['grep', 'awk']  # Basic commands
    recommended_commands = ['systemctl', 'ss', 'netstat']  # Useful but not critical
    
    missing_required = []
    missing_recommended = []
    
    for cmd in required_commands:
        if not which(cmd):
            missing_required.append(cmd)
    
    for cmd in recommended_commands:
        if not which(cmd):
            missing_recommended.append(cmd)
    
    if missing_required:
        print_colored(f"[!] ERROR: Missing required commands: {', '.join(missing_required)}", Colors.RED)
        return False, is_root
    
    if missing_recommended:
        print_colored(f"[!] INFO: Missing recommended commands: {', '.join(missing_recommended)}", Colors.CYAN)
        print_colored("    Some checks may be skipped", Colors.CYAN)
    
    return True, is_root

def which(command: str) -> Optional[str]:
    """Check if command exists (like 'which' command)"""
    try:
        result = subprocess.run(['which', command], capture_output=True, text=True)
        return result.stdout.strip() if result.returncode == 0 else None
    except:
        return None

# ============================================================================
# Result Validation and Normalization
# ============================================================================
def validate_result(result: AuditResult, module_name: str) -> bool:
    """Validate a result object"""
    is_valid, issues = result.validate()
    
    if not is_valid:
        statistics.add_validation_issue(module_name, issues)
    
    return is_valid

def normalize_result(result: AuditResult, module_name: str) -> AuditResult:
    """Normalize and repair a result object"""
    normalized = False
    
    # Ensure module exists
    if not result.module:
        result.module = module_name
        normalized = True
    
    # Ensure category exists
    if not result.category:
        result.category = "Uncategorized"
        normalized = True
    
    # Ensure message exists
    if not result.message:
        result.message = "No message"
        normalized = True
    
    # Normalize status value (case-insensitive matching)
    if result.status:
        matched_status = None
        for valid_status in VALID_STATUS_VALUES:
            if result.status.lower() == valid_status.lower():
                matched_status = valid_status
                break
        
        if matched_status and result.status != matched_status:
            result.status = matched_status
            normalized = True
        elif not matched_status:
            result.status = "Error"
            normalized = True
    else:
        result.status = "Error"
        normalized = True
    
    if normalized:
        statistics.increment_normalized()
    
    return result

def get_validated_results(results: List[AuditResult], module_name: str) -> List[AuditResult]:
    """Validate and normalize a list of results"""
    if not results:
        print_colored(f"[!] Module {module_name} returned no results", Colors.YELLOW)
        return []
    
    validated_results = []
    for result in results:
        if validate_result(result, module_name):
            validated_results.append(result)
        else:
            repaired_result = normalize_result(result, module_name)
            if validate_result(repaired_result, module_name):
                validated_results.append(repaired_result)
    
    return validated_results

# ============================================================================
# Module Statistics
# ============================================================================
def calculate_module_statistics(results: List[AuditResult]) -> ModuleStatistics:
    """Calculate statistics for a module's results"""
    return ModuleStatistics(
        total=len(results),
        passed=sum(1 for r in results if r.status == "Pass"),
        failed=sum(1 for r in results if r.status == "Fail"),
        warnings=sum(1 for r in results if r.status == "Warning"),
        info=sum(1 for r in results if r.status == "Info"),
        errors=sum(1 for r in results if r.status == "Error")
    )

# ============================================================================
# Module Management
# ============================================================================
def get_available_modules() -> Dict[str, Path]:
    """
    Dynamically discover and return available modules from the modules directory
    
    Scans the modules/ directory for Python files that follow the module pattern:
    - Filename: module_*.py
    - Contains: run_checks() function
    - Contains: MODULE_NAME variable
    
    Returns:
        Dictionary mapping module names to their file paths
    """
    modules_dir = SCRIPT_PATH / "modules"
    available_modules = {}
    
    if not modules_dir.exists():
        print_colored(f"[!] WARNING: Modules directory not found: {modules_dir}", Colors.YELLOW)
        return available_modules
    
    # Scan for module files
    module_files = sorted(modules_dir.glob("module_*.py"))
    
    for module_file in module_files:
        # Extract module name from filename (e.g., module_core.py -> Core)
        module_name_raw = module_file.stem.replace("module_", "")
        module_name = module_name_raw.title()  # Capitalize first letter
        
        # Special case for acronyms/uppercase module names
        if module_name_raw.upper() in ['CIS', 'NIST', 'STIG', 'NSA', 'CISA', 'ENISA']:
            module_name = module_name_raw.upper()
        elif module_name_raw.lower() == 'iso27001':
            module_name = 'ISO27001'
        
        # Validate module has required structure
        try:
            # Quick validation: check if file contains required elements
            with open(module_file, 'r', encoding='utf-8') as f:
                content = f.read()
                if 'def run_checks(' in content:
                    available_modules[module_name] = module_file
                else:
                    print_colored(f"[!] WARNING: Skipping {module_file.name} - missing run_checks() function", Colors.YELLOW)
        except Exception as e:
            print_colored(f"[!] WARNING: Could not validate module {module_file.name}: {e}", Colors.YELLOW)
    
    return available_modules

def list_available_modules():
    """List all available modules to the console"""
    modules = get_available_modules()
    
    if not modules:
        print_colored("[!] No modules found in modules/ directory", Colors.YELLOW)
        return
    
    print_colored("\n[*] Available Modules:", Colors.CYAN, bold=True)
    for module_name, module_path in sorted(modules.items()):
        # Try to read module docstring for description
        try:
            with open(module_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                description = "No description available"
                
                # Look for SYNOPSIS in docstring
                in_docstring = False
                for line in lines[:50]:  # Check first 50 lines
                    if '"""' in line or "'''" in line:
                        in_docstring = not in_docstring
                    elif in_docstring and 'SYNOPSIS' in line.upper():
                        # Get next non-empty line
                        idx = lines.index(line)
                        for next_line in lines[idx+1:idx+5]:
                            desc = next_line.strip()
                            if desc and not desc.startswith('"""') and not desc.startswith("'''"):
                                description = desc
                                break
                        break
                
                print_colored(f"  • {module_name.ljust(12)} - {description}", Colors.WHITE)
        except:
            print_colored(f"  • {module_name}", Colors.WHITE)
    
    print_colored(f"\nTotal modules found: {len(modules)}\n", Colors.CYAN)

def check_module_exists(module_name: str) -> bool:
    """Check if a module file exists"""
    available_modules = get_available_modules()
    if module_name not in available_modules:
        return False
    
    module_path = available_modules[module_name]
    return module_path.exists()

def execute_security_module(module_name: str, shared_data: Dict[str, Any]) -> List[AuditResult]:
    """Execute a security audit module"""
    available_modules = get_available_modules()
    module_path = available_modules.get(module_name)
    
    if not module_path or not module_path.exists():
        print_colored(f"[!] Module not found: {module_name}", Colors.RED)
        return []
    
    try:
        print_colored(f"\n[*] Executing module: {module_name}", Colors.CYAN)
        
        # Import and execute the module
        import importlib.util
        spec = importlib.util.spec_from_file_location(f"module_{module_name.lower()}", module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        # Call the module's main function
        if hasattr(module, 'run_checks'):
            results = module.run_checks(shared_data)
        else:
            print_colored(f"[!] Module {module_name} missing run_checks function", Colors.RED)
            return []
        
        # Validate and normalize results
        validated_results = get_validated_results(results, module_name)
        
        # Calculate and display module statistics
        stats = calculate_module_statistics(validated_results)
        statistics.module_stats[module_name] = stats
        
        print_colored(f"[+] Module {module_name} completed: {stats.total} checks", Colors.GREEN)
        print_colored(f"    Pass: {stats.passed} | Fail: {stats.failed} | Warning: {stats.warnings} | Info: {stats.info} | Error: {stats.errors}", Colors.GRAY)
        
        return validated_results
        
    except Exception as e:
        print_colored(f"[!] Error executing module {module_name}: {e}", Colors.RED)
        import traceback
        traceback.print_exc()
        return []

# ============================================================================
# Remediation Functions
# ============================================================================
def invoke_remediation(results: List[AuditResult], args: argparse.Namespace):
    """Handle remediation of issues"""
    auto_mode = args.auto_remediate
    remediate_all = args.remediate
    remediate_fail = args.remediate_fail
    remediate_warning = args.remediate_warning
    remediate_info = args.remediate_info
    remediation_file = args.remediation_file
    
    print_colored("\n" + "=" * 100, Colors.YELLOW)
    print_colored("                                REMEDIATION MODE", Colors.YELLOW, bold=True)
    print_colored("=" * 100, Colors.YELLOW)
    
    remediable_results = []
    
    # Check if using remediation file
    if remediation_file:
        if not os.path.exists(remediation_file):
            print_colored(f"[!] ERROR: Remediation file not found: {remediation_file}", Colors.RED)
            print_colored("=" * 100 + "\n", Colors.YELLOW)
            return
        
        try:
            with open(remediation_file, 'r') as f:
                remediation_data = json.load(f)
            
            if 'modules' not in remediation_data:
                print_colored("[!] ERROR: Invalid remediation file format. Expected 'modules' array.", Colors.RED)
                print_colored("=" * 100 + "\n", Colors.YELLOW)
                return
            
            # Match results from remediation file
            targeted_checks = []
            for module_data in remediation_data['modules']:
                module_name = module_data['moduleName']
                for result_data in module_data['results']:
                    for result in results:
                        if (result.module == module_name and
                            result.category == result_data.get('Category') and
                            result.message == result_data.get('Finding') and
                            result.remediation):
                            targeted_checks.append(result)
                            break
            
            if not targeted_checks:
                print_colored("[!] No matching remediable issues found in remediation file.", Colors.YELLOW)
                print_colored("=" * 100 + "\n", Colors.YELLOW)
                return
            
            print_colored(f"[*] Found {len(targeted_checks)} targeted issue(s) to remediate", Colors.CYAN)
            remediable_results = targeted_checks
            
        except Exception as e:
            print_colored(f"[!] ERROR: Failed to parse remediation file: {e}", Colors.RED)
            print_colored("=" * 100 + "\n", Colors.YELLOW)
            return
    else:
        # Standard mode - filter by status
        statuses_to_remediate = []
        if remediate_all:
            statuses_to_remediate = ["Fail", "Warning", "Info"]
            print_colored("[*] Mode: Remediate ALL issues (Fail, Warning, Info)", Colors.CYAN)
        else:
            if remediate_fail:
                statuses_to_remediate.append("Fail")
            if remediate_warning:
                statuses_to_remediate.append("Warning")
            if remediate_info:
                statuses_to_remediate.append("Info")
            print_colored(f"[*] Mode: Remediate {', '.join(statuses_to_remediate)} issues only", Colors.CYAN)
        
        remediable_results = [r for r in results if r.status in statuses_to_remediate and r.remediation]
        
        if not remediable_results:
            print_colored("\n[*] No remediable issues found for selected status types.", Colors.CYAN)
            print_colored("=" * 100 + "\n", Colors.YELLOW)
            return
        
        print_colored(f"[*] Found {len(remediable_results)} issue(s) with remediation available", Colors.YELLOW)
    
    # Auto-remediation safety confirmation
    if auto_mode:
        print_colored("\n+" + "-" * 98 + "+", Colors.RED)
        print_colored("|" + " " * 34 + "WARNING - AUTO-REMEDIATION" + " " * 37 + "|", Colors.RED)
        print_colored("+" + "-" * 98 + "+", Colors.RED)
        print_colored("|" + " " * 98 + "|", Colors.RED)
        print_colored(f"| This will automatically apply {str(len(remediable_results)).ljust(3)} remediation(s) WITHOUT prompting for each one." + " " * (98 - 76 - len(str(len(remediable_results)))) + "|", Colors.RED)
        print_colored("|" + " " * 98 + "|", Colors.RED)
        print_colored("| RISKS:" + " " * 91 + "|", Colors.RED)
        print_colored("| - System configuration will be modified automatically" + " " * 44 + "|", Colors.RED)
        print_colored("| - Changes may affect system functionality or applications" + " " * 39 + "|", Colors.RED)
        print_colored("| - Some changes may require system restart" + " " * 56 + "|", Colors.RED)
        print_colored("| - Automated remediation may have unintended consequences" + " " * 41 + "|", Colors.RED)
        print_colored("|" + " " * 98 + "|", Colors.RED)
        print_colored("| RECOMMENDATION: Review each remediation in interactive mode first" + " " * 31 + "|", Colors.RED)
        print_colored("|" + " " * 98 + "|", Colors.RED)
        print_colored("+" + "-" * 98 + "+", Colors.RED)
        print()
        
        print_colored("Issues to be remediated:", Colors.YELLOW)
        for result in remediable_results:
            print_colored(f"  - [{result.status}] {result.module} - {result.message}", Colors.GRAY)
        print()
        
        # First confirmation
        first_confirm = input(print_colored("Do you want to proceed with AUTO-REMEDIATION? Type 'YES' to continue: ", Colors.YELLOW, bold=True) or "")
        
        if first_confirm != 'YES':
            print_colored("\n[*] Auto-remediation cancelled by user.", Colors.YELLOW)
            print_colored("=" * 100 + "\n", Colors.YELLOW)
            return
        
        # Second confirmation with countdown
        print_colored("\nFinal confirmation required. Type 'CONFIRM' within 10 seconds to proceed: ", Colors.RED, bold=True, end='')
        import select
        
        timeout = 10
        start_time = time.time()
        second_confirm = None
        
        # Platform-specific input with timeout
        if sys.platform != 'win32':
            i, o, e = select.select([sys.stdin], [], [], timeout)
            if i:
                second_confirm = sys.stdin.readline().strip()
        else:
            # Windows fallback (no timeout)
            second_confirm = input()
        
        if second_confirm != 'CONFIRM':
            print_colored("\n[*] Auto-remediation cancelled (timeout or incorrect confirmation).", Colors.YELLOW)
            print_colored("=" * 100 + "\n", Colors.YELLOW)
            return
        
        print_colored("\n[*] AUTO-REMEDIATION CONFIRMED - Beginning automated remediation...", Colors.GREEN)
        time.sleep(2)
    else:
        print_colored("[*] Interactive mode (will prompt for each remediation)", Colors.CYAN)
    
    print()
    
    remediated_count = 0
    skipped_count = 0
    failed_remediation_count = 0
    remediation_log = []
    
    for result in remediable_results:
        print_colored(f"[*] Issue: {result.message}", Colors.CYAN)
        print_colored(f"    Module: {result.module} | Status: {result.status} | Category: {result.category}", Colors.GRAY)
        print_colored(f"    Remediation: {result.remediation}", Colors.GRAY)
        
        should_remediate = False
        
        if auto_mode:
            should_remediate = True
            print_colored("    [AUTO] Applying remediation...", Colors.YELLOW)
        else:
            response = input("    Apply remediation? (Y/N/S=Skip remaining): ")
            if response.upper() == 'S':
                print_colored("    [*] Skipping all remaining remediations", Colors.YELLOW)
                skipped_count += (len(remediable_results) - remediated_count - failed_remediation_count - skipped_count)
                break
            should_remediate = response.upper() == 'Y'
        
        if should_remediate:
            try:
                # Execute remediation command
                result_code = subprocess.run(result.remediation, shell=True, capture_output=True, text=True)
                
                if result_code.returncode == 0:
                    print_colored("    [+] Remediation applied successfully", Colors.GREEN)
                    remediated_count += 1
                    
                    remediation_log.append({
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "module": result.module,
                        "status": result.status,
                        "category": result.category,
                        "message": result.message,
                        "remediation": result.remediation,
                        "outcome": "Success"
                    })
                else:
                    print_colored(f"    [!] Remediation failed: {result_code.stderr}", Colors.RED)
                    failed_remediation_count += 1
                    
                    remediation_log.append({
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "module": result.module,
                        "status": result.status,
                        "category": result.category,
                        "message": result.message,
                        "remediation": result.remediation,
                        "outcome": f"Failed: {result_code.stderr}"
                    })
                    
            except Exception as e:
                print_colored(f"    [!] Remediation error: {e}", Colors.RED)
                failed_remediation_count += 1
                
                remediation_log.append({
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "module": result.module,
                    "status": result.status,
                    "category": result.category,
                    "message": result.message,
                    "remediation": result.remediation,
                    "outcome": f"Error: {e}"
                })
        else:
            print_colored("    [*] Skipped", Colors.YELLOW)
            skipped_count += 1
        
        print()
    
    # Save remediation log
    if remediation_log:
        log_path = SCRIPT_PATH / f"remediation-log-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        with open(log_path, 'w') as f:
            json.dump(remediation_log, f, indent=2)
        
        # Set readable permissions
        try:
            os.chmod(log_path, 0o644)
            
            # If running as root, try to change ownership to the user who invoked sudo
            if os.geteuid() == 0:
                sudo_user = os.environ.get('SUDO_USER')
                if sudo_user:
                    try:
                        import pwd
                        user_info = pwd.getpwnam(sudo_user)
                        os.chown(log_path, user_info.pw_uid, user_info.pw_gid)
                    except:
                        pass
        except:
            pass
        
        print_colored(f"[*] Remediation log saved to: {log_path}", Colors.CYAN)
    
    # Summary
    print_colored("=" * 100, Colors.YELLOW)
    print_colored("                             REMEDIATION SUMMARY", Colors.YELLOW, bold=True)
    print_colored("=" * 100, Colors.YELLOW)
    print_colored(f"  Total remediable issues: {len(remediable_results)}", Colors.WHITE)
    print_colored(f"  Successfully remediated: {remediated_count}", Colors.GREEN)
    print_colored(f"  Failed remediations: {failed_remediation_count}", Colors.RED)
    print_colored(f"  Skipped: {skipped_count}", Colors.YELLOW)
    
    if remediated_count > 0:
        success_rate = round((remediated_count / len(remediable_results)) * 100, 1)
        print_colored(f"  Success rate: {success_rate}%", Colors.CYAN)
    
    print_colored("=" * 100 + "\n", Colors.YELLOW)
    
    if remediated_count > 0 and not auto_mode:
        print_colored("[*] Some settings may require a system restart to take effect.", Colors.YELLOW)
        restart = input("Would you like to restart now? (Y/N): ")
        if restart.upper() == 'Y':
            print_colored("[*] Restarting system in 10 seconds... Press Ctrl+C to cancel", Colors.YELLOW)
            time.sleep(3)
            subprocess.run(['sudo', 'shutdown', '-r', '+1', 'System restart after security remediation'])
    elif remediated_count > 0 and auto_mode:
        print_colored("[*] Auto-remediation complete. Some settings may require a restart.", Colors.YELLOW)

# ============================================================================
# HTML Report Generation
# ============================================================================
def generate_html_report(all_results: List[AuditResult], execution_info: ExecutionInfo) -> str:
    """Generate comprehensive HTML report with full interactivity"""
    
    # Group results by module
    modules_data = {}
    for result in all_results:
        if result.module not in modules_data:
            modules_data[result.module] = []
        modules_data[result.module].append(result)
    
    # Generate HTML
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Linux Security Audit Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        :root {{
            --bg-primary: #ffffff;
            --bg-secondary: #f8f9fa;
            --bg-gradient-start: #667eea;
            --bg-gradient-end: #764ba2;
            --text-primary: #333333;
            --text-secondary: #666666;
            --border-color: #e0e0e0;
            --card-shadow: rgba(0,0,0,0.1);
            --header-hover: #5568d3;
            --row-hover: #f5f5f5;
        }}
        [data-theme="dark"] {{
            --bg-primary: #1e1e1e;
            --bg-secondary: #2d2d2d;
            --bg-gradient-start: #4a5568;
            --bg-gradient-end: #2d3748;
            --text-primary: #e0e0e0;
            --text-secondary: #a0a0a0;
            --border-color: #404040;
            --card-shadow: rgba(0,0,0,0.3);
            --header-hover: #3a4556;
            --row-hover: #353535;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
            padding: 20px;
            color: var(--text-primary);
            transition: all 0.3s;
        }}
        .theme-toggle {{
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 1000;
            background: var(--bg-primary);
            border: 2px solid var(--border-color);
            border-radius: 25px;
            padding: 10px 20px;
            cursor: pointer;
            box-shadow: 0 4px 12px var(--card-shadow);
            font-weight: 600;
            color: var(--text-primary);
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: var(--bg-primary);
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, var(--bg-gradient-start) 0%, var(--bg-gradient-end) 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .subtitle {{ font-size: 1.2em; opacity: 0.9; }}
        .info-section {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 30px;
            background: var(--bg-secondary);
            border-bottom: 3px solid var(--bg-gradient-start);
        }}
        .info-card {{
            background: var(--bg-primary);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px var(--card-shadow);
        }}
        .info-card h3 {{
            color: var(--bg-gradient-start);
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}
        .info-card p {{ font-size: 1.1em; font-weight: 600; }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            padding: 30px;
        }}
        .summary-card {{
            text-align: center;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 8px var(--card-shadow);
        }}
        .summary-card.total {{ background: #e3f2fd; border-left: 4px solid #2196F3; color: #1565c0; }}
        .summary-card.pass {{ background: #e8f5e9; border-left: 4px solid #4CAF50; color: #2e7d32; }}
        .summary-card.fail {{ background: #ffebee; border-left: 4px solid #f44336; color: #c62828; }}
        .summary-card.warning {{ background: #fff3e0; border-left: 4px solid #ff9800; color: #e65100; }}
        .summary-card.info {{ background: #e1f5fe; border-left: 4px solid #00bcd4; color: #006064; }}
        .summary-card.error {{ background: #f3e5f5; border-left: 4px solid #9c27b0; color: #6a1b9a; }}
        [data-theme="dark"] .summary-card.total {{ background: #1e3a5f; color: #90caf9; }}
        [data-theme="dark"] .summary-card.pass {{ background: #1b5e20; color: #a5d6a7; }}
        [data-theme="dark"] .summary-card.fail {{ background: #5f1c1c; color: #ef9a9a; }}
        [data-theme="dark"] .summary-card.warning {{ background: #5f3d00; color: #ffcc80; }}
        [data-theme="dark"] .summary-card.info {{ background: #004d56; color: #80deea; }}
        [data-theme="dark"] .summary-card.error {{ background: #4a148c; color: #ce93d8; }}
        .summary-card h3 {{ font-size: 2.5em; margin-bottom: 5px; }}
        .summary-card p {{ font-size: 0.9em; text-transform: uppercase; font-weight: 600; opacity: 0.7; }}
        .results {{ padding: 30px; }}
        .module-section {{
            margin-bottom: 40px;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
        }}
        .module-section.collapsed .module-content {{ display: none; }}
        .module-section.collapsed .toggle-icon::before {{ content: '▼'; }}
        .module-header {{
            background: var(--bg-gradient-start);
            color: white;
            padding: 20px;
            font-size: 1.5em;
            font-weight: 600;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .module-header:hover {{ background: var(--header-hover); }}
        .module-stats {{ font-size: 0.8em; }}
        .module-content {{ padding: 20px; }}
        .toggle-icon::before {{ content: '▲'; transition: transform 0.3s; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-primary);
            border-radius: 8px;
            overflow: hidden;
        }}
        thead {{
            background: var(--bg-gradient-start);
            color: white;
        }}
        th {{
            padding: 12px;
            text-align: left;
            font-weight: 600;
            cursor: pointer;
            user-select: none;
        }}
        th:hover {{ background: var(--header-hover); }}
        th.asc::after {{ content: ' ▲'; }}
        th.desc::after {{ content: ' ▼'; }}
        td {{
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
        }}
        tbody tr:hover {{ background: var(--row-hover); }}
        .filter-row input {{
            width: 95%;
            padding: 8px;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            background: var(--bg-primary);
            color: var(--text-primary);
        }}
        .status {{
            padding: 6px 12px;
            border-radius: 4px;
            font-weight: 600;
            text-transform: uppercase;
            font-size: 0.85em;
            display: inline-block;
        }}
        .status-pass {{ background: #4CAF50; color: white; }}
        .status-fail {{ background: #f44336; color: white; }}
        .status-warning {{ background: #ff9800; color: white; }}
        .status-info {{ background: #00bcd4; color: white; }}
        .status-error {{ background: #9c27b0; color: white; }}
        .details {{
            margin-top: 8px;
            padding: 8px;
            background: var(--bg-secondary);
            border-left: 3px solid var(--bg-gradient-start);
            font-size: 0.9em;
            color: var(--text-secondary);
        }}
        .remediation {{
            margin-top: 8px;
            padding: 8px;
            background: #fff3cd;
            border-left: 3px solid #ff9800;
            font-size: 0.9em;
            font-family: 'Courier New', monospace;
        }}
        [data-theme="dark"] .remediation {{
            background: #5f3d00;
            color: #ffcc80;
        }}
        .footer {{
            background: var(--bg-secondary);
            padding: 20px;
            text-align: center;
            color: var(--text-secondary);
            border-top: 2px solid var(--border-color);
        }}
        .footer a {{
            color: var(--bg-gradient-start);
            text-decoration: none;
        }}
        .footer a:hover {{ text-decoration: underline; }}
        .export-btn {{
            margin: 10px 5px;
            padding: 10px 20px;
            background: var(--bg-gradient-start);
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
        }}
        .export-btn:hover {{
            background: var(--header-hover);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px var(--card-shadow);
        }}
        .export-btn.secondary {{
            background: #6c757d;
        }}
        .export-btn.secondary:hover {{
            background: #5a6268;
        }}
        .global-exports {{
            margin-bottom: 30px;
            padding: 20px;
            background: var(--bg-secondary);
            border-radius: 8px;
        }}
        .modal {{
            display: none;
            position: fixed;
            z-index: 2000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.5);
        }}
        .modal-content {{
            background-color: var(--bg-primary);
            margin: 10% auto;
            padding: 30px;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            width: 80%;
            max-width: 500px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.5);
        }}
        .modal-header {{
            font-size: 1.5em;
            font-weight: 600;
            margin-bottom: 20px;
            color: var(--text-primary);
        }}
        .format-option {{
            padding: 15px;
            margin: 10px 0;
            background: var(--bg-secondary);
            border: 2px solid var(--border-color);
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            color: var(--text-primary);
            font-weight: 600;
        }}
        .format-option:hover {{
            background: var(--bg-gradient-start);
            color: white;
            transform: translateX(5px);
        }}
        .modal-close {{
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
            color: var(--text-secondary);
        }}
        .modal-close:hover {{ color: var(--text-primary); }}
    </style>
</head>
<body>
    <button class='theme-toggle' onclick='toggleTheme()'>Toggle Dark Mode</button>
    <div class='container'>
        <div class='header'>
            <h1>Linux Security Audit Report</h1>
            <div class='subtitle'>Comprehensive Multi-Framework Security Assessment</div>
        </div>
        <div class='info-section'>
            <div class='info-card'><h3>Hostname</h3><p>{html.escape(execution_info.hostname)}</p></div>
            <div class='info-card'><h3>Operating System</h3><p>{html.escape(execution_info.os_version)}</p></div>
            <div class='info-card'><h3>Scan Date</h3><p>{html.escape(execution_info.scan_date)}</p></div>
            <div class='info-card'><h3>Duration</h3><p>{html.escape(execution_info.duration)}</p></div>
            <div class='info-card'><h3>Modules Executed</h3><p>{html.escape(', '.join(execution_info.modules_run))}</p></div>
        </div>
        <div class='summary'>
            <div class='summary-card total'><h3>{execution_info.total_checks}</h3><p>Total Checks</p></div>
            <div class='summary-card pass'><h3>{execution_info.pass_count}</h3><p>Passed</p></div>
            <div class='summary-card fail'><h3>{execution_info.fail_count}</h3><p>Failed</p></div>
            <div class='summary-card warning'><h3>{execution_info.warning_count}</h3><p>Warnings</p></div>
            <div class='summary-card info'><h3>{execution_info.info_count}</h3><p>Info</p></div>
            <div class='summary-card error'><h3>{execution_info.error_count}</h3><p>Errors</p></div>
        </div>
        <div class='results'>
            <div class='global-exports'>
                <h3 style='margin-bottom: 15px; color: var(--text-primary);'>Global Export Options</h3>
                <button class='export-btn' onclick='showExportModal("all")'>Export All</button>
                <button class='export-btn secondary' onclick='showExportModal("selected")'>Export Selected</button>
            </div>
"""
    
    # Generate module sections
    for module_name, module_results in modules_data.items():
        stats = calculate_module_statistics(module_results)
        
        html_content += f"""
            <div class='module-section'>
                <div class='module-header' onclick='toggleModule(this)'>
                    <span>MODULE: {html.escape(module_name)}</span>
                    <span class='module-stats'>Pass: {stats.passed} | Fail: {stats.failed} | Warning: {stats.warnings} | Info: {stats.info} | Error: {stats.errors}</span>
                    <span class='toggle-icon'></span>
                </div>
                <div class='module-content'>
                    <table id='table-{module_name}'>
                        <thead>
                            <tr>
                                <th style='width: 5%'><input type='checkbox' class='select-all' onchange='toggleSelectAll(this)'></th>
                                <th style='width: 10%' onclick='sortTable(this)'>Status</th>
                                <th style='width: 25%' onclick='sortTable(this)'>Category</th>
                                <th style='width: 60%' onclick='sortTable(this)'>Finding</th>
                            </tr>
                            <tr class='filter-row'>
                                <td></td>
                                <td><input type='text' placeholder='Filter' onkeyup='filterTable(this)'></td>
                                <td><input type='text' placeholder='Filter' onkeyup='filterTable(this)'></td>
                                <td><input type='text' placeholder='Filter' onkeyup='filterTable(this)'></td>
                            </tr>
                        </thead>
                        <tbody>
"""
        
        for result in module_results:
            status_class = f"status-{result.status.lower()}"
            html_content += f"""
                            <tr>
                                <td><input type='checkbox' class='row-checkbox'></td>
                                <td><span class='status {status_class}'>{html.escape(result.status)}</span></td>
                                <td>{html.escape(result.category)}</td>
                                <td><strong>{html.escape(result.message)}</strong>
"""
            if result.details:
                html_content += f"<div class='details'>{html.escape(result.details)}</div>"
            if result.remediation:
                html_content += f"<div class='remediation'><strong>REMEDIATION:</strong> {html.escape(result.remediation)}</div>"
            html_content += "</td></tr>\n"
        
        html_content += f"""
                        </tbody>
                    </table>
                    <button class='export-btn' onclick='showExportModal("module", "table-{module_name}")'>Export Module</button>
                    <button class='export-btn secondary' onclick='showExportModal("module-selected", "table-{module_name}")'>Export Selected from Module</button>
                </div>
            </div>
"""
    
    # Add footer and JavaScript
    html_content += f"""
        </div>
        <div class='footer'>
            Generated by Linux Security Audit Script v{SCRIPT_VERSION}<br>
            GitHub: <a href='https://github.com/YourRepo/Linux-Security-Audit-Script'>GitHub Repository</a>
        </div>
    </div>
    <div id='exportModal' class='modal'>
        <div class='modal-content'>
            <span class='modal-close' onclick='closeExportModal()'>&times;</span>
            <div class='modal-header'>Select Export Format</div>
            <div class='format-option' onclick='executeExport("csv")'>CSV</div>
            <div class='format-option' onclick='executeExport("excel")'>Excel</div>
            <div class='format-option' onclick='executeExport("json")'>JSON</div>
            <div class='format-option' onclick='executeExport("xml")'>XML</div>
            <div class='format-option' onclick='executeExport("txt")'>TXT</div>
        </div>
    </div>
    <script>
        let currentExportMode = null;
        let currentTableId = null;
        
        function toggleTheme() {{
            const html = document.documentElement;
            const theme = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', theme);
            localStorage.setItem('theme', theme);
        }}
        
        document.addEventListener('DOMContentLoaded', () => {{
            const theme = localStorage.getItem('theme') || 'light';
            document.documentElement.setAttribute('data-theme', theme);
        }});
        
        function toggleModule(header) {{
            header.parentElement.classList.toggle('collapsed');
        }}
        
        function toggleSelectAll(checkbox) {{
            const table = checkbox.closest('table');
            table.querySelectorAll('tbody .row-checkbox').forEach(cb => cb.checked = checkbox.checked);
        }}
        
        function sortTable(th) {{
            const table = th.closest('table');
            const tbody = table.querySelector('tbody');
            const colIndex = Array.from(th.parentElement.children).indexOf(th);
            const rows = Array.from(tbody.rows);
            const isAsc = th.classList.contains('asc');
            th.parentElement.querySelectorAll('th').forEach(h => h.classList.remove('asc', 'desc'));
            th.classList.add(isAsc ? 'desc' : 'asc');
            rows.sort((a, b) => {{
                const aText = a.cells[colIndex].textContent.trim();
                const bText = b.cells[colIndex].textContent.trim();
                return isAsc ? bText.localeCompare(aText) : aText.localeCompare(bText);
            }});
            rows.forEach(row => tbody.appendChild(row));
        }}
        
        function filterTable(input) {{
            const table = input.closest('table');
            const colIndex = Array.from(input.parentElement.parentElement.children).indexOf(input.parentElement);
            const filterValue = input.value.toLowerCase();
            table.querySelectorAll('tbody tr').forEach(row => {{
                const cellText = row.cells[colIndex].textContent.toLowerCase();
                row.style.display = cellText.includes(filterValue) ? '' : 'none';
            }});
        }}
        
        function showExportModal(mode, tableId = null) {{
            currentExportMode = mode;
            currentTableId = tableId;
            document.getElementById('exportModal').style.display = 'block';
        }}
        
        function closeExportModal() {{
            document.getElementById('exportModal').style.display = 'none';
            currentExportMode = null;
            currentTableId = null;
        }}
        
        function executeExport(format) {{
            switch(currentExportMode) {{
                case 'all':
                    exportAll(format);
                    break;
                case 'selected':
                    exportSelected(format);
                    break;
                case 'module':
                    exportModule(currentTableId, format);
                    break;
                case 'module-selected':
                    exportModuleSelected(currentTableId, format);
                    break;
            }}
            closeExportModal();
        }}
        
        function getCellText(cell) {{
            let text = '';
            const strong = cell.querySelector('strong');
            if (strong) {{
                text += strong.textContent.trim() + '\\n\\n';
            }}
            const details = cell.querySelector('.details');
            if (details) {{
                text += 'Details: ' + details.textContent.trim() + '\\n\\n';
            }}
            const remediation = cell.querySelector('.remediation');
            if (remediation) {{
                text += remediation.textContent.trim() + '\\n';
            }}
            return text.trim();
        }}
        
        function getTableData(tableId, selectedOnly = false) {{
            const table = document.getElementById(tableId);
            const moduleName = table.closest('.module-section').querySelector('.module-header span:first-child').textContent.replace('MODULE: ', '').trim();
            const headers = ['Status', 'Category', 'Finding'];
            let rows;
            if (selectedOnly) {{
                const selected = table.querySelectorAll('tbody .row-checkbox:checked');
                rows = Array.from(selected).map(cb => cb.closest('tr'));
            }} else {{
                rows = Array.from(table.querySelectorAll('tbody tr')).filter(row => row.style.display !== 'none');
            }}
            const data = rows.map(row => 
                Array.from(row.cells).slice(1).map((cell, cellIndex) => {{
                    if (cellIndex === 0) {{
                        return cell.querySelector('.status') ? cell.querySelector('.status').textContent.trim() : cell.textContent.trim();
                    }} else if (cellIndex === 2) {{
                        return getCellText(cell);
                    }} else {{
                        return cell.textContent.trim();
                    }}
                }})
            );
            return {{ moduleName, headers, data }};
        }}
        
        function exportModule(tableId, format) {{
            const tableData = getTableData(tableId, false);
            const filename = tableData.moduleName + '-Report';
            exportData([tableData], filename, format);
        }}
        
        function exportModuleSelected(tableId, format) {{
            const tableData = getTableData(tableId, true);
            if (tableData.data.length === 0) {{
                alert('No rows selected');
                return;
            }}
            const filename = tableData.moduleName + '-Selected-Report';
            exportData([tableData], filename, format);
        }}
        
        function exportAll(format) {{
            const tables = document.querySelectorAll('.module-content table');
            const allModuleData = [];
            tables.forEach(table => {{
                const tableData = getTableData(table.id, false);
                if (tableData.data.length > 0) {{
                    allModuleData.push(tableData);
                }}
            }});
            if (allModuleData.length === 0) {{
                alert('No data to export');
                return;
            }}
            exportData(allModuleData, 'Full-Security-Audit-Report', format);
        }}
        
        function exportSelected(format) {{
            const tables = document.querySelectorAll('.module-content table');
            const allModuleData = [];
            tables.forEach(table => {{
                const tableData = getTableData(table.id, true);
                if (tableData.data.length > 0) {{
                    allModuleData.push(tableData);
                }}
            }});
            if (allModuleData.length === 0) {{
                alert('No rows selected');
                return;
            }}
            exportData(allModuleData, 'Selected-Security-Audit-Report', format);
        }}
        
        function exportData(moduleDataArray, filename, format) {{
            switch(format) {{
                case 'csv':
                    exportToCSV(moduleDataArray, filename + '.csv');
                    break;
                case 'excel':
                    exportToExcel(moduleDataArray, filename + '.xls');
                    break;
                case 'json':
                    exportToJSON(moduleDataArray, filename + '.json');
                    break;
                case 'xml':
                    exportToXML(moduleDataArray, filename + '.xml');
                    break;
                case 'txt':
                    exportToTXT(moduleDataArray, filename + '.txt');
                    break;
            }}
        }}
        
        function exportToCSV(moduleDataArray, filename) {{
            let csv = '';
            moduleDataArray.forEach((moduleData, index) => {{
                if (index > 0) csv += '\\r\\n\\r\\n';
                csv += '=== ' + moduleData.moduleName + ' ===\\r\\n';
                csv += moduleData.headers.map(h => '"' + h.replace(/"/g, '""') + '"').join(',') + '\\r\\n';
                moduleData.data.forEach(row => {{
                    csv += row.map(cell => '"' + cell.replace(/"/g, '""').replace(/\\r?\\n/g, '\\r\\n') + '"').join(',') + '\\r\\n';
                }});
            }});
            downloadFile(csv, filename, 'text/csv;charset=utf-8;');
        }}
        
        function exportToExcel(moduleDataArray, filename) {{
            let html = '<html>\\n<head><meta charset="utf-8"></head>\\n<body>\\n';
            moduleDataArray.forEach((moduleData, index) => {{
                html += '<table>\\n';
                html += '<tr><td colspan="' + moduleData.headers.length + '" style="font-weight:bold;font-size:14pt;background:#667eea;color:white;padding:10px;">' + escapeHtml(moduleData.moduleName) + '</td></tr>\\n';
                html += '<tr>' + moduleData.headers.map(h => '<th style="background:#667eea;color:white;font-weight:bold;padding:8px;">' + escapeHtml(h) + '</th>').join('') + '</tr>\\n';
                moduleData.data.forEach(row => {{
                    html += '<tr>' + row.map(cell => '<td style="padding:5px;border:1px solid #ddd; white-space:pre-wrap;">' + escapeHtml(cell).replace(/\\n/g, '<br />') + '</td>').join('') + '</tr>\\n';
                }});
                html += '</table>\\n';
                if (index < moduleDataArray.length - 1) {{
                    html += '<br><br>\\n';
                }}
            }});
            html += '</body>\\n</html>';
            html = html.replace(/\\n/g, '\\r\\n');
            downloadFile(html, filename + '.xls', 'application/vnd.ms-excel');
        }}
        
        function exportToJSON(moduleDataArray, filename) {{
            const jsonData = {{
                exportDate: new Date().toISOString(),
                modules: moduleDataArray.map(moduleData => ({{
                    moduleName: moduleData.moduleName,
                    headers: moduleData.headers,
                    results: moduleData.data.map(row => {{
                        const obj = {{}};
                        moduleData.headers.forEach((header, i) => {{
                            obj[header] = row[i];
                        }});
                        return obj;
                    }})
                }}))
            }};
            const jsonString = JSON.stringify(jsonData, null, 2);
            downloadFile(jsonString, filename, 'application/json');
        }}
        
        function exportToXML(moduleDataArray, filename) {{
            let xml = '<?xml version="1.0" encoding="UTF-8"?>\\r\\n';
            xml += '<security_audit>\\r\\n';
            xml += '  <metadata>\\r\\n';
            xml += '    <export_date>' + new Date().toISOString() + '</export_date>\\r\\n';
            xml += '    <total_modules>' + moduleDataArray.length + '</total_modules>\\r\\n';
            xml += '    <total_checks>' + moduleDataArray.reduce((sum, m) => sum + m.data.length, 0) + '</total_checks>\\r\\n';
            xml += '  </metadata>\\r\\n';
            xml += '  <events>\\r\\n';
            moduleDataArray.forEach(moduleData => {{
                moduleData.data.forEach(row => {{
                    xml += '    <event>\\r\\n';
                    xml += '      <timestamp>' + new Date().toISOString() + '</timestamp>\\r\\n';
                    xml += '      <module>' + escapeXml(moduleData.moduleName) + '</module>\\r\\n';
                    moduleData.headers.forEach((header, i) => {{
                        const tagName = header.replace(/\\s+/g, '_').toLowerCase();
                        const value = escapeXml(row[i] || '').replace(/\\r?\\n/g, '&#10;');
                        xml += '      <' + tagName + '>' + value + '</' + tagName + '>\\r\\n';
                    }});
                    xml += '    </event>\\r\\n';
                }});
            }});
            xml += '  </events>\\r\\n';
            xml += '</security_audit>';
            const finalFilename = filename.endsWith('.xml') ? filename : filename + '.xml';
            downloadFile(xml, finalFilename, 'application/xml');
        }}
        
        function exportToTXT(moduleDataArray, filename) {{
            let txt = 'LINUX SECURITY AUDIT REPORT\\r\\n';
            txt += '================================\\r\\n';
            txt += 'Export Date: ' + new Date().toLocaleString() + '\\r\\n\\r\\n';
            moduleDataArray.forEach((moduleData, index) => {{
                if (index > 0) txt += '\\r\\n\\r\\n';
                txt += '='.repeat(60) + '\\r\\n';
                txt += 'MODULE: ' + moduleData.moduleName + '\\r\\n';
                txt += '='.repeat(60) + '\\r\\n\\r\\n';
                const colWidths = moduleData.headers.map((h, i) => {{
                    const processedData = moduleData.data.map(row => row[i].replace(/\\r?\\n/g, ' | ').length);
                    const maxDataWidth = Math.max(...processedData);
                    return Math.max(h.length, maxDataWidth, 10);
                }});
                txt += moduleData.headers.map((h, i) => h.padEnd(colWidths[i])).join(' | ') + '\\r\\n';
                txt += colWidths.map(w => '-'.repeat(w)).join('-+-') + '\\r\\n';
                moduleData.data.forEach(row => {{
                    const processedRow = row.map(cell => cell.replace(/\\r?\\n/g, ' | '));
                    txt += processedRow.map((cell, i) => cell.padEnd(colWidths[i])).join(' | ') + '\\r\\n';
                }});
            }});
            downloadFile(txt, filename, 'text/plain');
        }}
        
        function downloadFile(content, filename, mimeType) {{
            const element = document.createElement('a');
            element.setAttribute('href', 'data:' + mimeType + ';charset=utf-8,' + encodeURIComponent(content));
            element.setAttribute('download', filename);
            element.style.display = 'none';
            document.body.appendChild(element);
            element.click();
            document.body.removeChild(element);
        }}
        
        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}
        
        function escapeXml(text) {{
            return text
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&apos;');
        }}
        
        window.onclick = function(event) {{
            const modal = document.getElementById('exportModal');
            if (event.target === modal) {{
                closeExportModal();
            }}
        }}
    </script>
</body>
</html>
"""
    
    return html_content

# ============================================================================
# Export Functions
# ============================================================================
def export_to_csv(results: List[AuditResult], filepath: Path):
    """Export results to CSV format"""
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['Module', 'Category', 'Status', 'Message', 'Details', 'Remediation', 'Timestamp'])
        writer.writeheader()
        for result in results:
            writer.writerow(result.to_dict())
    
    # Set readable permissions
    try:
        os.chmod(filepath, 0o644)
    except:
        pass
    
    print_colored(f"\n[+] CSV report saved to: {filepath}", Colors.GREEN)

def export_to_json(results: List[AuditResult], execution_info: ExecutionInfo, filepath: Path):
    """Export results to JSON format"""
    data = {
        "executionInfo": execution_info.to_dict(),
        "results": [r.to_dict() for r in results]
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    
    # Set readable permissions
    try:
        os.chmod(filepath, 0o644)
    except:
        pass
    
    print_colored(f"\n[+] JSON report saved to: {filepath}", Colors.GREEN)

def export_to_xml(results: List[AuditResult], execution_info: ExecutionInfo, filepath: Path):
    """Export results to XML format (SIEM-compatible)"""
    root = ET.Element('security_audit')
    
    # Metadata
    metadata = ET.SubElement(root, 'metadata')
    ET.SubElement(metadata, 'export_date').text = datetime.datetime.utcnow().isoformat()
    ET.SubElement(metadata, 'hostname').text = execution_info.hostname
    ET.SubElement(metadata, 'operating_system').text = execution_info.os_version
    ET.SubElement(metadata, 'scan_date').text = execution_info.scan_date
    ET.SubElement(metadata, 'duration').text = execution_info.duration
    ET.SubElement(metadata, 'total_checks').text = str(execution_info.total_checks)
    ET.SubElement(metadata, 'pass_count').text = str(execution_info.pass_count)
    ET.SubElement(metadata, 'fail_count').text = str(execution_info.fail_count)
    ET.SubElement(metadata, 'warning_count').text = str(execution_info.warning_count)
    ET.SubElement(metadata, 'info_count').text = str(execution_info.info_count)
    ET.SubElement(metadata, 'error_count').text = str(execution_info.error_count)
    
    # Events
    events = ET.SubElement(root, 'events')
    for result in results:
        event = ET.SubElement(events, 'event')
        ET.SubElement(event, 'timestamp').text = result.timestamp
        ET.SubElement(event, 'module').text = result.module
        ET.SubElement(event, 'status').text = result.status
        ET.SubElement(event, 'category').text = result.category
        ET.SubElement(event, 'message').text = result.message
        if result.details:
            ET.SubElement(event, 'details').text = result.details
        if result.remediation:
            ET.SubElement(event, 'remediation').text = result.remediation
    
    tree = ET.ElementTree(root)
    ET.indent(tree, space='  ')
    tree.write(filepath, encoding='utf-8', xml_declaration=True)
    
    # Set readable permissions
    try:
        os.chmod(filepath, 0o644)
    except:
        pass
    
    print_colored(f"\n[+] XML report saved to: {filepath}", Colors.GREEN)

def export_results(results: List[AuditResult], execution_info: ExecutionInfo, 
                  output_format: str, output_path: str = ""):
    """Main export function that delegates to specific format handlers"""
    if not output_path:
        timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        extension = {
            "HTML": "html",
            "CSV": "csv",
            "JSON": "json",
            "XML": "xml"
        }.get(output_format, "txt")
        output_path = SCRIPT_PATH / f"Security-Audit-Report-{timestamp}.{extension}"
    else:
        output_path = Path(output_path)
    
    if output_format == "HTML":
        html_content = generate_html_report(results, execution_info)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print_colored(f"\n[+] HTML report saved to: {output_path}", Colors.GREEN)
    elif output_format == "CSV":
        export_to_csv(results, output_path)
    elif output_format == "JSON":
        export_to_json(results, execution_info, output_path)
    elif output_format == "XML":
        export_to_xml(results, execution_info, output_path)
    elif output_format == "Console":
        print_colored("\n[+] Console output complete", Colors.GREEN)
        return None
    
    # Fix file permissions to make it readable by all users
    try:
        os.chmod(output_path, 0o644)
        
        # If running as root, try to change ownership to the user who invoked sudo
        if os.geteuid() == 0:
            sudo_user = os.environ.get('SUDO_USER')
            if sudo_user:
                try:
                    import pwd
                    user_info = pwd.getpwnam(sudo_user)
                    os.chown(output_path, user_info.pw_uid, user_info.pw_gid)
                    print_colored(f"[+] File ownership set to: {sudo_user}", Colors.CYAN)
                except Exception as e:
                    pass  # If ownership change fails, at least permissions are set
    except Exception as e:
        print_colored(f"[!] Warning: Could not set file permissions: {e}", Colors.YELLOW)
    
    return output_path

# ============================================================================
# Main Execution
# ============================================================================
def main():
    """Main execution function"""
    parser = argparse.ArgumentParser(
        description='Comprehensive Linux Security Audit Script',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument('-m', '--modules', type=str, default='All',
                       help='Comma-separated list of modules (use --list-modules to see available)')
    parser.add_argument('-f', '--output-format', type=str, default='HTML',
                       choices=['HTML', 'CSV', 'JSON', 'XML', 'Console'],
                       help='Output format')
    parser.add_argument('-o', '--output-path', type=str, default='',
                       help='Path for output file')
    parser.add_argument('--list-modules', action='store_true',
                       help='List all available modules and exit')
    parser.add_argument('--remediate', action='store_true',
                       help='Interactively remediate failed checks')
    parser.add_argument('--remediate-fail', action='store_true',
                       help='Remediate only FAIL status issues')
    parser.add_argument('--remediate-warning', action='store_true',
                       help='Remediate only WARNING status issues')
    parser.add_argument('--remediate-info', action='store_true',
                       help='Remediate only INFO status issues')
    parser.add_argument('--auto-remediate', action='store_true',
                       help='Automatically remediate without prompting')
    parser.add_argument('--remediation-file', type=str, default='',
                       help='JSON file with specific issues to remediate')
    
    args = parser.parse_args()
    
    # If just listing modules, do that and exit
    if args.list_modules:
        print_banner()
        list_available_modules()
        return
    
    start_time = datetime.datetime.now()
    
    print_banner()
    
    # Check if remediation requires root
    require_root = (args.remediate or args.remediate_fail or args.remediate_warning or 
                   args.remediate_info or args.auto_remediate)
    
    prerequisites_ok, is_root = check_prerequisites(require_root)
    if not prerequisites_ok:
        return
    
    # Get available modules dynamically
    available_modules = get_available_modules()
    
    if not available_modules:
        print_colored("[!] No modules found. Cannot proceed.", Colors.RED)
        return
    
    # Determine modules to run
    if args.modules == 'All':
        modules_to_run = sorted(available_modules.keys())
    else:
        requested_modules = [m.strip() for m in args.modules.split(',')]
        modules_to_run = []
        
        # Validate requested modules exist
        for module in requested_modules:
            # Try case-insensitive matching
            matched = False
            for available_module in available_modules.keys():
                if module.lower() == available_module.lower():
                    modules_to_run.append(available_module)
                    matched = True
                    break
            
            if not matched:
                print_colored(f"[!] WARNING: Module '{module}' not found", Colors.YELLOW)
        
        if not modules_to_run:
            print_colored("[!] No valid modules specified. Use --list-modules to see available modules.", Colors.RED)
            return
    
    print_colored(f"\n[*] Modules to execute: {', '.join(modules_to_run)}", Colors.CYAN)
    
    # Prepare shared data
    shared_data = {
        "hostname": socket.gethostname(),
        "os_version": f"{platform.system()} {platform.release()}",
        "scan_date": start_time,
        "is_root": is_root,
        "script_path": SCRIPT_PATH
    }
    
    # Execute modules
    all_results = []
    successful_modules = []
    
    for module in modules_to_run:
        try:
            module_results = execute_security_module(module, shared_data)
            if module_results:
                all_results.extend(module_results)
                successful_modules.append(module)
        except Exception as e:
            print_colored(f"[!] Failed to execute module {module}: {e}", Colors.RED)
    
    # Sort results by module
    all_results.sort(key=lambda r: r.module)
    
    if not all_results:
        print_colored("\n[!] No results generated", Colors.RED)
        return
    
    # Calculate execution info
    end_time = datetime.datetime.now()
    duration = end_time - start_time
    
    execution_info = ExecutionInfo(
        hostname=shared_data["hostname"],
        os_version=shared_data["os_version"],
        scan_date=start_time.strftime("%Y-%m-%d %H:%M:%S"),
        duration=str(duration).split('.')[0],
        modules_run=successful_modules,
        total_checks=len(all_results),
        pass_count=sum(1 for r in all_results if r.status == "Pass"),
        fail_count=sum(1 for r in all_results if r.status == "Fail"),
        warning_count=sum(1 for r in all_results if r.status == "Warning"),
        info_count=sum(1 for r in all_results if r.status == "Info"),
        error_count=sum(1 for r in all_results if r.status == "Error")
    )
    
    # Display summary
    print_colored("\n" + "=" * 100, Colors.CYAN)
    print_colored("                                 AUDIT SUMMARY", Colors.CYAN, bold=True)
    print_colored("=" * 100, Colors.CYAN)
    print_colored(f"Execution Mode:  {'ROOT (Full Access)' if is_root else 'NON-ROOT (Limited)'}", Colors.GREEN if is_root else Colors.CYAN)
    print_colored(f"Total Checks:    {execution_info.total_checks}", Colors.WHITE)
    print_colored(f"Passed:          {execution_info.pass_count}", Colors.GREEN)
    print_colored(f"Failed:          {execution_info.fail_count}", Colors.RED)
    print_colored(f"Warnings:        {execution_info.warning_count}", Colors.YELLOW)
    print_colored(f"Info:            {execution_info.info_count}", Colors.CYAN)
    print_colored(f"Errors:          {execution_info.error_count}", Colors.MAGENTA)
    print_colored(f"Duration:        {execution_info.duration}", Colors.WHITE)
    
    if statistics.normalized_results > 0:
        print_colored(f"\nValidation: {statistics.normalized_results} results normalized", Colors.YELLOW)
    
    if not is_root:
        print_colored("\n[!] Note: Some checks may be limited without root privileges", Colors.CYAN)
        print_colored("    Run with 'sudo' for complete security assessment", Colors.CYAN)
    
    print_colored("=" * 100 + "\n", Colors.CYAN)
    
    # Handle remediation if requested
    if args.remediate or args.remediate_fail or args.remediate_warning or args.remediate_info:
        if not is_root:
            print_colored("[!] ERROR: Remediation requires root privileges", Colors.RED)
            print_colored("    Run with: sudo python3 linux_security_audit.py --remediate", Colors.YELLOW)
        else:
            invoke_remediation(all_results, args)
    
    # Export results
    if args.output_format != "Console":
        output_path = export_results(all_results, execution_info, args.output_format, args.output_path)
        if args.output_format == "HTML" and output_path and output_path.exists():
            print_colored("[*] Opening report in browser...", Colors.CYAN)
            import webbrowser
            webbrowser.open(f"file://{output_path.absolute()}")
    
    print_colored("\n[+] Audit completed successfully!", Colors.GREEN)
    if not is_root:
        print_colored("[*] Tip: Run with 'sudo' for complete security assessment and remediation", Colors.CYAN)
    print_colored("[*] GitHub: https://github.com/YourRepo/Linux-Security-Audit-Script", Colors.CYAN)

# ============================================================================
# Script Entry Point
# ============================================================================
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_colored("\n\n[!] Audit interrupted by user", Colors.YELLOW)
        sys.exit(1)
    except Exception as e:
        print_colored(f"\n[!] Fatal error: {e}", Colors.RED)
        import traceback
        print_colored("\nStack Trace:", Colors.YELLOW)
        traceback.print_exc()
        sys.exit(1)
