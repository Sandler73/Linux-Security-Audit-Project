# Changelog

All notable changes to the Linux Security Audit Project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.9.0] - 2026-06-13 (Scoring Bug Fix, PCI-DSS Rename, Remediation Consistency)

### Fixed - code hygiene

- Removed a dead reference to an undefined `read_sysctl_value` in
  `module_core.py` (the kernel-module-lockdown check already reads the value
  correctly via `sysctl -n` on the following line).

### Changed - ASCII portability

- Removed all non-ASCII characters from source and documentation for
  cross-platform rendering safety: em/en dashes -> `-`, `<=`/`>=`/`->`
  operators spelled out, section sign -> `Sec.`, and decorative
  emoji/box-drawing/mojibake stripped or converted to ASCII equivalents.
  Source files and all Markdown docs are now pure 7-bit ASCII.

### Documentation - technical audit

- Reconciled the headline check count to the runtime-verified total (2,297)
  and updated the per-module count tables in `Home.md` and `Examples.md` to
  the exact verified counts.
- Corrected stale "8 modules/frameworks" and "8 profiles" references to 16
  and 18 respectively; standardized PCI -> PCI-DSS naming in module tables.
- Brought `README.md` current to v3.9 (stats table + version-history entry).
- Added `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1).


### Added - full cross-framework remediation audit + normalization

- **`shared_components/canonical_remediations.py`**: a single-source-of-truth
  registry mapping each remediation TOPIC to one canonical, detailed, robust
  remediation, plus a high-precision classifier. The orchestrator applies a
  normalization pass after all checks run: a finding classified into a
  value-independent topic has its remediation replaced with the canonical
  version, so the same fix reads identically across every framework.
- **37 overlapping topics indexed**, 27 of them value-independent and now
  unified to ONE remediation each: ip_forwarding, syn_cookies,
  icmp_redirects (27 checks across 10 frameworks), source_routing, rp_filter
  (27/12), aslr (19/10), core_dumps (20/10), ssh_root_login (14/11),
  ssh_password_auth, empty_passwords (18/11), legacy_services, ssh_strong_crypto (SSH cipher/MAC/KEX, 26 checks), mac_enforcement (SELinux/AppArmor/fapolicyd, 25), ntp_time_sync (29), mount_options (19), password_hashing (11), grub_password (9). The 6
  value-bearing topics (password_max_days/min_days, umask,
  password_complexity, ssh_idle_timeout, account_lockout) are mapped for transparency but keep their
  framework-specific values.
- Canonical remediations were chosen as the most informative version found
  and enhanced where insufficient: sysctl fixes now always set the runtime
  value, persist under `/etc/sysctl.d/`, apply with `sysctl --system`, and
  explain the rationale.
- **`docs/Remediation-Cross-Map.md`**: generated index cross-mapping every
  overlapping check to its topic, the frameworks involved, and the canonical
  remediation.

### Fixed - status/severity confusion miscounted as errors

- 9 checks passed a severity word ("Critical"/"High") in the STATUS position
  (valid statuses are Pass/Fail/Warning/Info/Error), so when the condition
  triggered they were miscounted as Errors (ACSC uid0, CIS/NSA anon-auth,
  CORE empty-passwords, GDPR/HIPAA time-sync, HIPAA duplicate-uid, ISO27001
  firewall, NSA readonly). Corrected to status "Fail" with the severity
  preserved via the `severity=` keyword.

### Fixed - OSInfo variant divergence (DistBaseline errors via orchestrator)

- The shared-data cache holds the `audit_common.OSInfo` variant, which a
  module wrote into `shared_data['os_info']`; DistBaseline's per-distro
  dispatch then read `.distro_id` on it and raised AttributeError (only via
  the orchestrator, not in isolated module runs). Fixed systemically by
  adding `distro_id`/`distro_version`/`pretty_name` compatibility properties
  to `audit_common.OSInfo`, completing the v3.7.1 reciprocal-alias work so
  both OSInfo variants are fully API-compatible.

### Fixed - module discovery name mismatch (silent fake compliance scores)

- **Root cause**: `get_available_modules()` derived module names from the
  filename via `.title()` with an incomplete acronym special-case list, so
  9 of 16 modules had a discovery name (e.g. "Pci", "Core", "Acsc") that did
  NOT match the `module` field on their AuditResults (e.g. "PCI", "CORE",
  "ACSC"). Per-module compliance scoring matches results by
  `r.module == discovery_name`, so those modules matched 0 results and
  reported a vacuous 100% / 0-checks score in BOTH the combined report and
  (downstream) the split reports.
- **Fix**: discovery now reads each module's declared `MODULE_NAME` directly
  from the file, guaranteeing the discovery key matches `result.module`. All
  16 modules now score correctly.

### Fixed - split-report compliance scoring (0.0% / Threshold N/A)

- `export_split_reports()` passed a `ComplianceScore` object in the wrong
  shape. The HTML generator expects `{"overall": {...}, "modules": {...}}`.
  Per-module reports now build that structure (the module's own score serves
  as both the overall and the single module entry), so each split report
  shows a real weighted percentage and threshold result.

### Changed - PCI module renamed to PCI-DSS

- `MODULE_NAME` is now `"PCI-DSS"` (was `"PCI"`), so reports and
  `--list-modules` display the accurate standard name. Standalone banners
  updated to `[PCI-DSS]`.
- CLI selector aliases added: `--modules PCIDSS`, `--modules PCI`, and
  `--modules pci-dss` all resolve to the canonical `PCI-DSS` (matching is
  case-insensitive and hyphen-insensitive).

### Fixed - cross-framework remediation/assessment consistency

- **New `shared_components/shared_assessments.py`**: canonical single-source
  assessments for physical checks that many frameworks audit independently.
  Each enumerates the fact ONCE (cached), returning the true count, the
  ACTUAL offending items (not just a number), a standardized status, a
  standardized detail string that includes the item list, and standardized
  OS-aware remediation.
- **World-writable files**: all 7 checks (CORE FS-006 + AS-005, CIS 6.1.10,
  CISA DP-7, ISO27001 A.8.3, NIST SI-13, STIG AC-22 + SI-25) migrated to the
  canonical assessment. Previously each used a different `find` invocation
  (some capped at `head -10`, some `head -20`, one used `-perm -002` vs
  `-0002`), divergent status logic (Pass/Fail vs Pass/Warning), divergent
  detail formats, and none listed the files. Now every framework reports the
  same count, the same file list, the same Fail-on-nonzero status, and the
  same remediation.
- **SUID/SGID**: CORE AS-004 migrated to the canonical SUID assessment.

### Verification

- All 16 modules: 2,294 runtime checks, 0 errors, 0 aborts.
- All 16 modules now produce correct per-module compliance scores (was 9
  broken). Split reports show real weighted percentages and thresholds.

### Added - Attack-surface report feature parity

- The attack-surface HTML report was rebuilt to match the main compliance
  report's interactive feature set: light/dark theme toggle (persisted to
  localStorage), collapsible domain sections, per-column filters, global
  search (include/exclude), sortable and resizable columns, column-visibility
  toggles, word-wrapped cells showing FULL (untruncated) finding text, and
  per-table + global export to CSV / JSON / XML.
- The synthesis now retains ALL findings per domain (not a top-8 slice) with
  full detail and remediation text, so nothing is truncated in the report.

### Added - Deeper attack-surface assessment (firewall + exec + linker)

- **`get_firewall_posture()`** in shared_assessments: assesses ufw,
  firewalld, nftables, iptables (v4+v6), and ipset, distinguishing
  INSTALLED vs ACTIVE vs CONFIGURED. Previously a firewall package that was
  installed-but-disabled, or running with no rules, was reported the same as
  no firewall at all. Status: Pass (enforcing rules) / Warning (active but
  accept-all) / Fail (installed-inactive or none).
- **New CORE attack-surface checks** (CORE now 10 AS checks): AS-008
  firewall posture, AS-009 executable-PATH writability (writable/world-
  writable directories on $PATH = privilege-escalation pathway), AS-010
  shared-object / linker controls (world-writable .so files, writable
  ld.so.conf, ld.so.preload presence = LD_PRELOAD hijack vector).

### Added - Distribution profiles (8 -> 18)

- New `--profile` values: kali, mxlinux, mint, zorin, elementary (Debian
  family); almalinux, rocky, centos, centosstream, fedora (RHEL family).
  Each excludes the inapplicable cross-family categories. Strict input
  validation (allowlist regex) unchanged; injection still rejected.

### Added - Tests

- `tests/test_shared_assessments.py` (10 tests): world-writable consistency
  (count/items/remediation identical across severity basis), SUID threshold
  logic, firewall posture status logic, and assessment caching.

### Verification (this session's additions)

- All 16 modules: 2,297 runtime checks (+3 from new CORE AS checks), 0
  errors, 0 aborts. All 18 profiles validate; 5 test suites pass.

---



Two new report capabilities plus supporting CORE checks.

### Added - Attack Surface Assessment report

- **`shared_components/attack_surface.py`** - a synthesis engine that
  re-frames audit findings around exposure rather than compliance. It maps
  every non-passing finding (from all selected frameworks) onto ten
  attack-surface domains and computes a severity-weighted exposure score
  (0-100) per domain and overall.
- **Domains**: Network Exposure, Authentication & Access, Privilege &
  Escalation, Filesystem Exposure, Service & Daemon Surface, Kernel & Boot
  Surface, Container & Orchestration, Credential & Secret Exposure,
  Cryptographic Posture, Detection & Response.
- **CLI**: `--attack-surface` generates the report (HTML + JSON) to
  `reports/Attack-Surface-<host>-<timestamp>.{html,json}`. The HTML report
  has an overall exposure dial, host summary, cross-domain top-findings
  table, and per-domain cards. The JSON companion carries the full
  structured assessment for SIEM/dashboard ingestion.
- The assessment runs without duplicate checks - it reads the existing
  AuditResult set plus the HostFacts registry.

### Added - CORE attack-surface enumeration checks

- New `CORE - Attack Surface` category (7 checks): external-facing TCP
  listeners, external-facing UDP listeners, legacy/cleartext service
  binaries, SUID/SGID exposure summary, world-writable exposure summary,
  container-runtime socket exposure, and kernel-module lockdown state.
  CORE is the home for these because it is the only non-framework-tied
  module. CORE check count rose from 175 to ~182.

### Added - Per-framework split reports

- **CLI**: `--split-reports` writes one focused report per framework to
  `reports/by-framework/<FRAMEWORK>-Audit-<host>-<timestamp>.<ext>`,
  alongside the combined report. `--split-only` produces just the
  per-framework set. Works for all output formats (HTML/CSV/JSON/XML).
- Each split report is a complete standalone report scoped to a single
  framework, so different audiences receive only their relevant data. When
  one framework is selected, no split occurs (the combined report already
  represents it).
- **`export_split_reports()`** in the orchestrator groups results by module
  and reuses the existing per-format generators with per-module
  ExecutionInfo.

### Added - Tests

- `tests/test_attack_surface.py` (7 tests): domain mapping, score bounds,
  pass-only minimal exposure, serializers, and CORE attack-surface
  integration.

### Verification

- All 16 modules run end-to-end: 2,294 runtime checks (was 2,287; +7 from
  the new CORE attack-surface checks), 0 errors, 0 aborts.
- All four test suites pass (test_remediation_library, test_os_detection,
  test_attack_surface, test_end_to_end).
- Combined run with `--split-reports --attack-surface` produces the
  combined report, 16 per-framework reports, and the attack-surface report
  together without error.

---



This patch release addresses inconsistencies and latent runtime bugs
surfaced during post-v3.7 verification testing.

### Fixed - Latent OSInfo bugs that silently truncated audits (HIGH)

Two `OSInfo` implementations had diverged: `audit_common.OSInfo` uses
`.distro`/`.version` attributes, `is_<family>_based()` methods, and
lowercase family strings; `os_detection.OSInfo` uses
`.distro_id`/`.version_id`, `is_<family>_family()`, and capitalized
family strings. The orchestrator passes the os_detection variant at
runtime, but several modules and `audit_common` helpers were written
against the other variant's names. The mismatch raised `AttributeError`
mid-run and **aborted entire check functions**:

- `check_package_installed()` in audit_common called
  `os_info.is_debian_based()` -> ISO27001 executed only **9 of 147**
  checks before aborting.
- `module_enisa` banner used `os_info.distro` -> ENISA aborted
  completely (**0 checks** ran in the full suite).

**Fix**: Added reciprocal compatibility aliases so the two OSInfo
classes are fully interchangeable:
- `os_detection.OSInfo`: added `.distro`, `.version`, `.kernel_version`
  properties; `is_debian_based/redhat_based/suse_based/arch_based()`
  methods; `is_alpine_family()/is_alpine_based()`.
- `audit_common.OSInfo`: added
  `is_debian_family/redhat_family/suse_family/arch_family()` methods.

After the fix, all 16 modules run end-to-end with **0 aborts and 0
errors** (2,287 runtime checks in a minimal container; more on a full
host where conditional checks fire).

### Fixed - Remediation guidance inconsistency across overlapping checks

The same remediation (e.g. installing AIDE) appeared in 4+ inconsistent
inline forms across modules - including `aideinit`, which is a
Debian-only wrapper and is incorrect on RHEL/SUSE/Arch (those need
`aide --init` plus distro-specific database file handling). 63% of
remediations were inline-hardcoded, bypassing the OS-aware
`remediation_library.py`.

**Fix**: migrated the large majority of library-coverable inline
remediations to the OS-aware library. Centralized calls
(`remediation_for()` + new `removal_for()` + new `patch_for()`) rose from
135 to 320. Tools routed through the library now include: AIDE, auditd,
chrony, ClamAV, rkhunter, Lynis, OpenSCAP, cryptsetup, unattended-upgrades,
dnf-automatic, gnupg, nftables, pam-google-authenticator, SELinux,
AppArmor, osquery, sysstat, sudo, logrotate, rsyslog, ufw.

**New - OS-aware package REMOVAL helper** (`get_removal_remediation()` in
remediation_library.py, exposed as `removal_for()` in each module):
resolves the correct purge command AND the correct per-distro package name
for "remove insecure service" checks. Previously these emitted Debian-only
or Debian/RHEL-only guidance (e.g. `apt purge bind9 || yum remove bind`)
with no SUSE/Arch/Alpine coverage and often the wrong package name. A
package-name registry handles the cases where names differ across families:
dns-server (bind9/bind), dhcp-server (isc-dhcp-server/dhcp-server),
nfs-server (nfs-kernel-server/nfs-utils), ldap-server
(slapd/openldap-servers/openldap2), snmp (snmpd/net-snmp), rsh, nis
(ypserv/ypbind), xserver, avahi, dovecot. 26 removal remediations migrated.

**New - OS-aware security-PATCH helper** (`get_patch_remediation()`,
exposed as `patch_for()`): emits `apt-get upgrade` / `dnf -y update
--security` / `zypper patch` / `pacman -Syu` / `apk upgrade` for the
detected family. 6 patch remediations migrated.

Verified in a live CIS report: 20 OS-aware removal remediations render
with full per-distribution guidance; all 16 modules run end-to-end with
0 aborts / 0 errors (2,287 runtime checks in a minimal container).

Verified: AIDE remediation is now **identical across all modules** and
correctly OS-specific:
- Debian: `apt-get install -y aide aide-common` + `aideinit`
- RHEL: `dnf install -y aide` + `aide --init`
- SUSE: `zypper install -y aide` + `aide --init`
- Arch: `pacman -S --noconfirm aide` + `aide --init`
- Alpine: `apk add aide` + `aide --init`

### Known remaining work (transparency)

- ~30 genuinely custom inline remediations remain (multi-tool installs
  like `apt install lynis aide rkhunter`, and multi-step config changes)
  that don't map to a single library tool_id; these are context-specific
  and lower priority
- Documentation line-by-line depth audit (docs/ and wiki/) remains a
  targeted refresh rather than exhaustive
- Module check-count targets in Module-Inventory.md not fully reached

---

## [3.7.0] - 2026-04-26 (Cross-Module Correlation, Distribution Profiles, Rollup Metrics)

This release adds three substantial capabilities and a comprehensive
file-by-file documentation audit.

### Added - Cross-Module Correlation (Phase 1)

- **`shared_components/host_facts.py`** - A canonical, immutable
  `HostFacts` dataclass (~80 typed fields) computed once at audit start
  and stored in `shared_data["host_facts"]`. Modules can read facts
  directly instead of re-deriving them from raw helpers.
- Fact families covered: identity (distro, container, VM), FIM
  (AIDE/Tripwire/Samhain/OSSEC/Wazuh), audit infrastructure (auditd,
  rules, journald), cryptography (FIPS, crypto-policy, OpenSSL 3.x),
  MAC (SELinux/AppArmor), firewall (ufw/firewalld/nftables, listening
  external count), authentication (SSH, PAM MFA, lockout), patching
  (auto-patch tool), time sync, centralized logging (rsyslog/syslog-ng/
  journal-upload), storage encryption (LUKS, swap, fstrim, SSD),
  containers (runtime, K8s, kubelet anonymous-auth/readonly-port),
  anti-malware (clamav, fail2ban, rkhunter, chkrootkit), tool
  inventories (backup, snapshot, secure-delete, vuln scanners, SAST,
  SBOM, signing, forensics, config mgmt, package signing), and boot
  security (Secure Boot EFI, TPM 2.0, tpm2-tools).
- `compute_host_facts(os_info, helpers)` is the single entry point.
  `get_or_compute_facts(shared_data, os_info, helpers)` is the
  convenience accessor for modules that may not have orchestrator
  context. Backward-compatible: legacy helper paths still work.

### Added - Per-Distribution Profiles (Phase 2)

- **`shared_components/profiles.py`** - eight built-in profiles with
  hardcoded subtractive filters: `generic`, `rhel9`, `rhel8`,
  `ubuntu24`, `ubuntu22`, `debian12`, `alpine`, `suse15`.
- **CLI integration**:
  - `--profile NAME` applies a per-distribution profile
  - `--list-profiles` enumerates all profiles with description,
    applicable distros, and excluded category prefixes
  - The pre-existing `--profile` boolean (perf timing) renamed to
    `--perf-profile` to free `--profile` for the natural distro
    semantics. `--profile-perf` is also accepted as an alias for
    backward compatibility.
- **Security design**:
  - Strict regex `^[a-z][a-z0-9_-]{0,30}$` for profile names; rejects
    path traversal, shell injection, command substitution, newlines,
    leading hyphens, and length-DoS attempts
  - All profile data is hardcoded Python source (no external file
    loads, no `eval`, no JSON/YAML parsing on user input)
  - Filter operations are SUBTRACTIVE only: profiles can drop modules
    or category prefixes but never add or modify checks
  - 23 security test cases verified including injection attempts
    (`rhel9; rm -rf /`, `../etc/passwd`, `rhel9$(id)`, etc.)

### Added - Rollup Metrics + Priority-Driven Executive Summary (Phase 3)

- **HTML report - Module Summary tiles** - color-banded grid (green
  >=90%, yellow 70-90%, orange 50-70%, red <50%) showing per-module
  score, pass/fail/warn/info/error counts, top severity badge, and
  anchor link to that module's detail section. Uses CSS grid with
  responsive `minmax(200px, 1fr)` template.
- **HTML report - Top Priority Findings** - top 10 non-Pass results
  sorted by severity rank (Critical -> High -> Medium -> Low ->
  Informational), then status priority (Fail -> Warning -> Info), then
  module name. Each row shows severity badge, status badge, module,
  category, and truncated message. Displayed above the per-module
  detail tables for fast scanning.
- TOC entries added for both new sections; CSS extended with the
  v3.7-specific color palette.

### Documentation (Phase 4)

File-by-file line-by-line audit and refresh of every doc:

- **README.md** - added v3.6 caching layer + v3.7 features bullets;
  added Distribution Profiles subsection; refreshed all 16 per-module
  rows in framework summary table to v3.5 finals (~2,319 total);
  updated all `--profile` examples to `--perf-profile` for the timing
  flag; added `--profile NAME` and `--list-profiles` to options table
- **Module-Inventory.md** - version bumped to 3.7; project-wide
  statistics refreshed (added HostFacts and built-in profiles
  metrics); gap-tracking tables updated to v3.5 finals; subtotals
  recomputed
- **wiki/Home.md** - version banner updated to 3.7; What Is bullet
  list extended with v3.6 caching + v3.7 correlation/profiles/rollup;
  per-module table refreshed to v3.5 finals
- **wiki/Quick_Start_Guide.md** - refreshed with v3.7 references
- **wiki/Usage_Guide.md** - All Available Options table extended with
  `--profile NAME`, `--list-profiles`, `--perf-profile`; added new
  Distribution Profiles section with profile table, examples, and
  security/validation note
- **wiki/Module_Documentation.md** - refreshed total to ~2,319; v3.5
  expansion sections retained from prior releases
- **wiki/Output_Reference.md** - HTML overview extended with v3.7
  features; Key Sections numbered list expanded with sections 4 and 5
  (Module Summary tiles + Top Priority Findings) including health
  band table and color palette
- **wiki/Examples.md** - total checks refreshed to ~2,319
- **wiki/Frequently_Asked_Questions__FAQ_.md** - total refreshed
- **wiki/_Sidebar.md** / **wiki/_Footer.md** - version 3.7 banner

### Statistics

- Project total: ~2,319 checks (unchanged from v3.6 - v3.7 is a
  framework/UX release, not a check-count expansion)
- Foundation files: 11 (added `host_facts.py` and `profiles.py`)
- CLI flags: 30 (added `--profile NAME` and `--list-profiles`)
- Built-in profiles: 8

### Verification

- All 16 modules import cleanly
- HTML report generation tested with single-module and 3-module runs;
  rollup tiles and priority findings render correctly
- 23 security validation test cases pass for `validate_profile_name`
  including injection, path traversal, command substitution, and
  length-DoS attempts
- Profile name `rhel9; rm -rf /` correctly rejected with `exit 2` and
  human-readable error
- All cache invariants from v3.6 still pass

---

## [3.5.0-gap-closure] - 2026-04-26 (Closure of v3.4 Gaps)

This release explicitly addresses the gap audit raised after v3.4. Each
section below maps to one of the user's five questions.

### Documentation refresh (Q1: main project docs)

- README.md - added v3.4-v3.5 Capabilities section (remediation library,
  pretty_name, mock test suite, Mermaid diagrams, runtime error fixes)
- SECURITY.md - supported-versions table refreshed; v3.3.x, v3.4.x, v3.5.x
  marked as currently supported; pre-3.0 versions transitioned to limited
  or end-of-life
- CONTRIBUTING.md - Testing Guidelines section rewritten to document the
  new `tests/` directory; deduplication of repeated checklist items;
  multi-distro testing matrix expanded to include zypper/pacman/apk

### Wiki refresh (Q2: wiki docs)

- Architecture-and-Design.md - v3.4 Mermaid diagrams already added (6 of
  them); v3.5 confirms accuracy
- Changelog.md - v3.4 and v3.5 entries appended at top of wiki page
- See `wiki/_Sidebar.md` and `wiki/_Footer.md` for v3.5 banner refresh

### Module expansion (Q3: framework coverage)

Documented in `tasks/todo.md`: ~1,286 checks remain below
internal targets across the 16 modules. v3.5 does NOT close this gap  - 
it documents the gap explicitly with prioritized phasing for v3.6+.

### Remediation library expansion (Q4: remediation parity)

`shared_components/remediation_library.py` rebuilt:

- **49 tools** registered (up from 30 in v3.4)
- **Per-family parity dramatically improved**: `verify` and `post_install`
  now populated for all relevant families per tool, not just Debian/RHEL
- **Service-name routing**: tools whose service name differs by family
  (e.g. clamav-daemon on Debian vs clamd on RHEL; chrony on Debian vs
  chronyd on RHEL/SUSE/Arch) route correctly per-family
- **New tool entries**: chkrootkit, gnupg, openssl, sudo, cron, rsyslog,
  logrotate, audisp-remote, sysstat, snort, zeek, wazuh-agent, grype,
  duplicity, iptables, bandit, pam-pwquality, pam-faillock, zypper-automatic
- **Mock test coverage**: `tests/test_remediation_library.py` (12 tests)
  asserts per-family parity, correct package manager syntax, and
  user-cited regressions (AIDE on Debian must include aide-common)

### OS detection robustness (Q5: dynamic OS identification)

`tests/test_os_detection.py` - 25 mock-based tests covering:

- Debian family: Ubuntu 22.04, Ubuntu 24.04, Ubuntu 26.04, Debian 12,
  Linux Mint 21, Pop!_OS 22, Kali 2024, Parrot 6
- Red Hat family: RHEL 9.4, CentOS Stream 9, Rocky 9.3, AlmaLinux 9.3,
  Fedora 40, Oracle Linux 9, Amazon Linux 2023
- SUSE family: openSUSE Leap 15.5, openSUSE Tumbleweed, SLES 15 SP5
- Arch family: Arch Linux, Manjaro, EndeavourOS
- Independent: Alpine 3.19, Gentoo

Universal invariants verified:

- `pretty_name` always populated (no "(unidentified)" markers for valid
  os-release content)
- `family` never resolves to "Unknown" for any registered fixture

The Ubuntu 26.04 case the user originally reported is now explicitly
covered by `test_ubuntu_26_04`.

---

## [3.6.0-perf-cache] - 2026-04-26 (Performance Optimization - Helper Caching)

### Added - Per-process caching layer in shared_components/module_helpers.py

The audit workflow makes overlapping helper calls across 16 modules:
- `command_available` called 1,079 times across modules (querying ~120 distinct commands)
- `systemd_active` called 496 times (querying ~50 distinct units)
- `run_command` called 527 times (querying ~100 distinct command-lines)
- `read_file_safe` called 819 times (reading ~85 distinct files)
- `file_exists`/`directory_exists` called 837 times combined
- `read_sysctl` called 100 times

v3.6 adds module-level dict caches for each helper, eliminating redundant
subprocess invocations and file reads within a single audit run. Caches:

- `_command_cache`: command_available results (PATH stable per audit run)
- `_systemd_active_cache`: systemctl is-active results
- `_systemd_enabled_cache`: systemctl is-enabled results
- `_run_command_cache`: keyed by (tuple(args), timeout)
- `_sysctl_cache`: /proc/sys reads
- `_file_content_cache`: keyed by (path, max_bytes)
- `_file_exists_cache`/`_directory_exists_cache`: stat results

Performance impact (sandbox testing):
- Cold-cache module run (e.g., ACSC standalone): ~7-25s
- Warm-cache module runs (e.g., HIPAA/GDPR after ACSC populated cache): 0.27-0.91s
- 5-30x speedup for downstream modules in a multi-module audit
- Speedup is highest for modules that share queries (most do - common
  services like auditd, fail2ban, AIDE; common files like /etc/ssh/sshd_config,
  /etc/audit/rules.d/*; common commands like systemctl, lsblk, ss)

### Added - `clear_caches()` API

Public function to invalidate all v3.6 caches. The orchestrator
`linux_security_audit.py` main() now calls clear_caches() at audit-run
start. This is a no-op for one-shot CLI invocations (process exits) but
matters for long-running supervisors that invoke main() in a loop and
need to observe state changes between iterations.

### Correctness

All caching is for read-only operations:
- subprocess calls in helpers query state (ss, ip, lsblk, getenforce,
  mokutil, systemctl is-active, etc.)
- File reads are pure
- /proc/sys reads are pure (we don't write sysctl values)

Invariant verification:
- `command_available`: True/False both cached correctly
- `read_sysctl`: returns identical value on repeat calls
- `file_exists`: True/False both cached
- `run_command`: tuple(args) keys distinguish different invocations
- `clear_caches`: resets all caches to empty

### Statistics

- 16 modules unchanged (no API or behavior changes)
- Helper-layer changes only (module_helpers.py: +60 lines for caching)
- All 2,319 checks confirmed runtime-clean post-optimization

---

## [3.5.15-core-deeper] - 2026-04-26 (Core v3.5 Baseline Hygiene Depth)

### Added - Core v3.5 (+16 checks, 175 -> 191 total)

**Sudo hygiene** (3 sub-controls):
- Defaults use_pty (PTY hijacking mitigation)
- Defaults logfile (separate sudo log)
- NOPASSWD count minimal (review threshold)

**User/group hygiene** (3 sub-controls):
- System accounts (UID 1-999) with login shells (should be none)
- Empty password hashes (critical)
- Default UMASK 027/077

**Mount hygiene** (2 sub-controls):
- /tmp restrictive mount (nodev/nosuid/noexec)
- /dev/shm restrictive mount

**Cron hygiene** (2 sub-controls):
- Cron file permissions (not world-writable)
- /etc/cron.allow allowlist preferred

**GRUB hygiene** (2 sub-controls):
- grub.cfg mode <= 0600
- GRUB superuser password set

**Service inventory** (2 sub-controls):
- Listening sockets count
- Legacy/risky services (rpcbind, NFS, avahi, telnet, etc.)

**PAM hygiene** (2 sub-controls):
- faillock deny <= 5
- pwquality minlen >= 14

---

## [3.5.14-cisa-deeper] - 2026-04-26 (CISA v3.5 SbD + KEV + ZTMM + Ransomware)

### Added - CISA v3.5 (+16 checks, 182 -> 198 total)

**CISA Secure by Design (SbD)** (3 sub-controls):
- P1 Customer outcome layers (signing + auto-patch)
- P2 Transparency/Accountability (audit + persistence + SBOM)
- P3 Org structure tools (git + config mgmt)

**CISA KEV (Known Exploited Vulnerabilities)** (2 sub-controls):
- Auto-patch active (KEV remediation timeline)
- Vuln scanning capability

**CISA Zero Trust Maturity Model (ZTMM) Pillars 1-5** (6 sub-controls):
- Pillar 1 Identity (MFA via PAM)
- Pillar 2 Devices (FIM database)
- Pillar 3 Networks (segmentation tooling)
- Pillar 4 Applications/Workloads (containers + MAC)
- Pillar 5 Data (LUKS at-rest encryption)
- Cross-cutting (visibility + automation + central logging)

**CISA Stop Ransomware** (3 sub-controls):
- 3-2-1 backup foundation + encryption
- Containment layers (firewall + MAC + mount)
- Anti-malware + EDR layers

**CISA Shields Up** (2 sub-controls):
- Comprehensive logging (auditd + persistent + SIEM)
- Backup automation (daily cron)

---

## [3.5.13-cis-deeper] - 2026-04-26 (CIS v3.5 Controls 16/17/18 + IG3)

### Added - CIS v3.5 (+17 checks, 252 -> 269 total)

**CIS Control 16 - Application Software Security** (3):
- 16.7 Hardening templates (oscap, lynis)
- 16.10 Secure design SAST tooling
- 16.11 Vetted modules (package signing)

**CIS Control 17 - Incident Response Management** (3):
- 17.1 IR notification capability
- 17.3 IR log preservation (auditd + persistent)
- 17.7 IR triage tooling

**CIS Control 18 - Penetration Testing** (2):
- 18.1 Pentest/vuln tooling
- 18.5 Scheduled re-test cadence

**CIS_Distribution_Independent_Linux Benchmark** (5):
- 1.5.1 ASLR full (randomize_va_space=2)
- 1.5.2 prelink not installed
- 1.6.x kptr_restrict >= 1
- 5.4.1.4 INACTIVE password lock <= 30 days
- 6.1 critical file permissions (passwd/shadow/group)

**CIS Docker Benchmark** (1-2 conditional):
- 1.1 Docker daemon audit
- 2.5 iptables NOT disabled

**CIS Kubernetes Benchmark** (1-2 conditional):
- 4.2.1 anonymous-auth=false
- 4.1.x kubelet.conf permissions

**CIS IG3 Advanced** (2):
- Advanced detection layers (osquery/Falco/Sysmon/auditd/OSSEC)
- Supply chain layers (SBOM + signing + GPG)

### Statistics

- CIS: 252 -> 269 checks
- CISA: 182 -> 198 checks
- Core: 175 -> 191 checks
- Project total: ~2,270 -> ~2,319 checks
- **All 16 modules now at v3.5 deeper expansion** (the v3.5 series is complete)

---

## [3.5.12-soc2-deeper] - 2026-04-26 (SOC 2 v3.5 Trust Service Criteria Depth)

### Added - SOC 2 v3.5 (+22 checks, 76 -> 98 total)

**Common Criteria (CC1-CC9):**
- CC1.4 Documentation
- CC2.2 Internal communication (email)
- CC3.2 Risk identification (vuln tools), CC3.4 change assessment (auditd)
- CC6.1 Logical access (MFA/pubkey), CC6.6 lockout, CC6.7 MAC, CC6.8 FIM
- CC7.1 anomaly detection, CC7.2 continuous monitoring, CC7.3 SIEM,
  CC7.4 IR, CC7.5 recovery
- CC8.1 change management
- CC9.1 risk mitigation

**Additional Criteria (Trust Service Criteria):**
- A1.2/A1.3 Availability - backup, snapshot, time sync, scheduled backups
- C1.1/C1.2 Confidentiality - LUKS+FIPS, sanitization tools
- PI1.1 Processing Integrity - package verification, FIM, debsums/rpm -V
- P3.1/P5.1 Privacy - at-rest encryption, erasure capability

---

## [3.5.11-enisa-deeper] - 2026-04-26 (ENISA v3.5 NIS2 + CRA + DORA)

### Added - ENISA v3.5 (+20 checks, 122 -> 142 total)

**NIS2 Directive Article 21** (9 sub-controls):
- (2)(a) Risk analysis tools
- (2)(b) Incident handling tooling
- (2)(c) Business continuity layers
- (2)(d) Supply chain security (SBOM + signing)
- (2)(e) Vulnerability handling (auto-patch)
- (2)(g) Cyber hygiene (CIS-aligned baseline)
- (2)(h) FIPS-aligned cryptography
- (2)(i) HR security (PAM lockout)
- (2)(j) MFA / continuous authentication

**EU Cyber Resilience Act (CRA) Annex I** (8 sub-controls):
- Sec 1: Cybersecurity baseline (FIPS)
- Sec 2(a): No known exploitable vulns (auto-patch)
- Sec 2(b): Security by default (firewall)
- Sec 2(c): Access protection (SSH hardening + sudo)
- Sec 2(d): Data integrity (FIM)
- Sec 2(e): Limited data processing (MAC)
- Sec 2(f): Minimal attack surface (<=5 listeners)
- Sec 2(j): Secure default configurations (UMASK)

**DORA (Digital Operational Resilience Act)** (2 sub-controls):
- Art 7 ICT risk management layers
- Art 17 Incident reporting capability

**ENISA Cloud Security** (1 sub-control):
- Multi-layer cloud security posture (FIPS, LUKS, MAC, central logging,
  auto-patch)

---

## [3.5.10-iso-deeper] - 2026-04-26 (ISO27001:2022 v3.5 Annex A Depth)

### Added - ISO27001 v3.5 (+15 checks, 134 -> 149 total)

**Organizational controls (A.5):**
- A.5.7 Threat intelligence integration (new in 2022)
- A.5.23 Information security for use of cloud services (new)
- A.5.30 ICT readiness for business continuity (new)

**Technological controls (A.8):**
- A.8.7 Anti-malware multi-layer defense
- A.8.8 Vulnerability management tooling + auto-patch
- A.8.10 Information deletion (new in 2022)
- A.8.11 Data masking (new in 2022)
- A.8.12 Data leakage prevention (new in 2022)
- A.8.16 Monitoring activities (new in 2022)
- A.8.20/A.8.22 Network security and segregation
- A.8.25/A.8.28 Secure development life cycle
- A.8.31 Dev/test/production separation
- A.8.32 Change management (etckeeper, ansible, audit)

### Statistics

- ISO27001: 134 -> 149 checks
- ENISA: 122 -> 142 checks
- SOC2: 76 -> 98 checks
- Project total: ~2,213 -> ~2,270 checks

---

## [3.5.9-cmmc-deeper] - 2026-04-26 (CMMC v3.5 NIST 800-171 Rev 3 + L3 Depth)

### Added - CMMC v3.5 (+17 checks, 77 -> 94 total)

**NIST SP 800-171 Rev 3 (May 2024) updates** (4 sub-controls):
- 03.05.07 Password length minlen >= 14 (Rev 3 emphasizes length)
- 03.13.11 FIPS 140-3 cryptographic key establishment
- 03.14.01 Flaw remediation auto-patching
- 03.13.08 Cryptographic protection in transit (SSH AES-256)

**Level 3 (NIST SP 800-172) enhancement controls** (5 sub-controls):
- 3.1.3e Concurrent session limit (PAM maxlogins)
- 3.4.1e Architecture diversity (multi-arch detection)
- 3.13.4e DLP indicators (egress firewall, DNS filter, audit watch)
- 3.14.6e SIEM forwarding for near-real-time analysis
- 3.6.1e SOC integration (4-layer monitoring stack)

**CUI handling** (3 sub-controls):
- 03.13.16 CUI cryptographic protection at rest (LUKS + FIPS)
- 03.08.03 Media sanitization tooling
- 03.08.04 CUI marking capability (SELinux/AppArmor MAC)

**Assessment readiness** (2 sub-controls):
- Assessment evidence tooling (lynis, openscap, auditd, AIDE, package signing)
- SPRS scoring evidence (lynis history, openscap reports)

**DFARS additional** (2 sub-controls):
- 252.204-7012 ICTRS reporting capability (mail)
- 252.204-7020 Continuous compliance (auditd + AIDE)

**ESP/CSP readiness** (1 sub-control):
- FedRAMP Moderate crypto baseline alignment
- Cloud-managed agent detection (AWS SSM, Azure Monitor, GCP Ops)

---

## [3.5.8-edr-deeper] - 2026-04-26 (EDR v3.5 Detection-as-Code + Forensics)

### Added - EDR v3.5 (+11-25 checks conditional, 76 -> 87+ total)

**Detection-as-code engines** (3 sub-controls):
- YARA scanner + rules directory
- Sigma rule tooling (sigma/sigmac/pysigma)
- Detection engines active (Wazuh/OSSEC, Falco, ClamAV)

**Cloud-native EDR agents** (1 sub-control, conditional):
- AWS Inspector, AWS SSM, Azure Monitor, Azure Defender, GCP Ops Agent,
  Datadog, Wiz Sensor

**Container runtime EDR** (1-3 sub-controls, conditional):
- Falco rules count
- Tetragon (Cilium runtime detection)
- Tracee (Aqua Security)

**Endpoint forensics tooling** (1 sub-control):
- Velociraptor, GRR, log2timeline (plaso), Volatility 3, TheHive Cortex,
  MISP, AVML, LiME, dumpe2fs

**Network traffic analysis** (1 sub-control):
- Zeek, Arkime/Moloch, Suricata, Snort, Brim/Zui, ntopng, tcpdump

**Honeypot/decoy** (1 sub-control):
- Cowrie, OpenCanary, Honeyd, T-Pot, Dionaea, Glastopf, canary tokens,
  honeyfile audit

**EDR anti-tamper** (1-2 sub-controls):
- EDR services enabled (cannot be casually stopped)
- EDR config audit rules

**MITRE ATT&CK coverage** (1 sub-control):
- Maps audit rules to T1003, T1059, T1098, T1543, T1547, T1562, T1070
- Reports % coverage of common techniques

**Live response** (2 sub-controls):
- Triage tooling (lsof, strace, gdb, perf, bpftrace, bcc-tools)
- Memory acquisition (AVML, LiME, /proc/kcore)

---

## [3.5.7-nsa-deeper] - 2026-04-26 (NSA v3.5 CNSA 2.0 + Modern Guidance)

### Added - NSA v3.5 (+21 checks, 172 -> 193 total)

**CNSA 2.0 quantum-resistant cryptography readiness** (4 sub-controls):
- OpenSSL 3.x detection (Provider API + CNSA 2.0 algorithm support)
- SSH AES-256 minimum
- SSH SHA-384/512 MACs
- Asymmetric host key strength (ED25519 / ECDSA P-384+ / RSA-3072+)

**NSA Kubernetes Hardening Guide V1.2** (1-4 conditional):
- K8s presence
- anonymous-auth disabled
- readOnlyPort disabled
- Container runtime audit
- K8s configuration audit rules

**NSA Encrypted DNS Implementation** (2 sub-controls):
- DNS security posture (DNSOverTLS + DNSSEC + systemd-resolved)
- /etc/resolv.conf via local resolver

**NSA VPN Configuration Guidance** (1-2 sub-controls):
- VPN tooling (WireGuard, strongSwan, Libreswan, OpenVPN)
- IKEv2 IPsec configuration

**NSA Memory Safety guidance** (4 sub-controls):
- ASLR full (randomize_va_space=2)
- KASLR enabled (no nokaslr)
- glibc 2.31+ hardening
- Sanitizer tooling (ASan, Valgrind)

**NSA eBPF Security guidance** (3 sub-controls):
- Unprivileged BPF disabled
- BPF JIT hardening
- eBPF LSM availability

**NSA Software Supply Chain** (3 sub-controls):
- SBOM tooling (syft, trivy, cyclonedx)
- Artifact signing (cosign, minisign, gpg)
- Package signature verification (apt keyrings, rpm gpgcheck)

**NSA Secure/Measured Boot** (2 sub-controls):
- UEFI Secure Boot enabled
- TPM 2.0 / Measured Boot capability

**NSA Active Cybersecurity Monitoring** (2 sub-controls):
- SIEM forwarders (rsyslog, syslog-ng, auditd remote, OSSEC, Splunk,
  Filebeat, Vector, Fluentd)
- Continuous monitoring stack (auditd + AIDE + fail2ban)

### Statistics

- NSA: 172 -> 193 checks
- EDR: 76 -> 87+ checks (more on systems with EDR services)
- CMMC: 77 -> 94 checks
- Project total: ~2,170 -> ~2,213 checks

### Fixed

- L15 (recurring) - sum() with potentially-None values caught during NSA
  v3.5 isolated function testing. encrypted_dns helper fixed with bool()
  coercion before reaching production. L18 (audit-before-expansion)
  pattern continues to pay dividends.

---

## [3.5.6-stig-deeper] - 2026-04-26 (STIG v3.5 SRG Coverage Expansion)

### Added - STIG v3.5 Application/Web/DB/Network/Container SRG (+12-25 conditional)

DISA STIG SRG areas underrepresented in v3.4. Many checks are conditional
(web server only fires when nginx/Apache present, DB only when DB active,
container only when docker/podman present), so static count is higher
than minimum runtime.

**SRG-APP-SRC Application Security and Development (3 sub-controls):**
- SRG-APP-000033 SAST tooling (shellcheck, bandit, semgrep, pylint)
- SRG-APP-000503 Cryptographic key management (openssl, gnutls, TPM, PKCS#11)
- SRG-APP-000089 Application audit (auditd watching /opt, /usr/local, /srv)

**SRG-APP-WEB Web Server STIG (3-6 sub-controls, conditional):**
- nginx: server_tokens off, TLSv1.2/1.3 only, HSTS header
- Apache: ServerTokens Prod, SSLProtocol -all +TLSv1.2 +TLSv1.3

**SRG-APP-DB Database STIG (1-3 sub-controls, conditional):**
- PostgreSQL: pg_hba.conf trust auth absent (V-258134)
- MySQL/MariaDB: bind-address restrictive, TLS configured

**SRG-APP-CTR Container Platform (3 sub-controls, conditional):**
- SRG-APP-000118-CTR Docker audit rules (paths and binaries)
- Rootless container capability (podman / dockerd-rootless-setuptool)
- Image scanning tools (trivy, grype, syft)

**SRG-NET Network Device (3 sub-controls):**
- SRG-NET-000131 Default-deny network (ufw / firewalld / nftables)
- SRG-NET-000074 Anti-spoofing (rp_filter strict)
- SRG-NET-000235 Source-routed packet rejection

**Additional V-numbers (3 sub-controls):**
- V-258134 (RHEL9) SSH KexAlgorithms FIPS-aligned
- V-258153 audit.log mode <= 0600
- V-258109 System banners (/etc/issue, /etc/issue.net, /etc/motd)
- V-260567 (Ubuntu) apt HTTPS repositories

### Statistics

- STIG: 198 -> ~210 checks runtime-confirmed
- Project total: ~2,157 -> ~2,170 checks (more on web/DB/container hosts)

---

## [3.5.5-nist-deeper] - 2026-04-26 (NIST v3.5 Underrepresented Family Expansion)

### Added - NIST v3.5 (+31 checks; static count, runtime-confirmed)

NIST 800-53 Rev 5 underrepresented control families plus CSF 2.0 and SSDF
800-218 coverage. Targets families with low pre-existing coverage (CA, CP,
MA, MP, RA, SA, PT, etc.) and CSF 2.0 DETECT/RESPOND/RECOVER subcategories.

**CA - Assessment, Authorization, Continuous Monitoring (4 sub-controls):**
- CA-7 Continuous monitoring tools (auditd + AIDE + logwatch + fail2ban + OSSEC + lynis)
- CA-2 Control assessment tools (OpenSCAP, Lynis, Trivy, Nuclei)
- CA-5 POA&M tooling indicator (git, package caches)
- CA-9 Internal system connections (LISTEN socket count)

**CP - Contingency Planning (5 sub-controls):**
- CP-9 Backup tooling presence (rsync, borg, restic, duplicity, bacula, etc.)
- CP-9(8) Encrypted backup capability
- CP-9 Backup automation (cron / systemd timer)
- CP-10 Recovery tools (kexec-tools, dracut, mkinitcpio)
- CP-10(4) Filesystem snapshot capability (zfs, btrfs, lvm, snapper)

**MA - Maintenance (3 sub-controls):**
- MA-2 Maintenance audit trail (dpkg.log, dnf.log, etc.)
- MA-3 Maintenance tools inventory
- MA-4 Nonlocal maintenance hardening (SSH PermitRootLogin)

**MP - Media Protection (3 sub-controls):**
- MP-2 USB device authorization (usbguard)
- MP-6 Media sanitization (shred, scrub, srm, hdparm, cryptsetup)
- MP-7 Mount option restrictions (nodev/nosuid/noexec)

**RA - Risk Assessment (3 sub-controls):**
- RA-5 Vulnerability tools (lynis, openscap, trivy, grype, nuclei, rkhunter, chkrootkit, debsecan)
- RA-5 Scheduled scans (cron presence)
- RA-10 Threat hunting (osquery, Falco, Sysmon, auditd, Wazuh)

**SA - System and Services Acquisition (3 sub-controls):**
- SA-3 SDLC tooling (git, gh, make, docker, podman)
- SA-11 Developer security testing (shellcheck, bandit, semgrep, flake8, pylint, yamllint)
- SA-15/SA-22 Supply chain security (container runtime + cosign + syft/trivy)

**PT - PII Processing (1 sub-control):**
- PT-3 PII protection layers (LUKS, fscrypt, ecryptfs)

**CSF 2.0 DETECT/RESPOND/RECOVER (5 subcategories):**
- DE.CM-1 Network monitoring (tcpdump, Suricata, Snort, Zeek)
- DE.CM-3 Personnel activity logging (auditd auid filter)
- RS.RP-1 IR tooling (tcpdump, lsof, strace, ausearch, journalctl)
- RS.CO-2 IR notification capability (mail/postfix)
- RC.RP-1 Recovery layers (backup tooling + snapshots)

**SSDF 800-218 (4 practices):**
- PO Trusted build environment (containers + SBOM)
- PS.1 Code provenance (git + GPG signed commits)
- PW.7/PW.8 Code review tools (shellcheck, yamllint, flake8/pylint, bandit)
- RV.1 Vulnerability identification (trivy, grype, lynis, openscap)

### Statistics

- NIST: 204 -> ~235 checks runtime-confirmed (static count higher due to
  conditional logic)
- Project total: ~2,126 -> ~2,157 checks

---

## [3.5.4-gdpr-deeper] - 2026-04-26 (GDPR v3.5 Deeper Expansion)

### Added - GDPR v3.5 Article Technical Depth (+21 checks, 54 -> 75 total)

**Article 5(1)(e) Storage limitation** (3 sub-controls):
- logrotate present + scheduled
- systemd-tmpfiles-clean.timer for /tmp purging
- auditd explicit retention configuration (max_log_file x num_logs)

**Article 17 Right to erasure depth** (3 sub-controls):
- Secure-delete tooling (shred, srm, scrub, wipe)
- Swap encryption (LUKS or /dev/mapper) - prevents data persistence in swap
- fstrim.timer for SSD block unmapping (essential for SSD secure erasure)

**Article 20 Right to data portability** (2 sub-controls):
- Export tooling (jq, csvkit, xmlstarlet, yq, pandoc)
- DB client tools (psql, mysql, sqlite3, mongo)

**Article 25(2) Privacy by default** (3 sub-controls):
- Network default-deny (ufw / firewalld zone drop|block)
- Minimal external listening services (<=5 non-loopback)
- Default UMASK 027 or 077 (privacy-friendly file creation)

**Article 32 Crypto depth** (3 sub-controls):
- CSPRNG availability (/dev/urandom, poolsize, rngd/haveged)
- Password hash algorithm strength (yescrypt > sha512)
- Pseudonymization tooling (openssl, gpg, age, minisign)

**Article 33 Breach detection depth** (4 sub-controls):
- SIEM forwarding (rsyslog @@/omfwd, journal-upload) - for 72h notification
- Real-time alerting (auditd email, fail2ban, logwatch, OSSEC)
- Time accuracy (NTP/chrony/timesyncd) - for breach timeline
- Evidence preservation (audit ruleset immutable -e 2)

**Articles 15-22 Data subject rights** (2 sub-controls):
- Email capability for subject communication (Art 12 1-month deadline)
- Activity-log query tools (journalctl, ausearch/aureport for Art 15 requests)

**Article 35 DPIA indicators** (1 sub-control):
- High-risk processing markers (public web/DB, video capture, geolocation,
  orchestration) - used to indicate DPIA likely required

---

## [3.5.3-hipaa-deeper] - 2026-04-26 (HIPAA v3.5 Deeper Expansion)

### Added - HIPAA v3.5 Security Rule Technical Depth (+25 checks, 89 -> 114 total)

**164.312(a)(2)(i) Unique user identification depth** (3 sub-controls):
- Generic account detection (admin, user, guest, test, demo, ephi, etc.)
- UID uniqueness (no duplicates)
- UID_MIN >= 1000

**164.312(a)(2)(iii) Automatic logoff depth** (3 sub-controls):
- Shell TMOUT (15 minutes, readonly)
- SSH ClientAlive (interval x count_max <= 900s)
- Desktop screen lock (gnome / xscreensaver) when GUI present

**164.312(a)(2)(iv) Encryption depth** (4 sub-controls):
- FIPS 140-3 mode (crypto.fips_enabled)
- Crypto-policies (RHEL FUTURE/FIPS)
- CA bundle freshness (<=180 days)
- SSH host keys (ED25519 preferred, no DSA)

**164.312(b) Audit controls depth** (4 sub-controls):
- Per-user audit (auid filter rules)
- Audit log access tracking (-w /var/log/audit -p wra)
- Audit ruleset immutable (-e 2)
- journald discipline (Storage=persistent + Seal=yes)

**164.312(c)(2) Integrity authentication** (3 sub-controls):
- FIM database present (AIDE, Tripwire, Samhain, OSSEC, Wazuh)
- Package verification tool (debsums, rpm -Va)
- Kernel-level integrity (dm-verity, IMA)

**164.312(d) Person/entity authentication depth** (3 sub-controls):
- MFA enforcement (AuthenticationMethods + PAM modules)
- SSH pubkey-only (PasswordAuthentication=no)
- Account lockout (PAM faillock / pam_tally2)

**164.312(e) Transmission security** (3 sub-controls):
- Network encryption layer (IPsec / WireGuard)
- nginx TLS strict (TLSv1.2/1.3 only)
- Apache TLS strict (SSLProtocol -all +TLSv1.2 +TLSv1.3)

**164.402-410 Breach notification readiness** (4 sub-controls):
- Audit retention capacity (>=1GB rolling)
- Email alerting capability
- User identification capability (auid tracking)
- Time sync (timeline accuracy)

**164.308(a)(1) Risk Analysis** (2 sub-controls):
- Vulnerability scanners present (lynis, openscap, trivy, etc.)
- Activity review tooling (logwatch, logcheck, OSSEC, auditd)

### Statistics

- HIPAA: 89 -> 114 checks
- GDPR: 54 -> 75 checks
- Project total: ~2,080 -> ~2,126 checks

---

## [3.5.2-acsc-deeper] - 2026-04-26 (ACSC v3.5 Deeper Expansion)

### Added - ACSC v3.5 Essential Eight ML3 + ISM Advanced

`modules/module_acsc.py` v3.5 expansion (+23 runtime-confirmed checks,
46 -> 69 total).

**Essential Eight ML3 depth (5 sub-controls):**
- E8.1 ML3 Cryptographic application verification (signature verification +
  fapolicyd/AppArmor enforcement)
- E8.5 ML3 Admin restriction (NOPASSWD audit + timestamp_timeout)
- E8.7 ML3 Phishing-resistant MFA (FIDO/U2F, Yubico, FIDO2 detection)
- E8.6 ML3 Automated patching (unattended-upgrades / dnf-automatic active)
- E8.4 ML3 User application hardening (browser policies)

**ISM cryptographic algorithm conformance (4 sub-controls):**
- SSH KexAlgorithms AACA-compliance (no SHA-1, no diffie-hellman-group1/14)
- SSH Ciphers AACA-compliance (AES-CTR/GCM only; no CBC, RC4, 3DES)
- SSH MACs AACA-compliance (SHA-2 family only; no MD5, no SHA-1)
- FIPS 140-3 mode

**ISM network segmentation (4 sub-controls):**
- Network interface inventory
- Reverse-path filtering (rp_filter)
- ICMP redirect acceptance disabled
- IPv6 configuration audit

**ISM logging centralization (3 sub-controls):**
- Centralized log forwarding (rsyslog @@/omfwd, syslog-ng remote,
  systemd-journal-upload)
- Audit retention capacity (max_log_file x num_logs)
- Log failure fail-safe actions (space_left_action, disk_full_action)

**ISM account separation (3 sub-controls):**
- UID 0 uniqueness (no non-root UID-0 accounts)
- Privileged group membership (wheel/sudo/admin)
- SUID/SGID inventory

**ISM email hardening - host-level (2 sub-controls):**
- Postfix outbound TLS (smtp_tls_security_level)
- Postfix inbound TLS (smtpd_tls_security_level)

**ISM incident response readiness (3 sub-controls):**
- Forensic tool availability (gdb, strace, ltrace, lsof, tcpdump, ss, etc.)
- journald forensic readiness (persistent journal)
- Network packet capture capability

### Statistics

- ACSC: 46 -> 69 checks runtime-confirmed
- Project total: ~2,057 -> ~2,080 checks

---

## [3.5.1-distbase-deeper] - 2026-04-26 (DistBaseline v3.5 Deeper Expansion)

### Added - DistBaseline v3.5 advanced distribution features

`modules/module_distbaseline.py` v3.5 expansion (+16-30 runtime, depends on
distribution and installed features). Static check count: ~110-115 because
many checks are conditional on distribution-specific features being present.

**Ubuntu Pro features** (active on Ubuntu only):
- pro/ua client presence
- Subscription attached state
- Livepatch (kernel hot-patching)
- ESM Infrastructure / Apps (10-year extended security support)
- USG (Ubuntu Security Guide hardening tooling)
- Realtime kernel detection

**RHEL Insights / subscription-manager** (RHEL family only):
- subscription-manager presence and attachment status
- Insights client (proactive vulnerability advisor)
- RHUI (cloud Red Hat Update Infrastructure) detection

**Snap / Flatpak host-level confinement**:
- Snap inventory and version
- Snap sensitive interface grants (home, system-files, raw-usb,
  removable-media, block-devices, kernel-module-load, raw-volume,
  personal-files)
- Flatpak inventory
- Flatpak host-filesystem overrides (filesystems=host detection)

**journald discipline**:
- Storage=persistent (logs survive reboot - required for PCI 10.5)
- Compression
- SystemMaxUse retention limit
- ForwardToSyslog (rsyslog forwarding for SIEM/centralized logging)
- Forward Secure Sealing (Seal=yes for tamper detection)
- SystemMaxFileSize per-file rotation

**Disk integrity**:
- fstrim.timer for SSD trim
- btrfs scrub timer detection
- ZFS scrub schedule
- Swap encryption (LUKS or /dev/mapper)

**System integrity markers**:
- machine-id consistency (/etc vs /var/lib/dbus)
- /etc/cron.allow allowlist (preferred over /etc/cron.deny)
- /etc/at.allow allowlist
- cron file permissions (no world-writable)

**Advanced firewall depth**:
- nftables tables/chains/rules count
- nftables INPUT default-drop policy
- firewalld default zone (drop/block preferred)
- firewalld active zones count

**kdump and panic-on-oops**:
- kdump.service active (RHEL family)
- kernel.panic_on_oops sysctl
- kernel.panic timeout

**LSM advanced**:
- Active LSM list from /sys/kernel/security/lsm
- eBPF LSM availability
- IMA appraisal mode (ima_appraise= on cmdline)
- File capabilities audit (setcap binaries)

### Fixed

- Bare-string-in-dict syntax errors (L19): single-line dict literals like
  `{"NIST": "AU-9", "SI-7"}` produce `SyntaxError: ':' expected after dictionary key`.
  Robust regex fix now handles both multi-line and single-line patterns.

### Statistics

- DistBaseline: 74 -> 90 checks runtime-confirmed (sandbox; static count
  is higher due to conditional Ubuntu/RHEL specific checks)
- Project total: ~2,041 -> ~2,057 checks

---

## [3.5.0-pci-deeper] - 2026-04-26 (PCI v3.5 Deeper Expansion + Quality Sweep)

### Added - PCI v3.5 deeper sub-requirement coverage

`modules/module_pci.py` PCI v3.5 expansion (+47 runtime-confirmed checks,
63 -> 110 total). Comprehensive PCI DSS v4.0.1 sub-requirement depth:

**Req 2.2 - System component configuration standards (7 sub-controls)**
- 2.2.1 Configuration management tooling indicator
- 2.2.2 Vendor default account lockdown verification
- 2.2.3 Active service count (primary function principle)
- 2.2.4 Risky/unnecessary services audit (telnet, rsh, rlogin, rexec, tftp,
  nfs, rpcbind, avahi, cups)
- 2.2.5 Cleartext-protocol listener detection (FTP/Telnet/TFTP/rexec/rlogin/rsh)
- 2.2.6 Kernel hardening sysctls (kptr_restrict, dmesg_restrict,
  protected_hardlinks/symlinks, randomize_va_space)
- 2.2.7 SSH Protocol 2 enforcement (no SSHv1)

**Req 3.5/3.6/3.7 - PAN protection and key management (5 sub-controls)**
- 3.5.1 PAN unreadable layers (LUKS + crypto libs)
- 3.5.1.1 Strong hash availability (SHA-2 family via OpenSSL)
- 3.6.1 Hardware key protection (TPM 2.0 / PKCS#11 / HSM)
- 3.7.1 Key management procedures (crypttab presence)
- 3.7.2 Key generation entropy (urandom + rngd)
- 3.7.x Key file directory permissions (/etc/ssl/private etc.)

**Req 5.2/5.3 - Anti-malware deployment and operation (5 sub-controls)**
- 5.2.1 Anti-malware solution deployed (7 vendor products)
- 5.2.2 Signature freshness (<= 7 days)
- 5.3.1 Mechanism active
- 5.3.2 Periodic scans scheduled
- 5.3.3 Cannot be disabled by users

**Req 7.2/7.3 - Access definition and enforcement (5 sub-controls)**
- 7.2.1 Access control system (PAM + sudo + MAC)
- 7.2.2 Least privilege (broad sudo grants count)
- 7.2.4 Account inactivity review (<= 180 days)
- 7.3.1 Access enforcement (no nullok)
- 7.3.2 Network default-deny (ufw / firewalld zone)

**Req 8.3/8.4/8.6 - Strong authentication, MFA, application credentials (7 sub-controls)**
- 8.3.1 No null authentication
- 8.3.2 Strong password hash (SHA512/yescrypt)
- 8.3.5/8.3.7 Password reuse prevention (pam_pwhistory)
- 8.3.6 Password complexity v4.0.1 minlen >= 12
- 8.3.9 Password aging <= 90 days
- 8.4.1 MFA for admin access (6 PAM modules detected + AuthenticationMethods)
- 8.6.1 System accounts locked
- 8.6.2 No hardcoded credentials in cron scripts

**Req 10.2/10.3/10.6 - Audit log content, integrity, time sync (12 sub-controls)**
- 10.2.1.1 User access logged (execve + auid)
- 10.2.1.2 Admin actions logged (privileged audit)
- 10.2.1.3 Audit log access monitored
- 10.2.1.4 Failed login auditing (faillock/faillog)
- 10.2.1.5 IAM changes logged (PAM + passwd/shadow)
- 10.2.1.6 Audit system events (auditctl/auditd)
- 10.2.1.7 Kernel module load/unload audit
- 10.3.1 Audit log file permissions (0600)
- 10.3.4 FIM on audit logs
- 10.6.1 Time synchronization service active
- 10.6.2 Authoritative NTP/chrony servers configured
- 10.6.3 NTS-authenticated time sources

**Req 11.4/11.5/11.6 - IDS/IPS, change detection, vuln testing (5 sub-controls)**
- 11.4 Vulnerability scanners (5 tools detected)
- 11.5.1 IDS/IPS deployed (6 products: Suricata, Snort, Zeek, Wazuh, Falco, OSSEC)
- 11.5.1.1 Egress monitoring (rsyslog forwarding)
- 11.5.2 FIM scheduled execution
- 11.6.1 Web tier tamper detection (ModSecurity/CRS)

### Quality Sweep - runtime audit of all v3.x expansion code

Performed comprehensive audit:
- 294 v3.x check functions exercised across all 16 modules
- 551 audit results generated
- **0 runtime errors** found
- Static analysis swept for `int(x, base)` with non-string operand (only the
  one DistBaseline case found and previously fixed)
- Static analysis swept for `re.search(...).group()` without None guard
  (all instances are safe short-circuit idioms: `m and m.group()`,
  `m.group() if m else default`, or `not m or m.group()`)
- Sweep for `sum([..., x and "lit" in x])` patterns where x might be string
  (only the one NIST AU-9(2) case found and previously fixed)

### Changed

- Updated tasks/lessons.md with L18 (audit before expansion).
- Updated tasks/todo.md with v3.5 phase completion.
- Module-Inventory.md updated to reflect PCI ~110 checks.

### Statistics

- Project: ~2,041 checks (was ~1,994; +47 from PCI v3.5)
- PCI gap closed: 63 -> 110 (target 200; remaining gap -90)

---

## [3.4.0-quality-hardening] - 2026-04-26 (Quality & Correctness Hardening)

### Fixed

- **OS detection display**: Orchestrator (`linux_security_audit.py`) now uses
  `os_detection.detect_os().pretty_name` (e.g. "Ubuntu 24.04.4 LTS") for the
  Operating System display string instead of `platform.system() +
  platform.release()` which produced the inaccurate "linux ###-generic"
  on Ubuntu 24.04.4 and Ubuntu 26.04. Two callsites updated:
  prerequisite check and shared_data construction.
- **`OSInfo.pretty_name`** field added with intelligent multi-tier fallback:
  os-release PRETTY_NAME -> lsb-release DISTRIB_DESCRIPTION -> marker file
  content -> composed from distro_name+version_id -> final platform fallback
  with explicit "(unidentified)" marker.
- **DistBaseline TypeError**: `int(mode, 8)` at line 2080 now uses `mode`
  directly (it's already an int from `file_mode()`); the second argument
  to `int()` is only valid for string inputs. The previous code raised
  `TypeError("int() can't convert non-string with explicit base")`.
- **NIST AU-9(2) TypeError**: `audisp_set = audisp_remote and "remote_server"
  in audisp_remote` returned the empty string when audisp_remote was empty,
  not False. `sum([rsy_remote, audisp_set])` then raised
  `TypeError("unsupported operand type(s) for +: 'int' and 'str'")`. Fixed
  with explicit `bool()` coercion.

### Added - `shared_components/remediation_library.py`

A new comprehensive distro-aware remediation library with 30 tool entries:

- **File integrity / HIDS**: aide, auditd, tripwire
- **Intrusion prevention**: fail2ban
- **Device control**: usbguard
- **MAC / allowlisting**: apparmor, selinux, fapolicyd
- **Anti-malware**: clamav, rkhunter
- **Vulnerability scanning**: lynis, openscap
- **Firewalls**: ufw, firewalld, nftables
- **Time sync**: chrony (with NTS guidance)
- **Patch automation**: unattended-upgrades, dnf-automatic
- **MFA**: pam-google-authenticator, pam-yubico
- **Encryption**: cryptsetup
- **Backup**: borg, restic
- **NSM/IDS**: suricata
- **EDR/visibility**: osquery, falco
- **SBOM/SCA**: syft, trivy
- **VPN**: wireguard
- **SAST**: shellcheck

Each entry includes:

- **primary_packages**: Per-family minimum packages (e.g. AIDE on Debian
  needs `aide`)
- **supporting_packages**: Per-family additional packages required for full
  functionality (e.g. AIDE on Debian also needs `aide-common` for the
  `aideinit` wrapper and daily cron job)
- **post_install**: Per-family ordered configuration commands
- **services**: systemd unit names to enable + start
- **verify**: Per-family verification commands
- **config_files**: Paths the operator should review/edit
- **notes**: Caveats, ordering requirements, distribution quirks
- **references**: Authoritative upstream documentation URLs

### Wired into all 16 modules

- `remediation_for(tool_id)` helper inserted into every module
- 89 ad-hoc remediation strings replaced with library calls (37 single-line
  + 26 multi-line + 26 sweeps)
- Graceful fallback when tool_id is not in library or when family is unknown

### Architecture wiki

Added 6 Mermaid diagrams to `Architecture-and-Design.md`:

- System architecture (orchestrator -> modules -> outputs)
- Module execution lifecycle (sequence diagram showing cache, OS detection,
  remediation library wiring)
- Cache hierarchy
- Remediation library flow
- OS detection decision tree (priority order: os-release -> lsb-release ->
  marker files -> fallback)
- Audit pipeline phases (validation -> correlation -> risk -> compliance ->
  baseline diff)

ASCII art diagrams replaced with Mermaid where they existed previously.

### Changelog wiki

Added Version 3.3 and Version 3.4 entries at top of `wiki/Changelog.md`.

---

## [3.3.2-final-existing] - 2026-04-26 (Phase 2 v3.3 Complete - All 16 Modules)

### Added - Final 4 Existing Modules Expanded

Phase 2 v3.3 expansion is now complete across **all 16 framework modules**.
This release adds the remaining 4 existing-module expansions:

**modules/module_cisa.py** v3.3 (147 -> ~182 checks, +~35)
- CISA Cross-Sector Cybersecurity Performance Goals (CPG v1.0.1):
  Account Security (2.A-2.H), Data Security (2.K-2.N), Vulnerability
  Management (2.O-2.S), Supply Chain (2.T-2.U), Response/Recovery (2.V-2.W)
- CISA Zero Trust Maturity Model (ZTMM) v2.0: 5 Pillars (Identity,
  Devices, Networks, Applications, Data) + Cross-cutting (Visibility,
  Automation, Governance)
- CISA Binding Operational Directives: BOD 22-01 (KEV), BOD 23-01 (asset
  visibility)
- CISA Secure by Design principles: memory-safe languages, default
  secure configs, hardening principles

**modules/module_enisa.py** v3.3 (97 -> 122 checks, +25 confirmed runtime)
- NIS2 Directive Article 21.2 - all 10 cybersecurity risk-management
  measures (a-j): risk analysis, incident handling, business continuity,
  supply chain, acquisition security, effectiveness assessment, cyber
  hygiene, cryptography, access control, MFA
- DORA (Digital Operational Resilience Act) Articles 6, 9, 10, 11, 12 -
  ICT risk management, identification, protection, detection, response
- ENISA Threat Landscape - top threats: ransomware, malware, social
  engineering, data threats, DDoS, disinformation, supply chain
- EU Cybersecurity Act Article 51: Basic, Substantial, High assurance levels

**modules/module_iso27001.py** v3.3 (115 -> ~134 checks, +~19)
- ISO 27001:2022 Annex A.8.27-A.8.34: secure architecture, secure coding,
  security testing, environment separation, change management, audit
  protection
- ISO/IEC 27017:2015 cloud-specific controls: CLD.6.3.1 (shared roles),
  CLD.8.1.5 (asset removal), CLD.9.5.1 (virtual segregation),
  CLD.12.1.5 (admin security), CLD.12.4.5 (cloud monitoring),
  CLD.13.1.4 (network management)
- ISO/IEC 27018:2019 PII processor controls: A.4.1, A.10.1, A.11.2
- ISO/IEC 27701:2019 Privacy Information Management: 7.4 (privacy by
  default), 7.5 (pseudonymization), 8.4 (erasure)

**modules/module_core.py** v3.3 (153 -> ~175 checks, +~22)
- Per-service systemd hardening directives (sshd, journald, auditd,
  rsyslog, chrony, cron) - average score across 8 hardening directives
- Advanced kernel features: lockdown mode, IMA, module sig_enforce,
  CPU vulnerability mitigations (Meltdown, Spectre, MDS, L1TF, SRBDS,
  TSX async abort), user namespace controls
- Secure boot chain: UEFI/EFI variables, mokutil Secure Boot state,
  GRUB password protection
- SUSE-specific: snapper, AppArmor, zypper repos
- Arch-specific: pacman keyring, SigLevel strict, reflector
- Container host hardening: cgroup v2, Docker daemon hardening directives
- Time security: NTS-authenticated time sync (chrony nts directive)
- Filesystem advanced: btrfs/zfs detection, /tmp on tmpfs

### Fixed

- **CISA pre-existing datetime bug**: `datetime.datetime.now()` in
  `__main__` block conflicted with `from datetime import datetime`.
  Changed to `datetime.now()`.

### Cumulative Phase 2 v3.3 Status

All 16 modules now have v3.3 expansions:
- 8 new modules: 555 checks (was 151 baseline; +404)
- 8 existing modules: ~1,439 checks (was 1,207 baseline; +~232)
- **Project total estimate: ~1,994 checks** (+636 from 1,358 v3.0 baseline)

---

## [3.3.1-existing-modules] - 2026-04-26 (Phase 2 Existing-Module v3.3)

### Added - Phase 2 Expansion of Originally-Existing Modules

The Phase 2 expansion has now extended into the 8 originally-existing
framework modules. Adds **+~131 checks** (static count) across CIS, NIST,
NSA, and STIG:

**modules/module_cis.py** v3.3 (212 -> ~252 checks, +~40)
- CIS 5.2.13-5.2.22 advanced SSH hardening (Ciphers, MACs, KexAlgorithms,
  HostKeyAlgorithms, LoginGraceTime, MaxAuthTries, MaxStartups, MaxSessions,
  AllowTcpForwarding, PermitUserEnvironment)
- CIS 5.4.1.x faillock (deny, unlock_time)
- CIS 5.4.2.x pwquality (minlen, dcredit/ucredit/ocredit/lcredit, minclass,
  maxrepeat, dictcheck)
- CIS 5.4.3 pam_pwhistory remember count
- CIS 5.4.4 ENCRYPT_METHOD (SHA512/yescrypt)
- CIS 4.1.3.1-4.1.3.20 auditd ruleset coverage by category (time-change,
  identity, system-locale, MAC-policy, logins, session, perm_mod, access,
  mount, delete, sudoers, sudo.log, modules, immutable)
- CIS 3.5.2.x nftables modern firewall (installed, service, default deny)
- CIS 1.1.1.x extended filesystem disabled modules (cramfs, freevxfs, jffs2,
  hfs, hfsplus, udf, squashfs)
- CIS 1.10 system-wide crypto policy

**modules/module_nist.py** v3.3 (172 -> ~204 checks, +~32)
- NIST SP 800-207 Zero Trust Architecture (Tenets 1-7): resource enumeration,
  encrypted communication, per-session access, dynamic policy, integrity
  monitoring, dynamic auth, continuous monitoring layers
- NIST SP 800-161 Supply Chain Risk Management (SR-3 controls, SR-4
  provenance/SBOM, SR-9 tamper resistance, SR-11 component authenticity)
- NIST CSF 2.0 Govern function (GV.OC, GV.RM, GV.SC, GV.PO)
- NIST 800-53 R5 PE (Physical/Environmental) technical indicators (PE-3,
  PE-6)
- NIST 800-53 R5 PM (Program Management) technical indicators (PM-5
  inventory, PM-12 insider threat)
- NIST SP 800-171 Rev 3 advanced practices (3.13.8 PFS, 3.13.11 FIPS,
  3.14.1 flaw remediation, 3.14.6 monitoring, 3.14.7 unauthorized use)
- NIST AU extended (AU-3(1), AU-7, AU-9(2), AU-12)
- NIST CM extended (CM-2(2), CM-5, CM-7(2))

**modules/module_nsa.py** v3.3 (144 -> ~172-202 checks, +~28-58)
- SELinux boolean enforcement (~17 should-be-off + ~3 should-be-on
  recommended booleans, conditional on SELinux enforcing)
- FIPS 140-3 depth: kernel FIPS, OpenSSL FIPS provider, system crypto
  policy, kernel keyring tools
- Kernel hardening: lockdown mode, IMA, module signing enforcement, ASLR,
  Yama ptrace_scope, KASLR, CPU vulnerability mitigations
- Network protocols: IPv6 status, dccp/sctp/rds/tipc disabled, ICMP
  redirects, source routing, log_martians
- NSA Cybersecurity Advisories: Web Shell defense (WAF), Host firewall,
  Privileged Access (SSH root), Living-off-the-Land detection, Auth Logging
- Commercial Solutions for Classified (CSfC) defense-in-depth + audit

**modules/module_stig.py** v3.3 (167 -> ~198 checks, +~31)
- RHEL 9 STIG additional V-numbers: V-258003 (PrintLastLog), V-258006
  (GSSAPIAuthentication), V-258007 (KerberosAuthentication), V-258028/9
  (gpgcheck, localpkg_gpgcheck), V-258034/5 (dmesg_restrict, kptr_restrict),
  V-258049/50 (protected_hardlinks/symlinks), V-258054 (ICMP broadcasts)
- Ubuntu 22.04 STIG additional V-numbers: V-260469 (wireless), V-260473
  (APT GPG), V-260491 (unattended-upgrades), V-260507 (AppArmor), V-260511
  (suid_dumpable)
- General Purpose OS SRG (GPOS): SRG-OS-000023 (banner), SRG-OS-000033
  (FIPS), SRG-OS-000037 (auid), SRG-OS-000062 (privileged), SRG-OS-000080
  (GRUB password), SRG-OS-000363 (FIM), SRG-OS-000437 (systemd),
  SRG-OS-000470 (failed logon)
- Container Platform SRG (when containers detected): SRG-APP-000033-CTR,
  SRG-APP-000516-CTR, Kubernetes STIG indicators
- Additional V-numbers: V-230373 (inactive lock), V-230376 (empty pw),
  V-230380 (LUKS), V-230388 (UID 0)

### Quality

All v3.3 expansions follow established patterns from L4 (proven splice
procedure) and L1 (helper-naming verification) in tasks/lessons.md:
- Use AuditResult directly (existing modules) or _r helper (new modules)
- Cross-reference dictionaries with comma-joined multi-control values
  per L3
- run_checks ends with `return results` per L2
- AST syntax verification + standalone import after every splice
- module_helpers used via aliased imports (_v33_*) to avoid namespace
  conflicts with the host modules' existing imports

---

## [3.3.0-expansion] - 2026-04-26 (Phase 2 Expansion v3.3)

### Added - Deep Technical Coverage Across 8 New Modules

Phase 2 expansion v3.3 adds **+171 checks** across the eight new framework
modules introduced in Phase 3, bringing their combined total to 555 checks
(from a baseline of 151).

**modules/module_distbaseline.py** v3.3 (38 -> 74 checks, +36)
- Filesystem mount option hardening (CIS-aligned: nosuid/nodev/noexec on
  /dev/shm, /tmp, /var, /var/log, /home)
- systemd unit hardening per-critical-service (sshd, journald, auditd, rsyslog,
  chrony, cron) with ProtectSystem/ProtectHome/PrivateTmp/NoNewPrivileges
  detection
- Boot security: GRUB password protection, GRUB config permissions, initramfs
  permissions, kdump crash dump, UEFI/EFI variables
- System-wide crypto policies: update-crypto-policies, OpenSSL FIPS provider,
  OpenSSL system-wide TLS minimums, GnuTLS config
- Kernel features: modules_disabled, unprivileged user namespaces, BPF JIT
  hardening, unprivileged BPF, Yama ptrace_scope, ASLR, dmesg_restrict,
  kptr_restrict, suid_dumpable, hardlink/symlink protection
- Time synchronization: chrony / ntpd / systemd-timesyncd with NTS auth detection
- User account security: empty passwords, UID 0 audit, duplicate UIDs/GIDs,
  /etc/passwd / /etc/shadow / /etc/group / /etc/gshadow permission audit
- auditd dispatcher extended: space_left_action, disk_full_action,
  max_log_file_action, audisp-remote forwarding
- Per-distro extended: Debian (AppArmor, Ubuntu Pro, debsums, needrestart,
  fail2ban), RHEL (SELinux, fapolicyd, USBGuard, OpenSCAP, Insights),
  SUSE (AppArmor, snapper, zypper), Arch (pacman keyring, SigLevel)
- Critical log path permissions and logrotate configuration

**modules/module_edr.py** v3.3 (49 -> 76 checks, +27)
- Persistence detection mapped to MITRE ATT&CK: cron (T1053.003), systemd
  (T1543.002), shell rc files (T1546.004), init scripts (T1037), SSH
  authorized_keys (T1098.004)
- Process injection indicators: LD_PRELOAD detection (T1574.006),
  ld.so.conf.d entries, Yama ptrace mitigation (T1055.008), protected
  FIFOs/regular files
- Network behavior: DNS resolver visibility (T1071.004), uncommon listening
  ports (T1571), egress monitoring (Suricata/Zeek/Snort/iptables LOG)
- Container runtime: Docker/Podman/containerd/CRI-O/kubelet detection;
  Falco/Tetragon/Sysdig/Tracee/Aqua/Twistlock; Docker daemon hardening
  (userns-remap, no-new-privileges, icc, log-driver, live-restore)
- Anti-forensics: auditd immutable mode -e 2 (T1562.001), shell history
  monitoring (T1070.003), critical file watches (T1562.006), time
  modification syscalls (T1070.006), /var/log/audit chattr +i
- Memory protection: NX bit, SMEP/SMAP, ASLR full, KASLR not disabled,
  KPTI/Meltdown mitigation
- Process accounting: acct/psacct service, journalctl health
- Auditd ruleset depth: total rule count, watch vs syscall ratios, standard
  rule keys (identity, privileged, perm_mod, modules, time-change,
  system-locale, MAC-policy, logins, session)
- eBPF/LSM extended: BPF LSM active in /sys/kernel/security/lsm,
  perf_event_paranoid, bpftool/bpftrace/bcc-tools

**modules/module_pci.py** v3.3 (33 -> 63 checks, +30)
- Req 1 extended: network architecture enumeration, nftables ruleset,
  reverse path filtering, NAT/masquerade detection
- Req 2 extended: insecure services audit, system security parameters,
  cron daemon for scheduled tasks
- Req 3 KMS: Vault/Barbican/SoftHSM/TPM2/KMIP detection, key store
  permissions, snakeoil cert detection, suspicious /tmp key files
- Req 4 TLS depth: Apache SSLProtocol modern (TLS 1.2+), Nginx ssl_protocols,
  CA certificate management
- Req 5 malware extended: AV deployment (ClamAV, MDE, CrowdStrike,
  SentinelOne, Sophos, ESET, Wazuh-rootcheck, rkhunter, chkrootkit),
  freshclam updater, ClamAV log directory
- Req 6 SDLC: SAST tools (bandit, semgrep, gosec, shellcheck, pylint,
  eslint), patch automation, WAF (ModSecurity, naxsi, shadow-daemon),
  web server inventory
- Req 8 MFA: PAM modules (google-auth, yubico, oath, duo, u2f, pkcs11,
  radius), ENCRYPT_METHOD, account lockout (faillock/tally2),
  pwhistory remember count, system accounts no shell
- Req 9 media: removable media count, destruction tools (shred, wipe,
  scrub, blkdiscard, nvme), USBGuard / usb-storage blacklist
- Req 10 audit completeness: file access rules, privileged action
  audit, audit log directory watch, auth events, kernel module
  changes, num_logs, time sync
- Req 11 testing: vuln scanners (OpenVAS, Trivy, Grype, Lynis,
  OpenSCAP, Nikto, Nuclei), IDS/IPS (Suricata, Snort, Zeek, Wazuh,
  OSSEC), FIM (AIDE, Tripwire, Wazuh-FIM, Samhain), AIDE schedule
- Req 12 indicators: software inventory, SIEM/log forwarding (rsyslog,
  fluentd, filebeat, vector, logstash), logging layers active

**modules/module_soc2.py** v3.3 (43 -> 76 checks, +33)
- CC1 control environment: AUP banners (/etc/issue, issue.net, motd),
  privileged group review (sudo + wheel)
- CC2 communication: log forwarding to SIEM, TLS-capable utilities
- CC4 monitoring: continuous monitoring (auditd), vulnerability
  evaluation tools, file integrity monitoring
- CC5 control activities: configuration management agents (Ansible,
  Puppet, Chef, Salt, CFEngine), PAM policy modules
- CC6 logical access: PAM security modules, PASS_MAX_DAYS,
  network firewall, SSH PermitRootLogin, sensitive file permissions,
  automated security updates
- CC7 operations: kernel security baseline drift, process accounting,
  journald forwarding, auditd retention, backup tools
- CC8 change management: configuration change auditing, package
  transaction logs
- CC9 risk mitigation: package signature verification across
  apt/rpm/pacman
- A1 availability: capacity monitoring agents (node_exporter,
  Prometheus, Telegraf, Collectd, Zabbix, Datadog), swap configured,
  scheduled backup cron jobs
- C1 confidentiality: LUKS disk encryption, secure deletion tools
- PI processing integrity: FIM database initialized, audit log
  directory present
- P privacy: rsyslog content filtering, logrotate configurations,
  encryption libraries available

**modules/module_gdpr.py** v3.3 (35 -> 54 checks, +19)
- Article 17 (right to erasure): secure deletion tools, backup
  retention configurations
- Article 30 (records of processing): data access auditing capability,
  audit log retention (num_logs, max_log_file)
- Article 5 (data minimization): rsyslog content filtering, log
  forwarding selectivity, log rotation configurations
- Article 25 (by design and by default): TLS 1.2+ minimum protocol,
  sensitive data directory permissions
- Article 32 extended: pseudonymisation libraries, SSH for encrypted
  admin access, snapshot/restore capability, vulnerability scanners,
  audit log immutability, MAC enforcement (SELinux/AppArmor)
- Article 33 (breach notification): remote log forwarding for
  detection, audit trail directory and file presence
- Articles 44-49 (international transfers): VPN technologies
  (WireGuard, OpenVPN, strongswan/ipsec, tinc), disk encryption (LUKS)

**modules/module_hipaa.py** v3.3 (63 -> 89 checks, +26)
- Sec 164.308 administrative: information system activity review (auditd
  rule count), workforce clearance (privileged group review),
  authorization/supervision (sudoers permissions), malware protection,
  login monitoring (faillock), incident response (SIEM forwarding),
  data backup plan, emergency mode (rescue/recovery), evaluation
  (vulnerability scanners)
- Sec 164.310 physical: maintenance records (package logs), disposal
  tools, media accountability auditing
- Sec 164.312 technical: automatic logoff (ClientAliveInterval),
  encryption tools, audit controls (standard rule keys), file integrity
  monitoring, MFA modules, TLS 1.2+ minimum, SSH cipher suite hardening
- Sec 164.314 organizational: software supply chain integrity
- Sec 164.316 documentation: audit retention, system documentation,
  change management via package logs
- Sec 164.402-414 breach notification: remote log forwarding,
  SIEM/log aggregation tooling, audit trail for breach investigation

### Fixed

- **PCI module helper-naming compatibility**: PCI's idiosyncratic naming
  convention (`_run_command`, `__directory_exists` with double underscore,
  `_result` instead of `_r`) required a regex-driven helper-name
  transformation pass before splicing the v3.3 expansion. A `_safe_listdir`
  helper was injected to replace the missing `list_directory` import.

- **SOC2 v3.1 expansion missing return statement**: The v3.1 expansion's
  `run_checks` was missing `return results` between the `try/except` block
  and `if __name__ == "__main__":`, causing the function to return None
  when called from `__main__`. Fixed.

- **GDPR v3.1 expansion missing return statement**: Same pattern as SOC2.
  Fixed.

- **Multi-value cross-reference dict syntax**: Several v3.3 expansions
  contained dict literals of the form `{"NIST": "AC-6", "AC-2"}` (treating
  the second value as a tuple element rather than another dict entry).
  Reformulated as comma-joined strings: `{"NIST": "AC-6, AC-2"}`. Fixed
  across SOC2, GDPR, and HIPAA expansion files.

### Quality

All v3.3 expansions follow established v3.x patterns:
- `_original_run_checks_<module>_v33` reference to original `run_checks`
- Redefined `run_checks` calls original then extends with new checks
- Cross-framework references on every check via `cross_references` dict
- Multi-distribution support via `os_detection`
- File I/O with explicit encoding and error handling
- Production-grade subprocess calls (list args, timeout, no shell=True)
- Comprehensive MITRE ATT&CK mappings on EDR persistence/anti-forensics
- AST syntax verification after every splice
- Standalone module verification (`python3 modules/module_X.py`)

---

## [3.2.0-expansion] - 2026-04-26 (Phase 2 Expansion v3.2)

CMMC v3.2 (47 -> 77, +30) and ACSC v3.2 (34 -> 46, +12) deep coverage.
See module_cmmc.py and module_acsc.py for v3.2 expansion blocks.

---

## [3.0.0-baselines] - 2026-04-26 (Phase 3 Baselines Complete)

### Added - All 7 Remaining Framework Modules

The Phase 3 baseline phase is complete. Eight new framework modules
totaling 1,290 checks across the previously-uncovered frameworks:

**modules/module_acsc.py** (~860 lines, 19 checks)
ACSC Essential Eight + Information Security Manual:
- E8.1 Application control (fapolicyd, AppArmor, SELinux, world-writable PATH)
- E8.2 Application patching (unattended-upgrades, dnf-automatic, security update queue)
- E8.4 User application hardening (browser inventory, PowerShell on Linux)
- E8.5 Restrict admin privileges (NOPASSWD audit, sudo/wheel membership)
- E8.6 OS patching (EOL detection, kernel age vs ML1/ML2/ML3 thresholds)
- E8.7 MFA (PAM module detection, sshd AuthenticationMethods)
- E8.8 Backups (rsync/Borg/Restic/Duplicity/Bacula/BackupPC tooling inventory)
- ISM-1610 Secure Boot
- ISM-0580 Centralized event logging
- ISM-1815 TLS log forwarding
- ISM-0428 Terminal session lock
- ISM-0421 Account lockout
- ISM-0417 Password complexity
- ISM-0457 Disk encryption

**modules/module_cmmc.py** (~890 lines, 24 checks)
CMMC 2.0 Levels 1-3 + DFARS 252.204-7012:
- AC domain: empty passwords, sudoers permissions, UID 0, root SSH, TMOUT, firewall
- AU domain: auditd, identity audit rules, disk_full_action, time sync
- CM domain: insecure services, kernel module blacklist
- IA domain: duplicate UIDs, password complexity, history, SHA-512 hashing
- SC domain: ip_forward, SSH ciphers, FIPS mode
- SI domain: pending updates, AV, IDS, FIM
- DFARS 7012(c) journal persistence

**modules/module_gdpr.py** (~970 lines, 18 checks)
GDPR Article 32 + ePrivacy:
- Art-32(1)(a) encryption at rest (LUKS, fscrypt, eCryptfs)
- Art-32(1)(a) encryption in transit (SSH ciphers, system crypto policies, web TLS)
- Art-32(1)(a) pseudonymisation indicators
- Art-32(1)(b) confidentiality (file permissions, MAC framework)
- Art-32(1)(b) integrity (FIM, auditd)
- Art-32(1)(b) availability (backup tooling, disk space)
- Art-32(1)(b) resilience (systemd Restart= directives)
- Art-32(1)(c) restoration (persistent journald)
- Art-32(1)(d) testing tools (OpenSCAP, Lynis, OpenVAS)
- Art-25 by design (default-deny firewall, restrictive umask)
- ePrivacy Art-5 cleartext service prohibition
- Art-33 breach detection capability

**modules/module_hipaa.py** (~1,000 lines, 18 checks)
HIPAA Security Rule + 405(d) HICP:
- Sec. 164.312(a)(2)(i) unique user identifiers
- Sec. 164.312(a)(2)(iii) automatic logoff (TMOUT, SSH client alive)
- Sec. 164.312(a)(2)(iv) encryption (LUKS)
- Sec. 164.312(b) audit controls (auditd, audit rule families, time sync)
- Sec. 164.312(c)(1) integrity (FIM, critical file permissions)
- Sec. 164.312(d) authentication (no empty passwords, complexity, lockout)
- Sec. 164.312(e)(1) transmission security (SSH legacy protocol, ciphers, no insecure remote)
- Sec. 164.308(a)(5)(ii)(B) malware protection
- Sec. 164.308(a)(7) contingency (backup tooling, persistent journal)
- HICP-1 email TLS, HICP-3 sudo logging

**modules/module_soc2.py** (~700-900 lines, 21 checks)
SOC 2 Type II Trust Service Criteria:
- CC4 Monitoring (auditd, central log forwarding)
- CC5 Control activities (MAC framework)
- CC6 Logical access (8 controls covering authentication, authorization, sessions)
- CC7 System operations (IDS, FIM, audit failure handling, time sync)
- CC8 Change management (audit watches on critical config)
- CC9 Risk mitigation (firewall, repository GPG verification)
- A1 Availability (disk space, backup, restart policies)
- C1 Confidentiality (encryption, secure deletion, file permissions)

**modules/module_distbaseline.py** (~1,000-1,200 lines, 6+ checks)
Distribution-Specific Hardening Baseline:
- Ubuntu USG: Livepatch, Pro/ESM attachment, AppArmor coverage, ufw default-deny,
  unattended-upgrades security origin, snap confinement
- RHEL Hardening: OpenSCAP, system crypto policy, fapolicyd, USBGuard, FIPS mode,
  subscription-manager
- SUSE Hardening: zypper patches, AppArmor on SLES, AIDE
- Arch baseline: pacman keyring init, SigLevel verification, AUR helper inventory
- Cross-distro: TPM 2.0, USBGuard, kernel lockdown mode, Secure Boot,
  kernel hardening sysctls

**modules/module_edr.py** (~700-900 lines, 18 checks)
Linux EDR Equivalent Detection:
- Falco runtime detection (binary, service, output configuration, rules)
- Wazuh/OSSEC (agent state, syscheck/FIM, rootcheck)
- Elastic Auditbeat (auditd module, file_integrity module, system module)
- Sysdig and Tracee presence
- Commercial: CrowdStrike Falcon, SentinelOne, Microsoft Defender, Cisco Tetration
- eBPF and BPF LSM kernel capabilities
- cgroups v2 unified hierarchy
- File integrity tools (AIDE database age, Tripwire, Samhain)
- IR readiness: persistent journald, central log forwarding, auditd, /tmp separation

### Verified - Full v3.0 Pipeline Integration

Combined run of all 8 new modules executes 151 checks in ~11 seconds:
- ACSC: 19, CMMC: 24, GDPR: 18, HIPAA: 18, SOC2: 21, DistBaseline: 6+,
  EDR: 18, PCI: 27 (PCI was completed previously)
- All modules discovered automatically by orchestrator
- Cross-framework correlation enrichment applied to all 151 results
- Risk priority scoring computed (top findings up to 91/100)
- Three-method compliance scoring functions
- Compatible with --baseline, --rollback-path, --remediation-bundle,
  --asset-criticality, --show-risk-priority, --show-correlations,
  --validate-results, --threshold

### Module Inventory After Phase 3 Baseline

Total modules: 16 (was 9 in 3.0-pci-module milestone, was 8 originally):
- 8 existing: CIS, CISA, Core, ENISA, ISO27001, NIST, NSA, STIG (1,207 checks)
- 8 new: ACSC, CMMC, DistBaseline, EDR, GDPR, HIPAA, PCI, SOC2 (~178 checks)
- Combined check count: ~1,385+

### Next Phase

Phase 2 enhancement: depth expansion of all 16 modules per the Enhancement
Roadmap. Targets:
- Existing 8 modules expanded from 1,207 -> ~2,250+ checks
- New 8 modules expanded from baseline -> ~1,000+ checks each domain
- Final target: ~3,000-4,000 total checks (Windows-parity range)

---

## [3.0.0-pci-module] - 2026-04-26 (Phase 3 Progress)

### Added - PCI DSS v4.0.1 Module

First v3.0 framework module ships, demonstrating the full v3 architecture
end-to-end. Production-grade implementation with no stubs or placeholders.

**modules/module_pci.py (1,482 lines):**

- **Requirement 1 (Network Security Controls)**: Firewall presence,
  active firewall service detection, listening port inventory, traffic
  restriction analysis, network segmentation indicators
- **Requirement 2 (Secure Configurations)**: Empty-password account
  detection, UID-0 audit, insecure service detection (telnet/rsh/rlogin/
  rexec/FTP/TFTP/xinetd), system hardening (ASLR, kptr_restrict,
  suid_dumpable, tcp_syncookies, ip_forward)
- **Requirement 3 (Stored Data Protection)**: LUKS disk encryption
  detection, system-wide crypto policy validation
- **Requirement 4 (Transit Encryption)**: SSH cipher suite validation
  excluding 3DES/RC4/Blowfish/CBC, MAC algorithm validation excluding
  MD5/SHA1-96/RIPEMD160
- **Requirement 5 (Malware Defence)**: Anti-malware solution detection
  (ClamAV, Sophos, ESET, TrendMicro, Falco, Wazuh, ChkRootkit, RKHunter),
  ClamAV signature update verification
- **Requirement 6 (Patch Management)**: Pending security update detection
  for apt and dnf families with 30-day SLA per PCI v4.0.1
- **Requirement 7 (Least Privilege)**: NOPASSWD sudoers detection,
  MAC framework enforcement validation (SELinux, AppArmor)
- **Requirement 8 (Authentication)**: Password minimum length 12
  (PCI v4.0.1), 90-day password expiration, 15-minute idle timeout,
  account lockout configuration
- **Requirement 10 (Logging)**: auditd active, remote log forwarding,
  time synchronization (chrony, ntpd, systemd-timesyncd), log retention
  configuration
- **Requirement 11 (Security Testing)**: IDS/IPS deployment (Suricata,
  Snort, OSSEC, Wazuh, Falco), file integrity monitoring (AIDE, Tripwire,
  Samhain)

### Added - Correlation Registry Expansion

Registry expanded from 135 to 158 topics with 23 new PCI DSS-specific
topics covering network segmentation, account hardening, transit
encryption, AV deployment, patch SLA, FIM, log retention, time sync,
intrusion detection, and access control.

### Verified

The new module integrates fully with the v3.0 pipeline:
- Automatic discovery by the orchestrator (`-m PCI`)
- Cross-framework correlation enrichment (every result carries
  references to NIST, CIS, ISO 27001, HIPAA, STIG where applicable)
- Risk priority scoring (Critical PCI fails score 80/100, Highs 70/100)
- Three-method compliance scoring
- Standalone execution (`python3 modules/module_pci.py`)

---

## [3.0.0-foundation] - 2026-04-26

### Added - Phase 1 Foundation Library

This release adds the v3.0 foundation library that the upcoming module
expansion (Phase 2) and new framework modules (Phase 3) build upon.
Existing v2.0 functionality is preserved unchanged; v3 capabilities
are additive and opt-in via new CLI flags.

**New shared_components modules:**

- `correlation_registry.py` (1,035 lines) - Cross-framework control mapping
  registry. 135 correlation topics covering SSH, password/PAM, account
  management, file permissions, network sysctl, kernel hardening, boot
  security, audit logging, syslog, time sync, filesystem, MAC, firewall,
  cron, banners, updates, crypto, services, process hardening, sudo. Each
  topic maps to identifiers in CIS, NIST 800-53, STIG V-numbers, ISO 27001
  Annex A, NSA, CISA, ENISA, PCI DSS, HIPAA, SOC 2, CMMC, ACSC, GDPR.

- `os_detection.py` (899 lines) - Comprehensive distribution detection
  covering 30+ Linux distributions. Multi-source resolution (/etc/os-release,
  /usr/lib/os-release, /etc/lsb-release, family marker files) with priority
  fallback. Detects: Debian/Ubuntu/Mint/Pop/elementary/Kali/Zorin/MX/Deepin/
  Parrot/Tails/Raspbian/Devuan; RHEL/CentOS/Fedora/Rocky/Alma/Oracle/Amazon
  Linux/Scientific; openSUSE Leap/Tumbleweed/SLES/SLED; Arch/Manjaro/
  EndeavourOS/Garuda/Artix/BlackArch; Alpine/Gentoo/Slackware/Void/NixOS.
  Identifies package manager, init system (systemd/openrc/runit/s6/dinit/
  sysvinit), MAC framework (SELinux/AppArmor/TOMOYO/SMACK/Yama), firewall
  (firewalld/ufw/nftables/iptables/shorewall), container runtime, and
  cloud provider via DMI strings (no network calls).

- `risk_scoring.py` (319 lines) - Risk priority scoring engine. Combines
  severity (40%), exploitability (25%), exposure (20%), and asset
  criticality (15%) into a 1-100 score for prioritised remediation.
  Auto-classification heuristics for exploitability and exposure when
  modules don't supply explicit ratings.

- `baseline_compare.py` (492 lines) - Drift detection between audit runs.
  Diffs current results against a baseline JSON file, classifying each
  finding as new_failure / resolved / regression / improved / worsened /
  new_pass / unchanged. Compliance score delta calculation.

- `remediation_bundles.py` (533 lines) - 8 predefined remediation groupings:
  HardenSSH, DisableLegacyProtocols, HardenKernel, EnableAuditLogging,
  HardenAuthentication, LockDownNetwork, SecureBootChain, HardenSystemd.
  Each bundle has documented impact profile (services affected, reboot
  requirement, SSH continuity risk).

- `rollback_generator.py` (617 lines) - Capture-before-modify rollback
  scripts. Records pre-modification state for sysctl values, file content/
  permissions, systemd service state/enablement, and kernel module
  loading. Generates atomic bash rollback scripts with set -euo pipefail,
  base64-embedded file content, validated commands, and 0700 mode.

- `v3_pipeline.py` (712 lines) - High-level audit pipeline integration.
  Wires validation, correlation enrichment, risk scoring, baseline diff,
  compliance scoring, and v3-format JSON export into a single facade.

**New orchestrator CLI flags:**

- `--baseline PATH` - Compare results against a previously saved baseline
- `--rollback-path PATH` - Generate rollback bash script during remediation
- `--remediation-bundle NAME` - Apply a named remediation bundle
- `--asset-criticality 1-10` - Set asset criticality for risk priority
- `--show-risk-priority` - Display risk priority scores for findings
- `--show-correlations` - Display cross-framework control correlations
- `--validate-results` - Run strict result validation
- `--list-bundles` - List available remediation bundles and exit
- `--threshold` - Compliance score pass/fail threshold (default 70.0)

**Compliance scoring (3 methods):**

- Simple: pass percentage of evaluated checks
- Weighted: severity-weighted percentage
- Severity-adjusted: weight x status credit (Pass=1.0, Info=0.85,
  Warning=0.40, Fail=0.0)

### Phase 2 and 3 Roadmap

Phase 2 will expand the existing 8 modules to populate cross_references
on every check, use the new OS detection for richer distro-specific logic,
and add the depth checks specified in the Enhancement Roadmap. Phase 3
will add 8 new framework modules (ACSC, CMMC, GDPR, HIPAA, PCI-DSS, SOC2,
Distribution Baseline, Linux EDR Equivalent) bringing total coverage to
~13-14 modules and ~3,500-4,000 checks.

### Quality Properties

- Pure Python 3.7+ stdlib only; zero external dependencies
- All subprocess calls use list args, timeouts, no shell=True
- All file I/O has explicit encoding and error handling
- Path traversal validation on all output file paths
- Thread-safe module-level caches with explicit locking
- Production atomic file writes (write-rename pattern)

---

## [Unreleased]

### Planned Features
- Additional output formats (PDF, Markdown, SARIF, SCAP)
- SQLite audit trail database
- Delta reporting and baseline comparison
- Syslog/CEF output for SIEM integration
- Container and Kubernetes security modules

## [2.0] - 2026-03-02

### Added

- **Performance Architecture (Phase 2)**:
  - Shared components library (`shared_components/audit_common.py`, 2,174 lines) with caching, parallel execution, and /proc filesystem reads
  - Intelligent file and command caching with ~50% hit rate across modules
  - Parallel module execution via `--parallel` flag with configurable `--workers` count
  - Direct /proc filesystem reads replacing subprocess calls for performance
  - Dynamic module discovery from `modules/` directory with validation
  - OS-aware functionality supporting Debian, Red Hat, SUSE, and Arch families with respective package managers (apt, yum/dnf, zypper, pacman)
  - Performance profiling via `--profile` flag with cache statistics and module timing

- **Structured Logging (Phase 3.1)**:
  - Dedicated `logs/` directory with hostname-stamped filenames
  - Configurable log levels via `--log-level` (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  - Custom log file path via `--log-file`
  - JSON-structured logging via `--json-log` for SIEM ingestion
  - Hybrid `log_and_print()` for simultaneous console and file output
  - Verbose mode (`--verbose`) and quiet mode (`--quiet`)
  - Per-module execution timing in performance profile

- **Interactive HTML Report Rewrite (Phase 3.2)**:
  - Executive dashboard with SVG donut chart visualization
  - Cross-framework compliance matrix with weighted scores
  - Remediation priority ranking table
  - Column resizing via drag handles
  - In-column filtering per table column
  - Column visibility toggles
  - Global search with include/exclude modes
  - Per-module and global export (CSV, Excel, JSON, XML, TXT formats)
  - Row selection via checkboxes with selection-based export
  - Print-friendly CSS with `@media print` support
  - Table of Contents with smooth-scroll navigation
  - Full-width header with dark blue gradient
  - Garamond typography throughout
  - Dark/light theme toggle with CSS custom properties

- **Compliance Scoring System (Phase 3.5)**:
  - `ComplianceScore` dataclass with three scoring methods
  - Simple pass percentage (Pass / Applicable, Info excluded)
  - Weighted scoring (Pass=1.0, Warning=0.5, Fail=0, Error=0)
  - Severity-weighted compliance (Critical=5x, High=3x, Medium=1.5x, Low=0.5x penalty factors)
  - Configurable pass/fail threshold (default 70%)
  - Per-module and overall compliance scores in HTML, console, JSON, and XML

- **Interactive Dashboard Filtering (Enhancement 1)**:
  - Clickable donut chart segments filter by status
  - Clickable summary cards filter by status (Pass/Fail/Warning/Info/Error)
  - Clickable severity cards filter by severity level
  - Toggle behavior (click again to deselect)
  - Filter notification bar with clear button
  - Filters apply across ALL module tables simultaneously

- **IP Address Identification (Enhancement 2)**:
  - `get_system_ip_addresses()` with four detection methods
  - Three paired identification points (hostname + OS + IPs) for SIEM attribution
  - Displayed in HTML info cards, console summary, JSON, and XML exports

- **STIG DISA V-Number Mapping**: 65 checks mapped to official V-numbers (38.9% coverage)
- **ISO27001 Secure Development Checks**: A.8.25 and A.8.26 controls (7 new checks)

### Changed

- **Project Structure**: Reorganized from flat layout to `modules/` + `shared_components/` + `logs/` + `reports/`
- **Python Requirement**: Minimum version raised from 3.6 to 3.7 (dataclasses dependency)
- **Module Architecture**: All 8 modules use shared_components caching and /proc reads
- **Check Count**: Validated at 1,207 total checks (was ~1,100 approximate)
- **Report Directory**: Reports saved to `reports/` directory by default
- **JSON Export**: Companion JSON auto-generated alongside all report formats
- **XML Export**: Enhanced metadata including IP addresses and compliance scores
- **Console Summary**: Now displays hostname, IP addresses, OS, and compliance scores
- **HTML Report**: Complete rewrite with 18+ interactive features

### Fixed
- Emoji corruption in module banners resolved via Unicode codepoint encoding
- Results Summary format standardized across all 8 modules
- CSV export properly handles special characters and multi-line content

### Security
- Report files created with 600 permissions in dedicated `reports/` directory
- Log files created with 644 permissions in dedicated `logs/` directory

## [2.0] - 2026-03-02

### Added

- **Performance Architecture (Phase 2)**:
  - Shared components library (`shared_components/audit_common.py`, 2,195 lines)
  - Intelligent caching with ~50% hit rate across modules
  - Parallel module execution (`--parallel`, `--workers`)
  - Direct /proc filesystem reads; dynamic module discovery from `modules/`
  - OS-aware functionality (Debian, Red Hat, SUSE, Arch families)
  - Performance profiling via `--profile`

- **Structured Logging (Phase 3.1)**:
  - `logs/` directory with hostname-stamped filenames
  - `--log-level`, `--log-file`, `--json-log`, `--verbose`, `--quiet`
  - Hybrid `log_and_print()` for simultaneous console/file output

- **Interactive HTML Report Rewrite (Phase 3.2)**:
  - SVG donut chart, compliance matrix, remediation priority ranking
  - Column resizing, in-column filtering, column visibility toggles
  - Global search (include/exclude), multi-format export (CSV/Excel/JSON/XML/TXT)
  - Row selection, print CSS, Table of Contents, dark/light theme, Garamond typography

- **Compliance Scoring (Phase 3.5)**:
  - `ComplianceScore` dataclass: simple, weighted, severity-adjusted methods
  - Configurable threshold (default 70%), per-module and overall scores

- **Dashboard Filtering (Enhancement 1)**:
  - Clickable donut segments, summary cards, severity cards filter all tables

- **IP Address Identification (Enhancement 2)**:
  - `get_system_ip_addresses()` with 4 detection methods
  - Displayed in HTML, console, JSON, XML

- **STIG V-Numbers**: 65 checks mapped (38.9% coverage)
- **ISO27001 Secure Development**: A.8.25-A.8.26 (7 checks)

### Changed
- Project structure: flat -> `modules/` + `shared_components/` + `logs/` + `reports/`
- Python 3.6 -> 3.7 (dataclasses); check count validated at 1,207
- HTML report: complete rewrite (18+ features); companion JSON auto-generated
- Console summary: hostname, IPs, OS, compliance scores

### Fixed
- Emoji corruption via Unicode codepoint encoding
- Results Summary format standardized; CSV special character handling

### Security
- Reports: 600 permissions in `reports/`; logs: 644 in `logs/`

## [1.1] - 2025-01-07

### Added
- **Module System Enhancements**:
  - Complete CISA module (140+ checks) with BOD compliance
  - Complete ENISA module (135+ checks) with EU cybersecurity standards
  - Complete ISO27001 module (145+ checks) with Annex A controls
  - Complete NSA module (155+ checks) with advanced hardening
  - Complete STIG module (180+ checks) with DoD requirements

- **Core Functionality**:
  - Dynamic module discovery system
  - Privilege-aware execution with graceful degradation
  - Intelligent OS detection and distribution-specific optimizations
  - Comprehensive error handling and validation

- **Reporting Features**:
  - Interactive HTML reports with filtering and search
  - Dark/Light theme toggle for HTML reports
  - Export selected issues to JSON for selective remediation
  - Multi-format output (HTML, CSV, JSON, XML, Console)
  - Real-time console output with color coding

- **Remediation System**:
  - Interactive remediation with issue-by-issue approval
  - Automated remediation with safety confirmations
  - Filtered remediation by status level (FAIL, WARNING, INFO)
  - Selective remediation from exported JSON files
  - Remediation command preview and validation

- **Documentation**:
  - Complete Wiki documentation (9 comprehensive pages)
  - Quick Start Guide
  - Comprehensive Usage Guide
  - Output Reference with format details
  - Module Documentation with check descriptions
  - Framework Reference with standards details
  - Development Guide for contributors
  - Troubleshooting Guide
  - Frequently Asked Questions (FAQ)

### Changed
- **Enhanced Module Coverage**:
  - Core module updated to 150+ checks
  - CIS module expanded to 200+ checks (v2.1)
  - NIST module enhanced to 160+ checks (v2.1)

- **Improved Performance**:
  - Optimized check execution
  - Reduced memory footprint
  - Faster filesystem operations
  - Efficient module loading

- **Better Error Messages**:
  - Clear, actionable error descriptions
  - Contextual help suggestions
  - Detailed troubleshooting information

- **Code Quality**:
  - Type hints throughout codebase
  - Comprehensive docstrings
  - PEP 8 compliance
  - Improved modularity and maintainability

### Fixed
- File permission checks now correctly handle octal notation
- Module import paths resolved for all execution contexts
- HTML report JavaScript compatibility across browsers
- CSV export handling of special characters
- JSON serialization of datetime objects
- XML entity escaping for remediation commands

### Security
- Input validation for all user-provided parameters
- Safe command execution with timeout protection
- Secure file permissions on generated reports (600)
- No external network calls or data transmission
- Privilege checks before sensitive operations

## [1.0] - 2024-12-15

### Added
- **Initial Release**:
  - Core security baseline module
  - CIS Benchmarks module
  - NIST Cybersecurity Framework module
  - Basic HTML report generation
  - CSV and JSON export capabilities
  - Command-line interface

- **Core Features**:
  - Multi-framework security auditing
  - Root and non-root execution support
  - Basic remediation functionality
  - Console output mode

- **Module System**:
  - Modular architecture with plugin support
  - Shared data structure between modules
  - Standardized AuditResult format

- **Documentation**:
  - README with basic usage
  - MIT License
  - Security policy

### Known Issues
- Limited error handling in some edge cases
- HTML reports lack advanced filtering
- No selective remediation capability
- Module discovery requires manual registration

## Version History Summary

| Version | Release Date | Modules | Checks | Key Features |
|---------|--------------|---------|--------|--------------|
| 2.0 | 2026-03-02 | 8 | 1,207 | Performance architecture, compliance scoring, interactive HTML, logging |
| 1.1 | 2025-01-07 | 8 | ~1,100 | Full framework coverage, advanced remediation, interactive reports |
| 1.0 | 2024-12-15 | 3 | 500+ | Initial release, basic functionality |

## Upgrade Guide

### Upgrading from 1.1 to 2.0

**Directory Structure Change** - Version 2.0 reorganizes the project layout.

**New Structure**: `modules/` + `shared_components/` + `logs/` + `reports/`

**Python Requirement**: 3.7+ (was 3.6+) due to dataclasses dependency.

**Migration Steps**:
```bash
cp -r Linux-Security-Audit-Project Linux-Security-Audit-Project-1.1-backup
cd Linux-Security-Audit-Project && git pull origin main
ls modules/ shared_components/
python3 linux_security_audit.py --list-modules
sudo python3 linux_security_audit.py -m Core --profile
```

**New CLI Flags**: `--parallel`, `--workers`, `--profile`, `--log-level`, `--log-file`, `--json-log`, `--verbose`, `--quiet`

### Upgrading from 1.1 to 2.0

**Structure**: `modules/` + `shared_components/` + `logs/` + `reports/`
**Python**: 3.7+ (was 3.6+)
**New flags**: `--parallel`, `--workers`, `--profile`, `--log-level`, `--log-file`, `--json-log`, `--verbose`, `--quiet`

```bash
cp -r Linux-Security-Audit-Project Linux-Security-Audit-Project-1.1-backup
cd Linux-Security-Audit-Project && git pull origin main
ls modules/ shared_components/
python3 linux_security_audit.py --list-modules
sudo python3 linux_security_audit.py -m Core --profile
```

### Upgrading from 1.1 to 2.0

**Structure**: `modules/` + `shared_components/` + `logs/` + `reports/`
**Python**: 3.7+ (was 3.6+)
**New flags**: `--parallel`, `--workers`, `--profile`, `--log-level`, `--log-file`, `--json-log`, `--verbose`, `--quiet`

```bash
cp -r Linux-Security-Audit-Project Linux-Security-Audit-Project-1.1-backup
cd Linux-Security-Audit-Project && git pull origin main
ls modules/ shared_components/
python3 linux_security_audit.py --list-modules
sudo python3 linux_security_audit.py -m Core --profile
```

### Upgrading from 1.0 to 1.1

**No Breaking Changes** - Version 1.1 is fully backward compatible.

**New Module Files Required**:
- Download 5 new module files: `module_cisa.py`, `module_enisa.py`, `module_iso27001.py`, `module_nsa.py`, `module_stig.py`
- Place in same directory as `linux_security_audit.py`
- No configuration changes needed

**Enhanced Features**:
- Existing HTML/CSV/JSON reports work as before
- New interactive features in HTML reports
- New remediation options available
- All previous functionality preserved

**Migration Steps**:
```bash
# Backup your 1.0 installation
cp -r Linux-Security-Audit-Project Linux-Security-Audit-Project-1.0-backup

# Pull latest changes
cd Linux-Security-Audit-Project
git pull origin main

# Verify new modules
python3 linux_security_audit.py --list-modules

# Run audit to test
sudo python3 linux_security_audit.py -m Core
```

## Development Roadmap

### Version 2.1 (Planned)

**Target Features**:
- [ ] PDF report generation
- [ ] Markdown report format
- [ ] SARIF / SCAP / XCCDF / Syslog / CEF output formats
- [ ] SQLite audit trail database
- [ ] Historical result tracking per host
- [ ] Delta reporting (new/resolved/regressed)
- [ ] Baseline comparison via `--compare` and `--baseline`

### Version 3.0 (Planned)

**Target Features**:
- [ ] Web-based dashboard interface
- [ ] Multi-system management
- [ ] Container and Kubernetes security modules
- [ ] Cloud security posture management
- [ ] Advanced analytics and ML-based risk scoring

## Contributing

We welcome contributions! Please see:
- **[Development Guide](../../wiki/Development-Guide)** - How to contribute
- **[GitHub Issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)** - Report bugs or request features
- **[Pull Requests](https://github.com/Sandler73/Linux-Security-Audit-Project/pulls)** - Submit code changes

### Contribution Guidelines

When submitting changes:
1. Update CHANGELOG.md with your changes under `[Unreleased]`
2. Follow semantic versioning
3. Include tests for new features
4. Update documentation as needed
5. Use clear commit messages

### Changelog Entry Format

```markdown
### Added
- New feature description with details

### Changed
- Modified feature description with rationale

### Deprecated
- Features marked for removal with timeline

### Removed
- Removed features with migration notes

### Fixed
- Bug fixes with issue numbers

### Security
- Security updates with CVE numbers if applicable
```

## Release Process

1. Update CHANGELOG.md with release version and date
2. Update version number in `linux_security_audit.py`
3. Create release tag: `git tag -a v1.1 -m "Release version 1.1"`
4. Push tag: `git push origin v1.1`
5. Create GitHub release with changelog notes
6. Update documentation with version references

## Support and Feedback

- **Bug Reports**: [GitHub Issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)
- **Feature Requests**: [GitHub Issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)
- **Questions**: [FAQ](../../wiki/Frequently-Asked-Questions-(FAQ)) or [GitHub Issues](https://github.com/Sandler73/Linux-Security-Audit-Project/issues)
- **Security Issues**: See [SECURITY.md](SECURITY.md)

---

**Legend:**
- `Added` - New features
- `Changed` - Changes to existing functionality
- `Deprecated` - Soon-to-be removed features
- `Removed` - Removed features
- `Fixed` - Bug fixes
- `Security` - Security updates

[Unreleased]: https://github.com/Sandler73/Linux-Security-Audit-Project/compare/v2.0...HEAD
[2.0]: https://github.com/Sandler73/Linux-Security-Audit-Project/compare/v1.1...v2.0
[1.1]: https://github.com/Sandler73/Linux-Security-Audit-Project/compare/v1.0...v1.1
[1.0]: https://github.com/Sandler73/Linux-Security-Audit-Project/releases/tag/v1.0

### Added - finer-grained remediation sub-topics (v3.9 continued)

- Decomposed the large heterogeneous clusters into precise sub-topics so only
  genuinely-identical fixes are unified, preserving each framework's scope and
  source-reference intent:
  - **auditd**: auditd_service_enable, auditd_rules_immutable, auditd_log_
    permissions (value-independent); auditd_log_retention, auditd_failure_
    action (value-bearing). Per-event audit RULES and the CIS-vs-MITRE ruleset
    CHOICE are deliberately NOT normalized.
  - **rsyslog**: rsyslog_service_enable, rsyslog_remote_forward
    (value-independent). PII redaction/anonymization (GDPR) stays separate.
  - **SSH**: ssh_x11_forwarding, ssh_permit_empty_passwords, ssh_banner,
    ssh_protocol, ssh_login_grace (value-independent); ssh_max_auth_tries,
    ssh_max_sessions (value-bearing).
- Total registry now 37 topics (27 value-independent + 10 value-bearing);
  379 checks force-normalized (up from 174), 494 classified.
- Added per-topic `message_only` classification scope: sub-topics whose
  remediation text is a shared multi-line block (auditd/rsyslog/ssh) match on
  the finding MESSAGE only, since the remediation field is too noisy there to
  be a reliable signal.
