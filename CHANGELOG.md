# Changelog

All notable changes to **Defender-Sentinel-KQL-Detections** are documented in this file.

## [1.2.1] - 2026-11-21

### Fixed
- **SENTINEL-005:** `createdump.exe` alone no longer triggers the rule; .NET uses it for ordinary crash dumps. It now counts only when the command line names `lsass`.
- **MDE-001:** Defender registry paths (`Exclusions`, `Real-Time Protection`) only match when combined with a write (`reg add/delete/import`, `Set-/New-/Remove-ItemProperty`), so `reg query` and other reads no longer fire.

## [1.2.0] - 2026-11-21

### Added
- **KQL syntax and schema check in CI (`tools/kql-lint`):** Every query is parsed with Microsoft's Kusto.Language engine (`@kusto/language-service-next`) against table schemas copied from Microsoft Learn. It immediately found a non-existent column (`ExploitTypes`) and the retired `AADSignInEventsBeta` table.
- **GitHub Actions workflow** running the metadata validator, the unit tests and the KQL check.
- **Validator:** `status` must be `Experimental`, `Hunting` or `Tested`.

### Fixed
- **MDE-001:** `has "DisableRealtimeMon"` never matched `DisableRealtimeMonitoring`, because `has` matches whole terms; parameters and aliases such as `-drtm` are now matched with regex. Generic `-EncodedCommand` use is no longer flagged by itself; payloads are decoded and checked for tampering. Removed the non-existent `AntivirusTampering` action type.
- **MDO-002:** Migrated to `EntraIdSignInEvents` and `RiskLevelAggregated` (`RiskLevelDuringSignIn` does not exist in the retired table). The rule now flags an inbox rule whose IP is absent from the user's successful sign-ins, instead of any mismatch with any single sign-in, which fired for most mobile and VPN users.
- **MDI-003:** The role and target principal are read from `TargetResources` by resource type instead of by array position, and results are grouped by `CorrelationId`.
- **MDVM-004:** Removed the hard-coded four-CVE "KEV" list and the KEV claim; fixed `IsExploitAvailable` (boolean) and `CvssScore` (string) handling; renamed the file accordingly.
- **SENTINEL-005:** ProcDump option regex now covers `-ma`, `-mm` and `-mp` in one pattern, the ordinal regex accepts `#+24`/`#024`, and `SHA1` replaces the usually empty `SHA256`.
- **SENTINEL-006:** Excluded `VaultGet`, which returns vault metadata, not secrets; the threshold now counts distinct secrets per caller; identity claims are read with `column_ifexists`; ATT&CK mapping corrected to T1555.006.

### Changed
- All alert rules are labeled `Experimental` until they have been run against tenant data. The previous `Lab-Validated` labels were not backed by recorded results.
- The validator requires PyYAML; the hand-written YAML fallback parser was removed. Dependencies are pinned.

## [1.1.0] - 2026-11-21

### Fixed & Changed
- **MDVM-004 (`detections/MDVM-004-high-exposure-exploited-critical-vulnerabilities.yaml`):** Renamed from `MDVM-004-unpatched-cisa-kev-high-exposure-endpoints.yaml` and joined `DeviceTvmSoftwareVulnerabilitiesKB` (`IsExploitAvailable == 1`) plus a `KnownExploitedCves` lookup list so the query filters on verified public exploitability and KEV status rather than generic CVSS severity alone.
- **MDI-003 (`detections/MDI-003-privileged-role-assignment-outside-pim.yaml`):** Expanded `OperationName` matching to cover permanent assignments executed inside PIM (`Add member to role outside of PIM (permanent)`, `Add member to role in PIM completed (permanent)`) in addition to direct `"Add member to role"` events, and updated `Account` entity mappings to use `FullName` for UPNs.
- **MDO-002 (`detections/MDO-002-aitm-session-hijack-and-hidden-inbox-rule.yaml`):** Scoped `platform` accurately to `Microsoft Defender XDR` (`CloudAppEvents` / `AADSignInEventsBeta`) and added IP mismatch (`RuleClientIP != SignInIP`), non-interactive logon, and sign-in risk correlation to detect session cookie replay.
- **MDE-001 & SENTINEL-005 Evasion Hardening:** Added `DeviceEvents` (`TamperingAttempt`, `AntivirusTampering`, and `OpenProcessApiCall` against `lsass.exe`), shortened PowerShell parameter prefix matching (`DisableRealtimeMon`), `comsvcs.dll` ordinal `#24` regex matching, and PID-based `procdump -ma` detection.
- Replaced `status: Production` labels with `Hunting / Lab-Validated` and `Hunting / Posture Query` to reflect rule validation scope accurately.

## [1.0.1] - 2026-11-21

### Added
- **Sentinel Entity Type Validation (`src/validate_detections.py`):** Added strict validation against official Microsoft Sentinel `entityType` identifiers and corresponding unit test coverage in `tests/test_detections.py`.

## [1.0.0] - 2026-11-21

### Added
- Initial release of 6 KQL detection and hunting rules (`MDE-001`, `MDO-002`, `MDI-003`, `MDVM-004`, `SENTINEL-005`, `SENTINEL-006`) and static schema validator.
