# Changelog

All notable changes to **Defender-Sentinel-KQL-Detections** are documented in this file.

## [1.0.0] - 2026-11-21

### Added
- Initial release of 6 KQL detection and hunting rules (MDE-001, MDO-002, MDI-003, MDVM-004, SENTINEL-005, SENTINEL-006) spanning Microsoft Defender XDR (DeviceProcessEvents, CloudAppEvents, AADSignInEventsBeta, DeviceTvmSoftwareVulnerabilities) and Microsoft Sentinel (AuditLogs, AzureDiagnostics).
- Static schema and MITRE ATT&CK validator (src/validate_detections.py) checking tactic/technique formatting, ISO-8601 lookback windows (queryFrequency <= queryPeriod), table references, and entityMappings column integrity.
- Unit test suite (	ests/test_detections.py) and GitHub Actions CI workflow (.github/workflows/ci.yml).