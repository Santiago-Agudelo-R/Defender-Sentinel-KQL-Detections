# Defender-Sentinel-KQL-Detections

KQL hunting queries and Microsoft Sentinel analytic rule definitions for **Microsoft Defender XDR** (`MDE`, `MDO`, `MDVM`) and **Microsoft Sentinel** (SC-200 lab track), with a Python static validator for schema, MITRE ATT&CK, and entity-mapping consistency.

[![KQL](https://img.shields.io/badge/Language-KQL-0078D4.svg)](https://learn.microsoft.com/en-us/kusto/query/)
[![Python 3.10+](https://img.shields.io/badge/Validator-Python_3.10%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/Santiago-Agudelo-R/Defender-Sentinel-KQL-Detections?color=success)](https://github.com/Santiago-Agudelo-R/Defender-Sentinel-KQL-Detections/releases)

---

## Overview

`Defender-Sentinel-KQL-Detections` stores Microsoft Defender XDR advanced hunting queries and Microsoft Sentinel scheduled analytic rule templates as structured YAML files. Each file is checked by `src/validate_detections.py` (using `PyYAML`) to verify:

1. **MITRE ATT&CK Alignment:** Valid tactic names (`DefenseEvasion`, `Persistence`, `PrivilegeEscalation`, `CredentialAccess`, `Collection`, `InitialAccess`) and technique IDs (`Txxxx` or `Txxxx.xxx`).
2. **Lookback & Scheduling Windows:** Valid ISO-8601 `queryFrequency` and `queryPeriod` values (`queryFrequency <= queryPeriod`).
3. **Table & Entity-Mapping Integrity:** Every table listed in `relevantTables` and every column mapped in `entityMappings` (`Host`, `Account`, `IP`, `Process`, `AzureResource`) must appear in the KQL query body and use valid Microsoft Sentinel entity types.

---

## Detection & Hunting Catalog

| Rule ID | Title | Platform | Tables | MITRE ATT&CK | Basis & Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| [**MDE-001**](detections/MDE-001-tamper-protection-and-sensor-evasion.yaml) | Microsoft Defender Sensor Tampering and Realtime Monitoring Disablement | Defender XDR | `DeviceProcessEvents`, `DeviceEvents` | `T1562.001` | Field experience (`Hunting / Lab-Validated`) |
| [**MDO-002**](detections/MDO-002-aitm-session-hijack-and-hidden-inbox-rule.yaml) | Post-Sign-In Suspicious Exchange Online Inbox Rule or Forwarding Modification | Defender XDR | `CloudAppEvents`, `AADSignInEventsBeta` | `T1564.008`, `T1114.003` | SC-200 lab (`Lab-Validated`) |
| [**MDI-003**](detections/MDI-003-privileged-role-assignment-outside-pim.yaml) | Permanent High-Privilege Entra ID Role Assignment (Direct or Permanent PIM) | Microsoft Sentinel | `AuditLogs` | `T1098.003` | Field experience (`Hunting / Lab-Validated`) |
| [**MDVM-004**](detections/MDVM-004-high-exposure-exploited-critical-vulnerabilities.yaml) | High-Exposure Endpoints with Unpatched Exploited or KEV Critical Vulnerabilities | Defender XDR | `DeviceTvmSoftwareVulnerabilities`, `DeviceTvmSoftwareVulnerabilitiesKB`, `DeviceInfo` | `T1190`, `T1068` | Field experience (`Hunting / Posture Query`) |
| [**SENTINEL-005**](detections/SENTINEL-005-credential-dumping-lsass-access.yaml) | Credential Dumping via `comsvcs.dll` (`MiniDump` / Ordinal 24), ProcDump, or Direct LSASS Access | Microsoft Sentinel | `DeviceProcessEvents`, `DeviceEvents` | `T1003.001` | SC-200 lab (`Lab-Validated`) |
| [**SENTINEL-006**](detections/SENTINEL-006-azure-keyvault-mass-secret-retrieval.yaml) | Anomalous Mass Secret Retrieval from Azure Key Vault | Microsoft Sentinel | `AzureDiagnostics` | `T1552.004`, `T1530` | SC-200 lab (`Lab-Validated`) |

**Basis:** *Field experience* queries reflect hunting patterns from day-to-day Defender XDR and Entra ID operations. *SC-200 lab* queries come from self-directed Microsoft Sentinel detection engineering labs. None of these rules should be enabled as automated blocking rules without first baselining false-positive volume in your tenant.

---

## Usage & Validation

Validate all detection rules locally using the Python validator:

```powershell
PS> python src/validate_detections.py --path detections
[OK] Validated 6 KQL detection rules in 'detections' with 0 errors.
```

Run the `pytest` unit test suite:

```powershell
PS> python -m pytest -v
============================= test session starts =============================
collected 6 items

tests/test_detections.py::test_all_repository_detections_pass_validation PASSED [ 16%]
tests/test_detections.py::test_duration_parser_accepts_valid_iso8601_and_rejects_invalid PASSED [ 33%]
tests/test_detections.py::test_validator_catches_invalid_mitre_technique_and_tactic PASSED [ 50%]
tests/test_detections.py::test_validator_catches_unreferenced_table_and_missing_entity_column PASSED [ 66%]
tests/test_detections.py::test_validator_catches_query_frequency_greater_than_period PASSED [ 83%]
tests/test_detections.py::test_validator_catches_unsupported_sentinel_entity_type PASSED [100%]

============================== 6 passed in 0.12s ==============================
```

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
