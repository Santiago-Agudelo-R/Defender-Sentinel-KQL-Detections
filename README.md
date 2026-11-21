# Defender-Sentinel-KQL-Detections

Detection-as-code for **Microsoft Defender XDR** and **Microsoft Sentinel**: six KQL rules stored as YAML, each checked in CI by a metadata validator and by Microsoft's own Kusto parser against the documented table schemas.

[![CI](https://github.com/Santiago-Agudelo-R/Defender-Sentinel-KQL-Detections/actions/workflows/ci.yml/badge.svg)](https://github.com/Santiago-Agudelo-R/Defender-Sentinel-KQL-Detections/actions/workflows/ci.yml)
[![KQL](https://img.shields.io/badge/Language-KQL-0078D4.svg)](https://learn.microsoft.com/kusto/query/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Detection catalog

| Rule | What it finds | Platform | Tables | ATT&CK | Basis | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| [MDE-001](detections/MDE-001-tamper-protection-and-sensor-evasion.yaml) | Attempts to switch off Defender protections, add exclusions or stop `WinDefend`/`Sense`, including short aliases (`-drtm`) and decoded `-EncodedCommand` payloads | Defender XDR | `DeviceProcessEvents`, `DeviceEvents` | T1562.001 | Field experience | Experimental |
| [MDO-002](detections/MDO-002-aitm-session-hijack-and-hidden-inbox-rule.yaml) | Inbox rules or forwarding created from an IP that never appears in the user's own sign-ins (AiTM session-cookie replay) | Defender XDR | `CloudAppEvents`, `EntraIdSignInEvents` | T1564.008, T1114.003 | SC-200 lab | Experimental |
| [MDI-003](detections/MDI-003-privileged-role-assignment-outside-pim.yaml) | Permanent Tier-0 Entra ID role assignments, direct or through PIM, excluding time-bound activations | Sentinel | `AuditLogs` | T1098.003 | Field experience | Experimental |
| [MDVM-004](detections/MDVM-004-high-exposure-exploitable-critical-vulnerabilities.yaml) | High-exposure devices ranked by Critical CVEs with public exploits, internet-facing first | Defender XDR | `DeviceTvmSoftwareVulnerabilities`, `...KB`, `DeviceInfo` | T1190, T1068 | Field experience | Hunting |
| [SENTINEL-005](detections/SENTINEL-005-credential-dumping-lsass-access.yaml) | LSASS dumping via `comsvcs.dll` (name or ordinal 24), ProcDump by name or PID, `createdump`, and direct LSASS handle opens | Sentinel | `DeviceProcessEvents`, `DeviceEvents` | T1003.001 | SC-200 lab | Experimental |
| [SENTINEL-006](detections/SENTINEL-006-azure-keyvault-mass-secret-retrieval.yaml) | One caller reading many **distinct** Key Vault secrets in an hour | Sentinel | `AzureDiagnostics` | T1555.006 | SC-200 lab | Experimental |

**Status** is enforced by the validator:

- **Experimental:** syntax and schema validated in CI; not yet run against tenant data, so false-positive volume is unknown.
- **Hunting:** posture or hunting query to run on demand, not an alert.
- **Tested:** run against tenant data and tuned for false positives. No rule has this status yet.

**Basis:** *Field experience* rules come from day-to-day Defender XDR and Entra ID work; *SC-200 lab* rules come from self-directed Sentinel labs. Each rule's `description` lists its expected noise.

---

## Design notes

A few decisions that shape the queries:

- **`has` matches whole terms.** Parameter prefixes and aliases (`-DisableRealtimeMon…`, `-drtm`) are matched with regex, because `has "DisableRealtimeMon"` would not match `DisableRealtimeMonitoring`.
- **AiTM detection compares IPs against the user's sign-in history**, not against a single sign-in. Comparing against any one sign-in fires on every mobile or VPN user.
- **`AADSignInEventsBeta` was retired on 2026-10-19.** MDO-002 uses its replacement, `EntraIdSignInEvents`, and the aggregated risk column `RiskLevelAggregated`.
- **`SHA256` is usually empty in device tables**, per Microsoft's schema reference, so rules project `SHA1`.
- **MDVM-004 is not a KEV rule.** Defender exposes `IsExploitAvailable`, not the CISA KEV catalog. To scope to KEV, join the published KEV CSV with `externaldata`.
- **TVM tables are not ingested into Sentinel**, so MDVM-004 runs in Defender XDR advanced hunting.

---

## Validation pipeline

Every push runs [`.github/workflows/ci.yml`](.github/workflows/ci.yml):

1. **Metadata validator** ([`src/validate_detections.py`](src/validate_detections.py)): required fields, allowed status and basis values, MITRE tactic and technique format, ISO-8601 schedule with `queryFrequency <= queryPeriod`, valid Sentinel entity types, and every declared table and mapped column present in the query.
2. **Unit tests** ([`tests/`](tests)): the validator rejects each class of broken rule.
3. **KQL syntax and schema check** ([`tools/kql-lint`](tools/kql-lint)): parses each query with [`@kusto/language-service-next`](https://www.npmjs.com/package/@kusto/language-service-next), the Kusto.Language engine behind Microsoft's query editors, against the column names and types in [`schema.kql-schema`](tools/kql-lint/schema.kql-schema), which are copied from Microsoft Learn. It fails on unknown tables or columns, retired tables and malformed operators.

Run it locally:

```bash
pip install -r requirements-dev.txt
python src/validate_detections.py --path detections
pytest -v

cd tools/kql-lint && npm ci && npm run lint
```

Limits: the parser proves a query is well-formed against the documented schema, not that it returns the right rows. That needs tenant data, which is what the **Tested** status is for.

---

## License

MIT. See [LICENSE](LICENSE).
