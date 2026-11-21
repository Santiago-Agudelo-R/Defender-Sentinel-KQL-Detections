#!/usr/bin/env python3
"""
Detection-as-Code schema and static KQL validator for Microsoft Defender XDR
and Microsoft Sentinel analytic rules.

Validates:
- Required rule metadata fields (id, title, basis, platform, severity, status, etc.)
- Allowed status values (Experimental, Hunting, Tested)
- MITRE ATT&CK tactic names and technique ID format (Txxxx or Txxxx.xxx)
- ISO-8601 duration strings for queryFrequency and queryPeriod
- Table reference consistency between relevantTables and the KQL query body
- Entity mapping column presence and valid Sentinel entityType names in the KQL query body

Author: Santiago Agudelo
License: MIT
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

REQUIRED_FIELDS = {
    "id",
    "title",
    "basis",
    "platform",
    "severity",
    "status",
    "queryFrequency",
    "queryPeriod",
    "triggerOperator",
    "triggerThreshold",
    "tactics",
    "techniques",
    "relevantTables",
    "entityMappings",
    "description",
    "query",
}

VALID_SEVERITIES = {"Informational", "Low", "Medium", "High"}
VALID_BASIS = {"Field experience", "SC-200 lab"}
# Experimental: syntax and schema validated, not yet run against tenant data.
# Hunting: posture or hunting query meant to be run on demand, not as an alert.
# Tested: run against tenant data and tuned for false positives.
VALID_STATUSES = {"Experimental", "Hunting", "Tested"}
VALID_OPERATORS = {"gt", "lt", "eq", "ne"}
VALID_ENTITY_TYPES = {"Account", "Host", "IP", "Process", "AzureResource", "File", "FileHash", "Mailbox", "CloudApplication"}
VALID_MITRE_TACTICS = {
    "Reconnaissance",
    "ResourceDevelopment",
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Collection",
    "CommandAndControl",
    "Exfiltration",
    "Impact",
}

MITRE_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
ISO_DURATION_RE = re.compile(r"^P(?:\d+D|T(?:\d+H|\d+M))$")
KQL_OPERATOR_RE = re.compile(r"\|\s*(where|project|summarize|extend|join|order\s+by)\b")


def load_detection_yaml(path: Path) -> Dict[str, Any]:
    """Load a detection YAML file into a dictionary."""
    parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"{path.name}: expected a YAML mapping at the top level")
    return parsed


def parse_duration_minutes(duration_str: str) -> Optional[int]:
    """Convert an ISO-8601 duration (e.g., PT30M, PT1H, P1D) into minutes."""
    if not ISO_DURATION_RE.match(duration_str):
        return None
    if duration_str.startswith("PT"):
        body = duration_str[2:]
        if body.endswith("H"):
            return int(body[:-1]) * 60
        if body.endswith("M"):
            return int(body[:-1])
    elif duration_str.startswith("P") and duration_str.endswith("D"):
        return int(duration_str[1:-1]) * 1440
    return None


def validate_detection(rule: Dict[str, Any], source_name: str = "<memory>") -> List[str]:
    """Validate a parsed detection rule dictionary and return a list of errors (empty if valid)."""
    errors: List[str] = []

    missing = REQUIRED_FIELDS - set(rule.keys())
    if missing:
        errors.append(f"{source_name}: Missing required fields: {sorted(missing)}")
        return errors

    if rule["severity"] not in VALID_SEVERITIES:
        errors.append(
            f"{source_name}: Invalid severity '{rule['severity']}'. Expected one of {sorted(VALID_SEVERITIES)}"
        )

    if rule["status"] not in VALID_STATUSES:
        errors.append(
            f"{source_name}: Invalid status '{rule['status']}'. Expected one of {sorted(VALID_STATUSES)}"
        )

    if rule["basis"] not in VALID_BASIS:
        errors.append(
            f"{source_name}: Invalid basis '{rule['basis']}'. Expected one of {sorted(VALID_BASIS)}"
        )

    if rule["triggerOperator"] not in VALID_OPERATORS:
        errors.append(
            f"{source_name}: Invalid triggerOperator '{rule['triggerOperator']}'"
        )

    if not isinstance(rule["triggerThreshold"], int) or rule["triggerThreshold"] < 0:
        errors.append(f"{source_name}: triggerThreshold must be a non-negative integer")

    freq_min = parse_duration_minutes(str(rule["queryFrequency"]))
    period_min = parse_duration_minutes(str(rule["queryPeriod"]))
    if freq_min is None:
        errors.append(
            f"{source_name}: Invalid ISO-8601 queryFrequency '{rule['queryFrequency']}'"
        )
    if period_min is None:
        errors.append(
            f"{source_name}: Invalid ISO-8601 queryPeriod '{rule['queryPeriod']}'"
        )
    if freq_min is not None and period_min is not None and freq_min > period_min:
        errors.append(
            f"{source_name}: queryFrequency ({rule['queryFrequency']}) cannot exceed queryPeriod ({rule['queryPeriod']})"
        )

    tactics = rule.get("tactics") or []
    if not isinstance(tactics, list) or not tactics:
        errors.append(f"{source_name}: tactics must be a non-empty list")
    else:
        for t in tactics:
            if t not in VALID_MITRE_TACTICS:
                errors.append(f"{source_name}: Unrecognized MITRE tactic '{t}'")

    techniques = rule.get("techniques") or []
    if not isinstance(techniques, list) or not techniques:
        errors.append(f"{source_name}: techniques must be a non-empty list")
    else:
        for tech in techniques:
            if not MITRE_TECHNIQUE_RE.match(str(tech)):
                errors.append(
                    f"{source_name}: Invalid MITRE technique ID '{tech}' (expected Txxxx or Txxxx.xxx)"
                )

    query_text = str(rule.get("query") or "").strip()
    if not query_text:
        errors.append(f"{source_name}: KQL query cannot be empty")
        return errors

    if not KQL_OPERATOR_RE.search(query_text):
        errors.append(
            f"{source_name}: KQL query does not contain standard tabular operators (| where, | project, | summarize)"
        )

    tables = rule.get("relevantTables") or []
    if not isinstance(tables, list) or not tables:
        errors.append(f"{source_name}: relevantTables must be a non-empty list")
    else:
        for tbl in tables:
            if not re.search(rf"\b{re.escape(str(tbl))}\b", query_text):
                errors.append(
                    f"{source_name}: Declared table '{tbl}' in relevantTables is not referenced in KQL query"
                )

    mappings = rule.get("entityMappings") or []
    if not isinstance(mappings, list) or not mappings:
        errors.append(f"{source_name}: entityMappings must be a non-empty list")
    else:
        for em in mappings:
            etype = str(em.get("entityType", "")).strip()
            if etype not in VALID_ENTITY_TYPES:
                errors.append(
                    f"{source_name}: Unsupported Sentinel entityType '{etype}'. Expected one of {sorted(VALID_ENTITY_TYPES)}"
                )
            for fm in em.get("fieldMappings", []):
                col = str(fm.get("columnName", "")).strip()
                if not col or not re.search(rf"\b{re.escape(col)}\b", query_text):
                    errors.append(
                        f"{source_name}: Entity mapping column '{col}' is not projected or referenced in KQL query"
                    )

    return errors


def validate_directory(detections_dir: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Validate all *.yaml files in a directory."""
    yaml_files = sorted(detections_dir.glob("*.yaml"))
    all_rules: List[Dict[str, Any]] = []
    all_errors: List[str] = []
    seen_ids: set[str] = set()

    if not yaml_files:
        all_errors.append(f"No .yaml detection files found in {detections_dir}")
        return all_rules, all_errors

    for path in yaml_files:
        rule = load_detection_yaml(path)
        errs = validate_detection(rule, source_name=path.name)
        all_errors.extend(errs)
        rule_id = str(rule.get("id", ""))
        if rule_id in seen_ids:
            all_errors.append(f"{path.name}: Duplicate rule id '{rule_id}'")
        seen_ids.add(rule_id)
        all_rules.append(rule)

    return all_rules, all_errors


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Microsoft Defender XDR & Sentinel KQL detection YAML files."
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=Path("detections"),
        help="Path to directory containing detection .yaml files.",
    )
    args = parser.parse_args(argv)

    rules, errors = validate_directory(args.path)
    if errors:
        for err in errors:
            print(f"[FAIL] {err}", file=sys.stderr)
        return 1

    print(f"[OK] Validated {len(rules)} KQL detection rules in '{args.path}' with 0 errors.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
