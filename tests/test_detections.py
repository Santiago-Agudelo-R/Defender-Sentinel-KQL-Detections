# Author: Santiago Agudelo | License: MIT
from __future__ import annotations

import copy
from pathlib import Path

import pytest

from src.validate_detections import (
    load_detection_yaml,
    parse_duration_minutes,
    validate_detection,
    validate_directory,
)


def test_all_repository_detections_pass_validation() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    detections_dir = repo_root / "detections"
    rules, errors = validate_directory(detections_dir)
    assert errors == []
    assert len(rules) == 6


def test_duration_parser_accepts_valid_iso8601_and_rejects_invalid() -> None:
    assert parse_duration_minutes("PT30M") == 30
    assert parse_duration_minutes("PT2H") == 120
    assert parse_duration_minutes("P1D") == 1440
    assert parse_duration_minutes("1h") is None
    assert parse_duration_minutes("INVALID") is None


def test_validator_catches_invalid_mitre_technique_and_tactic() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    sample_file = (
        repo_root
        / "detections"
        / "MDE-001-tamper-protection-and-sensor-evasion.yaml"
    )
    rule = load_detection_yaml(sample_file)

    bad_rule = copy.deepcopy(rule)
    bad_rule["tactics"] = ["NotARealTactic"]
    bad_rule["techniques"] = ["T99999"]
    errs = validate_detection(bad_rule, "bad_mitre.yaml")
    assert any("Unrecognized MITRE tactic" in e for e in errs)
    assert any("Invalid MITRE technique ID" in e for e in errs)


def test_validator_catches_unreferenced_table_and_missing_entity_column() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    sample_file = (
        repo_root
        / "detections"
        / "MDE-001-tamper-protection-and-sensor-evasion.yaml"
    )
    rule = load_detection_yaml(sample_file)

    bad_rule = copy.deepcopy(rule)
    bad_rule["relevantTables"] = ["DeviceProcessEvents", "NonExistentTable"]
    bad_rule["entityMappings"][0]["fieldMappings"][0]["columnName"] = "MissingColumnXYZ"

    errs = validate_detection(bad_rule, "bad_table.yaml")
    assert any("NonExistentTable" in e for e in errs)
    assert any("MissingColumnXYZ" in e for e in errs)


def test_validator_catches_query_frequency_greater_than_period() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    sample_file = (
        repo_root
        / "detections"
        / "MDE-001-tamper-protection-and-sensor-evasion.yaml"
    )
    rule = load_detection_yaml(sample_file)

    bad_rule = copy.deepcopy(rule)
    bad_rule["queryFrequency"] = "P1D"
    bad_rule["queryPeriod"] = "PT1H"

    errs = validate_detection(bad_rule, "bad_window.yaml")
    assert any("cannot exceed queryPeriod" in e for e in errs)

def test_validator_catches_unsupported_sentinel_entity_type() -> None:
    rules = [
        load_detection_yaml(p)
        for p in sorted((REPO_ROOT / "detections").glob("*.yaml"))
    ]
    sample = dict(rules[0])
    sample["entityMappings"] = [
        {
            "entityType": "InvalidEntityType",
            "fieldMappings": [{"identifier": "HostName", "columnName": "DeviceName"}],
        }
    ]
    errors = validate_detection(sample, source_name="bad_entity_type.yaml")
    assert any("Unsupported Sentinel entityType" in e for e in errors)
