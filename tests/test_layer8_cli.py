from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _base_policy(audit_path: str) -> dict:
    return {
        "layer4": {
            "allowed_jurisdictions": ["US"],
            "allowed_residency_classes": ["domestic"],
            "blocked_export_control_flags": [],
            "blocked_sanctions_flags": [],
        },
        "layer5": {
            "blocked_export_control_flags": [],
            "blocked_sanctions_flags": [],
            "quarantine_export_control_flags": [],
            "quarantine_sanctions_flags": [],
            "require_layer4_allow": False,
        },
        "layer6": {"include_payload": False, "redact_payload_keys": []},
        "audit_log_path": audit_path,
    }


def _base_envelope() -> dict:
    return {
        "artifact_id": "a-1",
        "artifact_type": "intel",
        "producer_layer": "layer3",
        "payload": {"k": "v"},
        "metadata": {"m": "n"},
        "jurisdiction_tags": {
            "jurisdiction": "US",
            "residency_class": "domestic",
            "export_control_flags": [],
            "sanctions_flags": [],
        },
    }


def _run_cli(policy_path: Path, envelope_path: Path | None, stdin_payload: str | None = None):
    cmd = [sys.executable, "-m", "orchestrator.cli", "--policy", str(policy_path)]
    if envelope_path is not None:
        cmd.extend(["--envelope", str(envelope_path)])
    return subprocess.run(
        cmd,
        input=stdin_payload,
        text=True,
        capture_output=True,
        check=False,
    )


def test_cli_deliver_exit_0(tmp_path: Path) -> None:
    policy = _base_policy(str(tmp_path / "audit.log"))
    envelope = _base_envelope()

    policy_path = tmp_path / "policy.json"
    envelope_path = tmp_path / "envelope.json"
    _write_json(policy_path, policy)
    _write_json(envelope_path, envelope)

    completed = _run_cli(policy_path, envelope_path)

    assert completed.returncode == 0
    payload = json.loads(completed.stdout)
    assert payload["layer5"]["action"] == "deliver"
    assert payload["audit_written"] is True


def test_cli_quarantine_exit_2(tmp_path: Path) -> None:
    policy = _base_policy(str(tmp_path / "audit.log"))
    policy["layer5"]["quarantine_export_control_flags"] = ["NLR"]
    envelope = _base_envelope()
    envelope["jurisdiction_tags"]["export_control_flags"] = ["NLR"]

    policy_path = tmp_path / "policy.json"
    envelope_path = tmp_path / "envelope.json"
    _write_json(policy_path, policy)
    _write_json(envelope_path, envelope)

    completed = _run_cli(policy_path, envelope_path)

    assert completed.returncode == 2
    payload = json.loads(completed.stdout)
    assert payload["layer5"]["action"] == "quarantine"


def test_cli_block_exit_3(tmp_path: Path) -> None:
    policy = _base_policy(str(tmp_path / "audit.log"))
    policy["layer5"]["blocked_sanctions_flags"] = ["SDN"]
    envelope = _base_envelope()
    envelope["jurisdiction_tags"]["sanctions_flags"] = ["SDN"]

    policy_path = tmp_path / "policy.json"
    envelope_path = tmp_path / "envelope.json"
    _write_json(policy_path, policy)
    _write_json(envelope_path, envelope)

    completed = _run_cli(policy_path, envelope_path)

    assert completed.returncode == 3
    payload = json.loads(completed.stdout)
    assert payload["layer5"]["action"] == "block"


def test_cli_reads_envelope_from_stdin(tmp_path: Path) -> None:
    policy = _base_policy(str(tmp_path / "audit.log"))
    envelope = _base_envelope()

    policy_path = tmp_path / "policy.json"
    _write_json(policy_path, policy)

    completed = _run_cli(policy_path, envelope_path=None, stdin_payload=json.dumps(envelope))

    assert completed.returncode == 0
    payload = json.loads(completed.stdout)
    assert payload["layer5"]["action"] == "deliver"
