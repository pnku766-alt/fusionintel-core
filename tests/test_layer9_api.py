from __future__ import annotations

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def _base_policy() -> dict:
    return {
        "layer4": {"allowed_jurisdictions": ["US"], "allowed_residency_classes": ["domestic"]},
        "layer5": {"require_layer4_allow": False},
        "layer6": {"include_payload": False, "redact_payload_keys": []},
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


def test_healthz() -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_process_deliver() -> None:
    body = {"policy": _base_policy(), "envelope": _base_envelope()}
    r = client.post("/v1/process", json=body)
    assert r.status_code == 200
    j = r.json()
    assert j["layer4"]["allow"] is True
    assert j["layer5"]["action"] == "deliver"


def test_process_blocks_when_layer4_not_allowed_and_layer5_requires_layer4() -> None:
    policy = _base_policy()
    policy["layer5"]["require_layer4_allow"] = True

    env = _base_envelope()
    env["jurisdiction_tags"]["jurisdiction"] = "CN"

    r = client.post("/v1/process", json={"policy": policy, "envelope": env})
    assert r.status_code == 200
    j = r.json()
    assert j["layer4"]["allow"] is False
    assert j["layer5"]["action"] == "block"