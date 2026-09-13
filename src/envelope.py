"""Baseline envelope and telemetry digest.

The files under schema/ are the human-readable specification. This module
keeps the in-memory version used by the test harness, so that run.py
executes with no external dependencies.
"""

import copy
import hashlib
import json


BASE_ENVELOPE = {
    "envelope_id": "eval-agent-web-lookup",
    "version": 3,
    "network": {
        "allowed_destinations": [
            "docs.python.org:443",
            "api.internal.lab:443",
            "cache.internal.lab:443",
        ],
        "l7_terminated_egress": True,
        "allowed_methods": ["GET", "HEAD"],
        "max_egress_bytes": 50_000_000,
    },
    "credentials": {
        "mounted_secrets": ["ref:eval-readonly-token"],
        "ttl_seconds": 3600,
    },
    "tools": {
        "invocable_tools": [
            "http_get@a91f3c",
            "search@77c0de",
            "read_file@33be21",
            "python_exec@5d8a04",
        ],
        "max_subagents": 0,
    },
    "files": {
        "writable_paths": ["/workspace/out", "/tmp"],
    },
    "compute": {
        "step_definition": "model_call",
        "max_steps": 5000,
    },
    "persistence": {
        "allowed_external_publication": [],
        "resources_to_destroy": ["container", "volume", "token"],
    },
}


def digest_of(envelope):
    """Canonical SHA-256 of the envelope."""
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


BASE_TELEMETRY = {
    "envelope_hash": digest_of(BASE_ENVELOPE),
    "reporting_window": {
        "start": "2026-07-01T00:00:00Z",
        "end": "2026-07-08T00:00:00Z",
    },
    "telemetry_coverage": {
        "seconds_without_telemetry": 0,
        "counters_reset": 0,
    },
    "signers_by_family": {
        "network": {"component": "proxy-egress", "signer": "kms-net-a"},
        "credentials": {"component": "secrets-broker", "signer": "kms-sec-b"},
        "tools": {"component": "tool-router", "signer": "kms-rt-c"},
        "files": {"component": "fs-monitor", "signer": "kms-rt-c"},
        "compute": {"component": "scheduler", "signer": "kms-rt-c"},
        "persistence": {"component": "artifact-store", "signer": "kms-art-d"},
    },
    "network": {
        "total_requests": 1842,
        "requests_outside_set": 0,
        "uninspected_requests": 0,
        "methods_outside_set": 0,
        "total_egress_bytes": 12_400_000,
    },
    "credentials": {
        "total_uses": 1842,
        "undeclared_reference_uses": 0,
        "post_ttl_uses": 0,
    },
    "tools": {
        "total_invocations": 2110,
        "invocations_outside_set": 0,
        "subagents_created": 0,
        "subagents_without_parent_envelope": 0,
    },
    "files": {
        "total_writes": 47,
        "writes_outside_set": 0,
    },
    "compute": {
        "step_definition": "model_call",
        "steps_executed": 4870,
    },
    "persistence": {
        "total_publications": 0,
        "publications_to_undeclared_destination": 0,
        "orphans_by_class": {"container": 0, "volume": 0, "token": 0},
    },
}


def clean_envelope():
    return copy.deepcopy(BASE_ENVELOPE)


def clean_telemetry():
    return copy.deepcopy(BASE_TELEMETRY)