"""Verifier checks.

Every check takes (envelope, telemetry) and returns a list of findings.
All logic is a comparison between a declared field and an aggregate
counter: the verifier never needs access to the lab's network.
"""

from collections import namedtuple

from envelope import digest_of

Finding = namedtuple("Finding", "violation severity message")


# --- cross-cutting block ----------------------------------------------

def t1_hash_binding(env, tel):
    if tel["envelope_hash"] != digest_of(env):
        return [Finding("V10", "high",
                        "digest was issued against an envelope other than "
                        "the published one")]
    return []


def t2_declared_window(env, tel):
    w = tel.get("reporting_window", {})
    if not w.get("start") or not w.get("end"):
        return [Finding("V10", "medium", "reporting window is not declared")]
    return []


def t3_telemetry_coverage(env, tel):
    c = tel["telemetry_coverage"]
    out = []
    if c["seconds_without_telemetry"] > 0:
        out.append(Finding("V10", "high",
                           "degraded digest: %d s without telemetry; a zero "
                           "counter is not evidence that no event occurred"
                           % c["seconds_without_telemetry"]))
    if c["counters_reset"] > 0:
        out.append(Finding("V10", "medium",
                           "counters were reset during the window"))
    return out


def t4_signer_separation(env, tel):
    fam = tel["signers_by_family"]
    out = []
    for name, f in fam.items():
        if f["signer"] == f["component"]:
            out.append(Finding("V10", "high",
                               "family '%s' is self-reported: the signer is "
                               "the component under observation" % name))
    signers = {f["signer"] for f in fam.values()}
    if len(signers) == 1 and not out:
        out.append(Finding("V10", "medium",
                           "partial separation: all families share a single "
                           "signer"))
    return out


# --- network -----------------------------------------------------------

def v1_undeclared_destination(env, tel):
    if tel["network"]["requests_outside_set"] > 0:
        return [Finding("V1", "high",
                        "%d requests to destinations outside the declared set"
                        % tel["network"]["requests_outside_set"])]
    return []


def v2_undeclared_method(env, tel):
    if not env["network"]["l7_terminated_egress"]:
        return [Finding("V2", "coverage",
                        "egress is not L7-terminated: allowed_methods is not "
                        "externally verifiable")]
    if tel["network"]["methods_outside_set"] > 0:
        return [Finding("V2", "high",
                        "%d requests using a method outside the declared set"
                        % tel["network"]["methods_outside_set"])]
    if tel["network"]["uninspected_requests"] > 0:
        return [Finding("V2", "medium",
                        "%d uninspected requests despite declaring L7 "
                        "termination" % tel["network"]["uninspected_requests"])]
    return []


def v7_egress_volume(env, tel):
    if tel["network"]["total_egress_bytes"] > env["network"]["max_egress_bytes"]:
        return [Finding("V7", "high",
                        "egress bytes (%d) above the declared ceiling (%d)"
                        % (tel["network"]["total_egress_bytes"],
                           env["network"]["max_egress_bytes"]))]
    return []


# --- credentials -------------------------------------------------------

def v3_unmounted_credential(env, tel):
    if tel["credentials"]["undeclared_reference_uses"] > 0:
        return [Finding("V3", "high",
                        "%d uses of credentials not declared in the envelope"
                        % tel["credentials"]["undeclared_reference_uses"])]
    return []


def v3b_credential_past_ttl(env, tel):
    if tel["credentials"]["post_ttl_uses"] > 0:
        return [Finding("V3", "medium",
                        "%d uses after the declared TTL of %d s"
                        % (tel["credentials"]["post_ttl_uses"],
                           env["credentials"]["ttl_seconds"]))]
    return []


# --- tools -------------------------------------------------------------

def v4_undeclared_tool(env, tel):
    if tel["tools"]["invocations_outside_set"] > 0:
        return [Finding("V4", "high",
                        "%d invocations of tools outside the declared set "
                        "(includes silent schema expansion)"
                        % tel["tools"]["invocations_outside_set"])]
    return []


def v4b_subagents(env, tel):
    out = []
    t, e = tel["tools"], env["tools"]
    if t["subagents_created"] > e["max_subagents"]:
        out.append(Finding("V4", "high",
                           "%d subagents created; declared maximum is %d"
                           % (t["subagents_created"], e["max_subagents"])))
    if t["subagents_without_parent_envelope"] > 0:
        out.append(Finding("V4", "high",
                           "%d subagents without a declared parent envelope"
                           % t["subagents_without_parent_envelope"]))
    return out


# --- files -------------------------------------------------------------

def v6b_write_outside_path(env, tel):
    if tel["files"]["writes_outside_set"] > 0:
        return [Finding("V6", "high",
                        "%d writes outside the declared paths"
                        % tel["files"]["writes_outside_set"])]
    return []


# --- compute -----------------------------------------------------------

def v5_step_budget_exceeded(env, tel):
    if tel["compute"]["steps_executed"] > env["compute"]["max_steps"]:
        return [Finding("V5", "high",
                        "%d steps executed; declared maximum is %d"
                        % (tel["compute"]["steps_executed"],
                           env["compute"]["max_steps"]))]
    return []


def v5b_step_definition(env, tel):
    if tel["compute"]["step_definition"] != env["compute"]["step_definition"]:
        return [Finding("V5", "coverage",
                        "incomparable step definition: envelope declares "
                        "'%s', digest reports '%s'"
                        % (env["compute"]["step_definition"],
                           tel["compute"]["step_definition"]))]
    return []


# --- persistence -------------------------------------------------------

def v6_external_publication(env, tel):
    out = []
    p, e = tel["persistence"], env["persistence"]
    if not e["allowed_external_publication"] and p["total_publications"] > 0:
        out.append(Finding("V6", "high",
                           "%d external publications while the declared "
                           "destination list is empty" % p["total_publications"]))
    if p["publications_to_undeclared_destination"] > 0:
        out.append(Finding("V6", "high",
                           "%d publications to undeclared destinations"
                           % p["publications_to_undeclared_destination"]))
    return out


def v6c_orphaned_resources(env, tel):
    out = []
    for cls, n in tel["persistence"]["orphans_by_class"].items():
        if n != 0:
            out.append(Finding("V6", "medium",
                               "%d orphaned resources of class '%s'; the "
                               "teardown invariant requires zero" % (n, cls)))
    return out


CHECKS = [
    t1_hash_binding,
    t2_declared_window,
    t3_telemetry_coverage,
    t4_signer_separation,
    v1_undeclared_destination,
    v2_undeclared_method,
    v7_egress_volume,
    v3_unmounted_credential,
    v3b_credential_past_ttl,
    v4_undeclared_tool,
    v4b_subagents,
    v6b_write_outside_path,
    v5_step_budget_exceeded,
    v5b_step_definition,
    v6_external_publication,
    v6c_orphaned_resources,
]


def verify(envelope, telemetry):
    """Return the list of findings from every check."""
    findings = []
    for check in CHECKS:
        findings.extend(check(envelope, telemetry))
    return findings