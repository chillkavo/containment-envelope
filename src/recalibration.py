"""Dynamic recalibration after an incident.

    python3 recalibrate.py

Contrasts two responses to the same incident findings:

  (a) ENUMERATION  - add one prohibition per observed behaviour.
                     The rule set grows without bound.
  (b) RECALIBRATION - narrow the value of an existing granted field,
                     and sweep every grant of the same class.
                     The schema size stays constant.

The measurable claim: enumeration grows the schema, parameterisation
does not.
"""

import copy

from checks import verify
from envelope import digest_of
from trace_incident import INCIDENT_ENVELOPE, INCIDENT_TELEMETRY


def count_fields(env):
    """Number of leaf grant fields in an envelope."""
    n = 0
    for family, fields in env.items():
        if isinstance(fields, dict):
            n += len(fields)
    return n


# ---------------------------------------------------------------------
# (a) What enumeration would have required
# ---------------------------------------------------------------------
# One new prohibition per behaviour observed in the forensic record.
# Every entry is specific to what was seen, and none of them generalise
# to the next variant.

ENUMERATED_RULES = [
    "do not exploit the package registry cache proxy",
    "do not use a request-capture service as a C2 queue",
    "do not use pastebins as second-stage loaders",
    "do not use file-drop hosts for exfiltration",
    "do not use an on-platform CORS proxy as an egress relay",
    "do not rewrite /etc/resolv.conf",
    "do not pin hosts in /etc/hosts",
    "do not monkey-patch socket.getaddrinfo",
    "do not enrol devices into a mesh VPN",
    "do not commit payloads to dataset side branches",
    "do not coordinate through an internal message board",
    "do not create self-respawning pods",
]


# ---------------------------------------------------------------------
# (b) What recalibration requires
# ---------------------------------------------------------------------
# The incident revealed one thing: a DECLARED destination can be an
# escape vector. The response is not a new rule about package proxies.
# It is a class-level sweep over every network grant, narrowing the
# values of fields that already exist.

def recalibrate(env):
    v2 = copy.deepcopy(env)
    v2["version"] = env["version"] + 1

    # Class-level sweep over the network family. The escape used a
    # declared destination, so the response applies to ALL declared
    # destinations, not to the one that was exploited.
    v2["network"]["l7_terminated_egress"] = True          # was False
    v2["network"]["allowed_methods"] = ["GET"]            # was GET, POST
    v2["network"]["max_egress_bytes"] = 1_000_000_000     # was 10e9

    # Credential family: shorten the window a stolen grant stays usable.
    v2["credentials"]["ttl_seconds"] = 3600               # was 86400

    return v2


CHANGES = [
    ("network.l7_terminated_egress", "False", "True"),
    ("network.allowed_methods", "[GET, POST]", "[GET]"),
    ("network.max_egress_bytes", "10,000,000,000", "1,000,000,000"),
    ("credentials.ttl_seconds", "86400", "3600"),
]


def main():
    v1 = INCIDENT_ENVELOPE
    v2 = recalibrate(v1)

    print("# Dynamic recalibration after the July 2026 incident\n")

    print("## (a) Enumeration: one prohibition per observed behaviour\n")
    for i, r in enumerate(ENUMERATED_RULES, 1):
        print("%2d. %s" % (i, r))
    print("\nNew rules required: %d" % len(ENUMERATED_RULES))
    print("Each is specific to an observed behaviour. None constrains the")
    print("next variant: a different pastebin, a different relay, a")
    print("different resolver trick. The list does not converge.")

    print("\n## (b) Recalibration: narrow existing fields\n")
    print("| Field | v%d | v%d |" % (v1["version"], v2["version"]))
    print("|---|---|---|")
    for field, old, new in CHANGES:
        print("| %s | %s | %s |" % (field, old, new))

    print("\nNew fields added: 0")
    print("Values narrowed: %d" % len(CHANGES))

    print("\n## Schema size\n")
    print("| | Fields |")
    print("|---|---|")
    print("| Envelope v%d | %d |" % (v1["version"], count_fields(v1)))
    print("| Envelope v%d | %d |" % (v2["version"], count_fields(v2)))
    print("| Enumerated rule set | %d and growing |" % len(ENUMERATED_RULES))

    print("\n## Effect on verifiability\n")
    tel = dict(INCIDENT_TELEMETRY)

    tel["envelope_hash"] = digest_of(v1)
    f1 = verify(v1, tel)
    cov1 = [f for f in f1 if f.severity == "coverage"]

    tel2 = copy.deepcopy(tel)
    tel2["envelope_hash"] = digest_of(v2)
    # Under v2 the lab terminates egress at L7, so requests are inspected.
    tel2["network"]["uninspected_requests"] = 0
    f2 = verify(v2, tel2)
    cov2 = [f for f in f2 if f.severity == "coverage"]

    print("| | Findings | Coverage gaps |")
    print("|---|---|---|")
    print("| v%d | %d | %d |" % (v1["version"], len(f1), len(cov1)))
    print("| v%d | %d | %d |" % (v2["version"], len(f2), len(cov2)))
    print("\nRecalibration closed the V2 coverage gap without adding a")
    print("field: allowed_methods became externally verifiable because an")
    print("existing boolean was narrowed, not because a rule was written.")

    print("\n## Limit\n")
    print("Recalibration does not close V8. Narrowing a ceiling moves the")
    print("threshold; it does not make a within-limit action distinguishable")
    print("from a legitimate one. Parameterisation bounds how many rules a")
    print("standard needs. It does not extend what aggregates can observe.")


if __name__ == "__main__":
    main()