"""The convergence argument as a curve, not a single data point.

    python3 growth.py

recalibration.py shows what ONE incident required: 12 new prohibitions
under enumeration, 0 new fields (4 narrowed values) under parameterisation.
That is one point, not a trend. This script simulates a sequence of N
successive incidents, each revealing some new attacker techniques, and
tracks rule-set size under enumeration against grant-field count under
parameterisation across the sequence.

This is a MODEL, calibrated to the one real data point this artifact has
(12 rules / 0 fields for the July 2026 incident), not a forecast. Treat
the shape of the divergence as the claim -- enumeration's growth rate
does not go to zero, parameterisation's does -- not the specific numbers
at incident 30.

Deterministic: seed = 2026, stated once, used for every draw below.
"""

import random

from recalibration import count_fields
from trace_incident import INCIDENT_ENVELOPE

SEED = 2026
N_INCIDENTS = 30
BASE_FIELDS = count_fields(INCIDENT_ENVELOPE)  # 15, the only real envelope in this artifact

# Enumeration: calibrated so incident 1's expected new-rule count matches
# the one real data point (12, from recalibration.ENUMERATED_RULES). The
# decay is slow and never reaches zero -- attacker techniques are
# combinatorially large, so novel-technique discovery slows as the
# obvious ones get listed, but does not stop. This is what "does not
# converge" means quantitatively: cumulative rules grow asymptotically
# linear, with slope approaching FLOOR, not zero.
BASE_K = 12
DECAY = 0.97
FLOOR = 3
NOISE_SIGMA = 1.5   # incident-to-incident variation in technique count;
# Gaussian because it is a small perturbation around an expected count,
# not itself the source of the trend.

# Parameterisation: calibrated so incident 1 has 0 expected new fields
# (matching recalibration.py exactly). A genuinely new GRANT FAMILY
# (as opposed to a new value for an existing one) is rarer than a new
# technique, and gets rarer faster: the space of distinct capability
# families an execution environment can grant (network, credentials,
# tools, files, compute, persistence, model runtime, ...) is bounded,
# unlike the space of attacker techniques, so this probability decays
# toward saturation rather than a nonzero floor.
P_NEW_FIELD_0 = 0.06
FIELD_DECAY = 0.90


def simulate(n, seed):
    rng = random.Random(seed)
    enum_cumulative = 0
    field_count = BASE_FIELDS
    rows = []
    for i in range(1, n + 1):
        if i == 1:
            # Incident 1 IS the real data point (recalibration.py), not a
            # draw: 12 rules, 0 new fields, exactly. Noise only applies to
            # the incidents this artifact has no ground truth for.
            k = BASE_K
            new_field = 0
        else:
            k = BASE_K * (DECAY ** (i - 1)) + rng.gauss(0, NOISE_SIGMA)
            k = max(FLOOR, round(k))
            p_new = P_NEW_FIELD_0 * (FIELD_DECAY ** (i - 1))
            new_field = 1 if rng.random() < p_new else 0
        enum_cumulative += k
        field_count += new_field

        rows.append({
            "incident": i,
            "new_rules": k,
            "enum_total": enum_cumulative,
            "new_field": new_field,
            "field_total": field_count,
        })
    return rows


def bar(value, max_value, width=50):
    n = int(round(value / max_value * width)) if max_value else 0
    return "#" * max(0, n)


def main():
    rows = simulate(N_INCIDENTS, SEED)

    print("# Convergence: enumeration vs. parameterisation\n")
    print("N = %d simulated incidents, seed = %d. Incident 1 is calibrated "
          "to reproduce recalibration.py's real numbers exactly: %d new "
          "rules, %d new fields.\n"
          % (N_INCIDENTS, SEED, rows[0]["new_rules"], rows[0]["new_field"]))

    print("## Per-incident table\n")
    print("| Incident | New rules (enum) | Enum total | New field? | Field total |")
    print("|---|---|---|---|---|")
    for r in rows:
        print("| %d | %d | %d | %s | %d |" % (
            r["incident"], r["new_rules"], r["enum_total"],
            "yes" if r["new_field"] else "-", r["field_total"]))

    max_val = rows[-1]["enum_total"]
    print("\n## ASCII chart (shared scale, 1 char ~= %.1f rules)\n"
          % (max_val / 50))
    print("```")
    for r in rows:
        if r["incident"] % 2 == 1 or r["incident"] == N_INCIDENTS:
            print("i%-3d enum   |%-50s %d" % (r["incident"],
                  bar(r["enum_total"], max_val), r["enum_total"]))
            print("     fields |%-50s %d" % (
                  bar(r["field_total"], max_val), r["field_total"]))
    print("```")

    print("\n## Summary\n")
    print("| | Incident 1 | Incident %d | Growth |" % N_INCIDENTS)
    print("|---|---|---|---|")
    print("| Enumerated rules (cumulative) | %d | %d | %.1fx |" % (
        rows[0]["enum_total"], rows[-1]["enum_total"],
        rows[-1]["enum_total"] / rows[0]["enum_total"]))
    print("| Grant fields (cumulative) | %d | %d | %.1fx |" % (
        BASE_FIELDS, rows[-1]["field_total"],
        rows[-1]["field_total"] / BASE_FIELDS))

    last10_rules = sum(r["new_rules"] for r in rows[-10:])
    last10_fields = sum(r["new_field"] for r in rows[-10:])
    print("\nIn the final 10 simulated incidents, enumeration is still "
          "adding %.1f rules/incident on average (floor = %d); "
          "parameterisation added %d new fields across the same 10 "
          "incidents. The gap is not that parameterisation grows "
          "slower -- by incident %d it has effectively stopped, while "
          "enumeration has not, and by construction (FLOOR > 0) never "
          "does." % (last10_rules / 10, FLOOR, last10_fields, N_INCIDENTS))

    print("\n## Limit of this model\n")
    print("This simulation cannot show parameterisation reaching a "
          "capability boundary it cannot express -- an incident that "
          "genuinely requires an eighth grant family this schema has no "
          "field for would show up here as `new_field=yes`, but the model "
          "has no way to say whether the SCHEMA's checks.py would need a "
          "new check function to read that field, only whether the "
          "envelope needed a new key. That distinction is a real gap "
          "between this script and the paper's convergence claim, not a "
          "number the model can resolve.")


if __name__ == "__main__":
    main()
