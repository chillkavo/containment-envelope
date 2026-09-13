"""Detection latency: turn the paper's central claim into a measurement.

    python3 latency.py

The paper claims attestation-based containment "bounds how long a failure
stays invisible from outside." Nothing in the existing artifact measures
this. This script builds a per-day telemetry schedule for the July 2026
incident from the documented phase action counts, re-runs the unmodified
verifier (checks.py) against a synthetic digest for each day, and records
the first day each violation class would have fired -- then repeats that
under three publication cadences to show how the number degrades.

Deterministic. No random sampling is used anywhere in this script: the
per-day activity schedule is a fixed proportional allocation, not a draw
from a distribution, so there is no seed to state. (Compare noise.py and
cases with a genuine sampling step, which do state and fix a seed.)
"""

import copy
from datetime import date, timedelta

from checks import verify
from envelope import digest_of
from trace_incident import INCIDENT_ENVELOPE, INCIDENT_TELEMETRY

# ---------------------------------------------------------------------
# Ground truth: documented phase action counts from the task brief /
# HF forensic reconstruction. Everything below this block is either
# copied verbatim from trace_incident.py or an explicitly flagged
# allocation choice -- never a second, hidden fact.
# ---------------------------------------------------------------------

PHASE_ACTIONS = {
    "recon": 6191,
    "rce": 2911,
    "dropper": 6972,
    "exfil": 56,
    "c2": 114,
    "evasion": 6,
    "k8s": 87,
    "supply_chain": 69,
    "mesh": 115,
}

# Kill-chain order. The public record does not give phase-level timestamps,
# so this ordering is an assumption (standard intrusion progression: recon,
# initial access, delivery, C2, lateral movement, replication, objective,
# anti-forensics), stated here rather than left implicit.
PHASE_ORDER = ["recon", "rce", "dropper", "c2", "k8s", "mesh",
               "supply_chain", "exfil", "evasion"]

ACTIVE_WINDOW_DAYS = 5    # [DOC] first action 07-09, last 07-13 -> 5 calendar days
ATTRIBUTION_DAY = 12      # [DOC] 07-09 -> public attribution 07-21
START_DATE = date(2026, 7, 9)
HORIZON_DAYS = 60         # long enough to let a monthly digest land

# Each phase's counter contribution and the ratio at which its actions
# convert into that counter, taken from the [DOC] annotations already in
# trace_incident.py (e.g. "files.total_writes: 6_972 # dropper phase
# actions", "40_000_000 # 56 exfil actions"). Nothing here is a new fact.
PHASE_TO_COUNTER_RATIO = {
    "c2": 100 / 114,            # network.requests_outside_set, of 114 c2 actions
    "dropper": 6972 / 6972,     # files.total_writes, 1:1 as documented
    "exfil": 40_000_000 / 56,   # network.total_egress_bytes, bytes per action
    "k8s": 11 / 87,             # persistence.orphans_by_class[container]
    "mesh": 181 / 115,          # persistence.orphans_by_class[token]
    "supply_chain": 5 / 69,     # persistence.total_publications
}


def iso(day_offset):
    return (START_DATE + timedelta(days=day_offset - 1)).isoformat() + "T00:00:00Z"


def phase_day_allocation():
    """For each phase, its float action count on each day 1..ACTIVE_WINDOW_DAYS.

    Uniform-within-phase: each phase is spread evenly across its own slot
    of the kill-chain timeline. Absent action-level timestamps in the
    public record, uniform is the allocation that assumes the least --
    it does not privilege an early or late burst within a phase that
    nothing in the record supports.
    """
    total = sum(PHASE_ACTIONS.values())
    pos = 0.0
    slots = {}
    for p in PHASE_ORDER:
        start = pos
        pos += PHASE_ACTIONS[p]
        slots[p] = (start / total * ACTIVE_WINDOW_DAYS, pos / total * ACTIVE_WINDOW_DAYS)

    alloc = {p: {} for p in PHASE_ORDER}
    for p, (s, e) in slots.items():
        for d in range(1, ACTIVE_WINDOW_DAYS + 1):
            day_start, day_end = d - 1, d
            overlap = max(0.0, min(e, day_end) - max(s, day_start))
            frac = overlap / (e - s) if e > s else 0.0
            alloc[p][d] = frac * PHASE_ACTIONS[p]
    return alloc


def phase_cumulative_table(horizon):
    """Cumulative action count per phase, per day 0..horizon. Flat after
    ACTIVE_WINDOW_DAYS: the attacker is dormant, no further actions accrue,
    but resources already created (orphans, publications) do not un-happen."""
    alloc = phase_day_allocation()
    table = {0: {p: 0.0 for p in PHASE_ORDER}}
    for d in range(1, horizon + 1):
        prev = table[d - 1]
        table[d] = {p: prev[p] + alloc[p].get(d, 0.0) for p in PHASE_ORDER}
    return table


def build_period_telemetry(flow, state, day_start, day_end):
    """flow = this period's own activity (resets each publication, matching
    the single-reporting-window shape of BASE_TELEMETRY/INCIDENT_TELEMETRY).
    state = cumulative-to-date activity, used only for fields that are a
    point-in-time state assertion rather than a per-window flow count:
    orphaned resources and total publications describe what currently
    exists, not what happened in the last window, so they do not reset."""
    tel = copy.deepcopy(INCIDENT_TELEMETRY)
    total_flow = sum(flow.values())

    tel["reporting_window"] = {"start": iso(day_start), "end": iso(day_end + 1)}
    tel["telemetry_coverage"] = {"seconds_without_telemetry": 0, "counters_reset": 0}
    # signers_by_family is left untouched: it is a structural property of
    # the lab's signing topology, not a function of accumulated telemetry.

    tel["network"]["total_requests"] = round(total_flow)
    tel["network"]["uninspected_requests"] = round(total_flow)
    tel["network"]["methods_outside_set"] = 0
    tel["network"]["requests_outside_set"] = round(flow["c2"] * PHASE_TO_COUNTER_RATIO["c2"])
    tel["network"]["total_egress_bytes"] = round(flow["exfil"] * PHASE_TO_COUNTER_RATIO["exfil"])

    tel["credentials"]["total_uses"] = round(total_flow)
    tel["credentials"]["undeclared_reference_uses"] = 0
    tel["credentials"]["post_ttl_uses"] = 0

    tel["tools"]["total_invocations"] = round(total_flow)
    tel["tools"]["invocations_outside_set"] = 0
    tel["tools"]["subagents_created"] = 0
    tel["tools"]["subagents_without_parent_envelope"] = 0

    tel["files"]["total_writes"] = round(flow["dropper"] * PHASE_TO_COUNTER_RATIO["dropper"])
    tel["files"]["writes_outside_set"] = 0

    tel["compute"]["steps_executed"] = round(total_flow)

    pubs = round(state["supply_chain"] * PHASE_TO_COUNTER_RATIO["supply_chain"])
    tel["persistence"]["total_publications"] = pubs
    tel["persistence"]["publications_to_undeclared_destination"] = pubs
    tel["persistence"]["orphans_by_class"] = {
        "container": round(state["k8s"] * PHASE_TO_COUNTER_RATIO["k8s"]),
        "volume": 0,
        "token": round(state["mesh"] * PHASE_TO_COUNTER_RATIO["mesh"]),
    }

    tel["model_runtime"]["total_model_calls"] = round(total_flow)
    tel["model_runtime"]["calls_with_classifiers_disabled"] = round(total_flow)
    tel["model_runtime"]["calls_with_reduced_refusals"] = round(total_flow)

    tel["envelope_hash"] = digest_of(INCIDENT_ENVELOPE)
    return tel


def run_cadence(period_days, cum):
    """Return {violation_class: first_publication_day} under a fixed
    publication cadence."""
    first_fire = {}
    k = 0
    while True:
        k += 1
        day_start = (k - 1) * period_days + 1
        day_end = k * period_days
        if day_start > HORIZON_DAYS:
            break
        end_clamped = min(day_end, HORIZON_DAYS)
        start_clamped = min(day_start - 1, HORIZON_DAYS)
        flow = {p: cum[end_clamped][p] - cum[start_clamped][p] for p in PHASE_ORDER}
        state = {p: cum[end_clamped][p] for p in PHASE_ORDER}

        tel = build_period_telemetry(flow, state, day_start, day_end)
        findings = verify(INCIDENT_ENVELOPE, tel)
        for f in findings:
            if f.severity in ("high", "medium") and f.violation not in first_fire:
                first_fire[f.violation] = day_end
    return first_fire


def main():
    cum = phase_cumulative_table(HORIZON_DAYS)

    cadences = [("daily", 1), ("weekly", 7), ("monthly", 30)]
    results = {}
    for name, period in cadences:
        results[name] = run_cadence(period, cum)

    all_classes = sorted(set().union(*[set(r) for r in results.values()]))

    print("# Detection latency\n")
    print("Active attack window: days 1-%d (2026-07-09 to 2026-07-13, [DOC]).\n"
          "Baseline: public attribution at day %d (2026-07-09 to 2026-07-21, [DOC]).\n"
          % (ACTIVE_WINDOW_DAYS, ATTRIBUTION_DAY))

    print("## Primary result: daily cadence vs the attribution baseline\n")
    print("| Class | First day detected | Days saved vs %d-day baseline |"
          % ATTRIBUTION_DAY)
    print("|---|---|---|")
    for c in all_classes:
        d = results["daily"].get(c)
        if d is None:
            continue
        saved = ATTRIBUTION_DAY - d
        print("| %s | %d | %+d |" % (c, d, saved))

    print("\n## Cadence sensitivity\n")
    print("| Class | Daily (day) | Weekly (day) | Monthly (day) | "
          "Days saved, daily | Days saved, monthly |")
    print("|---|---|---|---|---|---|")
    for c in all_classes:
        d = results["daily"].get(c)
        w = results["weekly"].get(c)
        m = results["monthly"].get(c)
        d_saved = ATTRIBUTION_DAY - d if d is not None else None
        m_saved = ATTRIBUTION_DAY - m if m is not None else None
        print("| %s | %s | %s | %s | %s | %s |" % (
            c,
            d if d is not None else "-",
            w if w is not None else "-",
            m if m is not None else "-",
            ("%+d" % d_saved) if d_saved is not None else "-",
            ("%+d" % m_saved) if m_saved is not None else "-",
        ))

    print("\nMonthly cadence bundles the entire active window into the first")
    print("digest, published on day 30 -- *after* the day-%d attribution"
          " baseline. At monthly cadence, attestation is slower than the"
          " investigation that actually happened; this is the honest"
          " downside of the cadence trade-off, not an edge case." % ATTRIBUTION_DAY)

    print("\n## Classes that never fire, at any cadence, in this incident\n")
    print("| Class | Why |")
    print("|---|---|")
    print("| V2 | Coverage gap, not a detection: `l7_terminated_egress` is "
          "declared False, so method use is out of scope by the lab's own "
          "honest declaration -- flagged every period, never as a finding. |")
    print("| V3 | Not observed: this incident used no undeclared credential "
          "reference. Detectable class, absent case. |")
    print("| V4 | Not observed: the escape used its declared shell tool. "
          "Detectable class, absent case. |")
    print("| V7 | Not triggered: reconstructed egress (40 MB) stays under "
          "the reconstructed ceiling (10 GB). Whether this holds for other "
          "plausible ceilings is exactly what sensitivity.py checks -- do "
          "not read this row as \"V7 is undetectable.\" |")
    print("| V8 | Not detectable by design: the escape used a declared "
          "destination within every declared limit. No cadence helps. |")
    print("| V9 | Not detectable by design: cross-sandbox coordination is "
          "invisible from a single digest regardless of cadence. |")
    print("| V11 | Fires as `declared`, not a violation: the envelope "
          "honestly grants disabled classifiers for this environment. |")

    print("\n## Daily activity schedule (allocation detail)\n")
    print("| Day | Date | Actions this day | Cumulative |")
    print("|---|---|---|---|")
    running = 0
    for d in range(1, ACTIVE_WINDOW_DAYS + 1):
        day_total = sum(cum[d][p] - cum[d - 1][p] for p in PHASE_ORDER)
        running += day_total
        print("| %d | %s | %d | %d |" % (d, iso(d)[:10], round(day_total), round(running)))


if __name__ == "__main__":
    main()
