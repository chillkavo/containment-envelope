"""Run the verifier over every case and emit the detectability matrix.

    python3 run.py

No external dependencies.
"""

from cases import build_cases
from checks import verify

CLASSES = ["V1", "V2", "V3", "V4", "V5", "V6", "V7", "V8", "V9", "V10", "V11"]

NAMES = {
    "V1": "Egress to an undeclared destination",
    "V2": "Undeclared method on a declared destination",
    "V3": "Use of an unmounted credential",
    "V4": "Invocation of an undeclared tool",
    "V5": "Compute budget exceeded",
    "V6": "Persistence outside what was declared",
    "V7": "Exfiltration by anomalous volume",
    "V8": "Exfiltration within every declared limit",
    "V9": "Cross-sandbox coordination via a shared destination",
    "V10": "Declared envelope differs from the applied one",
    "V11": "Safety-control state differs from what was declared",
}


def classify(detected, total):
    if total == 0:
        return "no case"
    if detected == total:
        return "Yes"
    if detected == 0:
        return "No"
    return "Partial (%d/%d)" % (detected, total)


def main():
    cases = build_cases()

    by_class = {c: [0, 0] for c in CLASSES}   # [detected, total]
    false_positives = 0
    clean_runs = 0
    rows = []

    for name, env, tel, truth in cases:
        findings = verify(env, tel)
        found = {f.violation for f in findings if f.severity not in ("coverage", "declared")}
        coverage = [f for f in findings if f.severity in ("coverage", "declared")]

        if truth is None:
            clean_runs += 1
            if found:
                false_positives += 1
            status = "FP" if found else "ok"
        else:
            by_class[truth][1] += 1
            hit = truth in found
            if hit:
                by_class[truth][0] += 1
            status = "detected" if hit else "NOT detected"
            if not hit and coverage:
                status = "coverage declared"

        rows.append((name, truth or "-", status, len(findings)))

    print("# Results\n")
    print("## Per-case detail\n")
    print("| Case | Ground truth | Outcome | Findings |")
    print("|---|---|---|---|")
    for row in rows:
        print("| %s | %s | %s | %d |" % row)

    print("\n## Detectability matrix\n")
    print("| ID | Violation class | Detectable |")
    print("|---|---|---|")
    for c in CLASSES:
        det, tot = by_class[c]
        print("| %s | %s | %s |" % (c, NAMES[c], classify(det, tot)))

    full = sum(1 for c in CLASSES
               if by_class[c][1] and by_class[c][0] == by_class[c][1])
    partial = sum(1 for c in CLASSES
                  if by_class[c][1] and 0 < by_class[c][0] < by_class[c][1])
    none = sum(1 for c in CLASSES
               if by_class[c][1] and by_class[c][0] == 0)

    print("\n## Summary\n")
    print("- Classes evaluated: %d" % len([c for c in CLASSES if by_class[c][1]]))
    print("- Fully detectable: %d" % full)
    print("- Partially detectable: %d" % partial)
    print("- Not detectable: %d" % none)
    print("- Clean control runs: %d" % clean_runs)
    print("- False positives: %d" % false_positives)


if __name__ == "__main__":
    main()