"""A third party's entry point: verify an envelope against a telemetry
digest without ever touching the lab's network.

    python3 verify_cli.py envelope.yaml telemetry.json
    python3 verify_cli.py --selftest
    python3 verify_cli.py --sign-demo

Exit codes: 0 = clean (no high-severity findings), 1 = the inputs do not
validate against the schema (malformed, or a family present in one
artifact with nothing to check it against -- these are reported as
findings of their own, not silently skipped), 2 = the inputs validate
and the verifier found a high-severity violation.

Dependency note: the schema's canonical examples ship as YAML
(Schema/envelope.example.yaml). PyYAML is not standard library, and the
brief for this artifact is "no external dependencies, runs with
`python3 x.py` on a clean machine" -- so this file includes a small,
explicitly scoped YAML-subset loader (block mappings, block sequences,
folded scalars) rather than depending on it. It is not a general YAML
parser and does not try to be; JSON input is unaffected and preferred
wherever a caller controls the format.
"""

import hashlib
import hmac
import json
import sys

from checks import verify
from envelope import BASE_ENVELOPE, BASE_TELEMETRY, digest_of

FAMILIES = ["network", "credentials", "tools", "files", "compute",
            "persistence", "model_runtime"]
CROSS_CUTTING_TEL_KEYS = ["envelope_hash", "reporting_window",
                          "telemetry_coverage", "signers_by_family"]


# ---------------------------------------------------------------------
# A minimal, explicitly scoped YAML-subset loader. Supports: block
# mappings, block sequences of scalars, block sequences of small inline
# mappings ("- host: x\n  port: y"), folded (">") and literal ("|")
# scalars, and bare int/float/bool/string scalars. Does not support flow
# style, anchors, multi-document files, or tags -- none of which this
# schema uses.
# ---------------------------------------------------------------------

def _tokenize(text):
    toks = []
    for raw in text.splitlines():
        if not raw.strip() or raw.strip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        toks.append((indent, raw.strip()))
    return toks


def _looks_like_mapping(s):
    # A colon introduces a YAML key only when followed by a space or at
    # end of line -- "ref:eval-readonly-token" is a scalar, "ref: eval"
    # is a mapping. Plain `':' in s` conflates the two.
    return ": " in s or s.endswith(":")


def _parse_scalar(s):
    if s in ("true", "True"):
        return True
    if s in ("false", "False"):
        return False
    if s in ("null", "~", ""):
        return None
    if s == "[]":
        return []
    if s == "{}":
        return {}
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        pass
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        return s[1:-1]
    return s


def _split_kv(line):
    idx = line.find(":")
    if idx == -1:
        return line, ""
    return line[:idx].strip(), line[idx + 1:].strip()


def _parse_nodes(toks, i, indent):
    if i >= len(toks) or toks[i][0] != indent:
        return {}, i
    is_seq = toks[i][1].startswith("- ") or toks[i][1] == "-"
    if is_seq:
        items = []
        while i < len(toks) and toks[i][0] == indent and \
                (toks[i][1].startswith("- ") or toks[i][1] == "-"):
            content = toks[i][1]
            rest = content[1:].strip()
            i += 1
            if rest == "":
                child, i = _parse_nodes(toks, i, indent + 2)
                items.append(child)
            elif _looks_like_mapping(rest):
                key, val = _split_kv(rest)
                item = {}
                if val == "":
                    child, i = _parse_nodes(toks, i, indent + 2)
                    item[key] = child
                else:
                    item[key] = _parse_scalar(val)
                while i < len(toks) and toks[i][0] == indent + 2:
                    k2, v2 = _split_kv(toks[i][1])
                    i += 1
                    if v2 == "":
                        child, i = _parse_nodes(toks, i, indent + 4)
                        item[k2] = child
                    else:
                        item[k2] = _parse_scalar(v2)
                items.append(item)
            else:
                items.append(_parse_scalar(rest))
        return items, i
    else:
        out = {}
        while i < len(toks) and toks[i][0] == indent:
            key, val = _split_kv(toks[i][1])
            i += 1
            if val in (">", "|"):
                parts = []
                while i < len(toks) and toks[i][0] > indent:
                    parts.append(toks[i][1])
                    i += 1
                out[key] = " ".join(parts) if val == ">" else "\n".join(parts)
            elif val == "":
                if i < len(toks) and toks[i][0] > indent:
                    child, i = _parse_nodes(toks, i, toks[i][0])
                    out[key] = child
                else:
                    out[key] = None
            else:
                out[key] = _parse_scalar(val)
        return out, i


def load_yaml_subset(text):
    toks = _tokenize(text)
    if not toks:
        return {}
    value, _ = _parse_nodes(toks, 0, toks[0][0])
    return value


def load_file(path):
    with open(path) as f:
        text = f.read()
    if path.endswith((".yaml", ".yml")):
        return load_yaml_subset(text)
    return json.loads(text)


# ---------------------------------------------------------------------
# Schema validation. checks.py assumes every family/field it reads is
# present and will raise KeyError otherwise -- that is correct for a
# module that trusts its caller, but wrong for a CLI a third party runs
# against an arbitrary file. This layer turns "malformed" and
# "structurally unverifiable" into reported findings instead of a crash.
# ---------------------------------------------------------------------

def validate_envelope(env):
    errors = []
    if not isinstance(env, dict):
        return ["envelope does not parse to a mapping"]
    for fam in FAMILIES:
        if fam not in env:
            errors.append("envelope is missing required family '%s'" % fam)
            continue
        for field in BASE_ENVELOPE[fam]:
            if field not in env[fam]:
                errors.append("envelope family '%s' is missing field '%s'"
                               % (fam, field))
    return errors


def validate_telemetry(env, tel):
    errors = []
    if not isinstance(tel, dict):
        return ["telemetry does not parse to a mapping"]
    for key in CROSS_CUTTING_TEL_KEYS:
        if key not in tel:
            errors.append("telemetry is missing required key '%s'" % key)

    signers = tel.get("signers_by_family", {}) or {}
    env_families = set(env) if isinstance(env, dict) else set()

    for fam in FAMILIES:
        in_env = fam in env_families
        in_tel = fam in tel
        if in_tel and not in_env:
            errors.append(
                "telemetry reports family '%s' with no corresponding "
                "envelope declaration -- these counters are unverifiable: "
                "there is no grant to check them against" % fam)
        if in_env and not in_tel:
            errors.append(
                "envelope declares family '%s' but telemetry reports no "
                "counters for it -- the grant is unmeasured, not merely "
                "unused" % fam)
        if in_tel:
            for field in BASE_TELEMETRY[fam]:
                if field not in tel[fam]:
                    errors.append(
                        "telemetry family '%s' is missing counter '%s'"
                        % (fam, field))
        if (in_env or in_tel) and fam not in signers:
            errors.append(
                "family '%s' has no entry in signers_by_family -- its "
                "counters are asserted but not attributably signed" % fam)
    return errors


# ---------------------------------------------------------------------
# Signing demo: signer separation VERIFIED, not merely asserted.
# t4_signer_separation in checks.py checks that a signer's NAME differs
# from the component's name -- a naming convention. It cannot detect
# whether a "signer" is cryptographically anything at all. This demo
# adds the other half: an HMAC per family, so a verifier can tell
# whether a family's counters were altered after the claimed signer
# produced them. The two checks are complementary, not redundant: HMAC
# proves integrity under a claimed key; t4 proves the claimed key-holder
# is not the component being measured. Neither alone is sufficient.
# ---------------------------------------------------------------------

DEMO_SIGNER_KEYS = {
    "kms-net-a": b"demo-key-net-a-NOT-FOR-PRODUCTION",
    "kms-sec-b": b"demo-key-sec-b-NOT-FOR-PRODUCTION",
    "kms-rt-c": b"demo-key-rt-c-NOT-FOR-PRODUCTION",
    "kms-art-d": b"demo-key-art-d-NOT-FOR-PRODUCTION",
    "kms-inf-e": b"demo-key-inf-e-NOT-FOR-PRODUCTION",
    "proxy-egress": b"demo-key-proxy-egress-NOT-FOR-PRODUCTION",
}


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sign_family(counters, signer_id):
    key = DEMO_SIGNER_KEYS[signer_id]
    return hmac.new(key, _canonical(counters), hashlib.sha256).hexdigest()


def check_family_signature(counters, signer_id, signature):
    if signer_id not in DEMO_SIGNER_KEYS:
        return False
    return hmac.compare_digest(sign_family(counters, signer_id), signature)


def signing_demo():
    print("# Signing demo: separation verified, not asserted\n")
    tel = BASE_TELEMETRY
    signers = tel["signers_by_family"]

    print("## Each family signed by its claimed signer\n")
    print("| Family | Signer | Signature (truncated) | Verifies? |")
    print("|---|---|---|---|")
    signatures = {}
    for fam, info in signers.items():
        sig = sign_family(tel[fam], info["signer"])
        signatures[fam] = sig
        ok = check_family_signature(tel[fam], info["signer"], sig)
        print("| %s | %s | %s... | %s |" % (fam, info["signer"], sig[:16],
                                             "yes" if ok else "no"))

    print("\n## Tamper check: mutate network counters after signing\n")
    tampered = dict(tel["network"])
    tampered["total_egress_bytes"] = tel["network"]["total_egress_bytes"] + 999_000
    still_valid = check_family_signature(tampered, signers["network"]["signer"],
                                          signatures["network"])
    print("Signature computed before the change, checked against the "
          "changed counters: %s" % ("VALID (bug)" if still_valid else
                                     "REJECTED -- tamper detected"))

    print("\n## Cryptographic validity is not the same claim as separation\n")
    self_sig = sign_family(tel["network"], "proxy-egress")
    self_valid = check_family_signature(tel["network"], "proxy-egress", self_sig)
    print("If 'network' were signed by 'proxy-egress' (the component "
          "itself, not an independent signer), the HMAC still verifies: "
          "%s. The signature alone cannot tell you the signer and the "
          "component are the same party -- that is what "
          "t4_signer_separation checks structurally, by comparing "
          "identities, not bytes. A real deployment needs both: HMAC (or "
          "a real KMS signature) for integrity, t4 for independence."
          % ("valid" if self_valid else "invalid"))


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------

def run_verification(env, tel, label=""):
    errors = validate_envelope(env)
    errors += validate_telemetry(env, tel)

    if label:
        print("# %s\n" % label)

    if errors:
        print("## Schema validation failed\n")
        for e in errors:
            print("- %s" % e)
        print("\nverify() was not run: the inputs do not validate against "
              "the reference shape in envelope.py.")
        return 1

    print("## Schema validation passed\n")
    findings = verify(env, tel)
    print("## Findings\n")
    if not findings:
        print("(none)\n")
    else:
        print("| Class | Severity | Message |")
        print("|---|---|---|")
        for f in findings:
            print("| %s | %s | %s |" % (f.violation, f.severity, f.message))
    high = [f for f in findings if f.severity == "high"]
    print("\n%d finding(s), %d high-severity." % (len(findings), len(high)))
    return 2 if high else 0


def selftest():
    print("# Self-test\n")

    print("## 1. Malformed envelope (missing model_runtime)\n")
    import copy
    broken = copy.deepcopy(BASE_ENVELOPE)
    del broken["model_runtime"]
    tel = copy.deepcopy(BASE_TELEMETRY)
    tel["envelope_hash"] = digest_of(broken)
    code1 = run_verification(broken, tel)
    print("\nExit code would be: %d\n" % code1)

    print("## 2. Clean, valid envelope/telemetry pair\n")
    env = copy.deepcopy(BASE_ENVELOPE)
    tel2 = copy.deepcopy(BASE_TELEMETRY)
    tel2["envelope_hash"] = digest_of(env)
    code2 = run_verification(env, tel2)
    print("\nExit code would be: %d\n" % code2)

    print("## 3. Signing demo\n")
    signing_demo()

    return 0


def main():
    args = sys.argv[1:]
    if "--sign-demo" in args:
        signing_demo()
        sys.exit(0)
    if "--selftest" in args or not args:
        sys.exit(selftest())

    if len(args) != 2:
        print("usage: verify_cli.py envelope.(yaml|json) telemetry.json", file=sys.stderr)
        sys.exit(1)

    env_path, tel_path = args
    try:
        env = load_file(env_path)
        tel = load_file(tel_path)
    except Exception as e:
        print("could not parse input: %s" % e, file=sys.stderr)
        sys.exit(1)

    code = run_verification(env, tel, label="Verification: %s / %s" % (env_path, tel_path))
    sys.exit(code)


if __name__ == "__main__":
    main()
