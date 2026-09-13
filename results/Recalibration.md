# Dynamic recalibration after the July 2026 incident

## (a) Enumeration: one prohibition per observed behaviour

 1. do not exploit the package registry cache proxy
 2. do not use a request-capture service as a C2 queue
 3. do not use pastebins as second-stage loaders
 4. do not use file-drop hosts for exfiltration
 5. do not use an on-platform CORS proxy as an egress relay
 6. do not rewrite /etc/resolv.conf
 7. do not pin hosts in /etc/hosts
 8. do not monkey-patch socket.getaddrinfo
 9. do not enrol devices into a mesh VPN
10. do not commit payloads to dataset side branches
11. do not coordinate through an internal message board
12. do not create self-respawning pods

New rules required: 12
Each is specific to an observed behaviour. None constrains the
next variant: a different pastebin, a different relay, a
different resolver trick. The list does not converge.

## (b) Recalibration: narrow existing fields

| Field | v1 | v2 |
|---|---|---|
| network.l7_terminated_egress | False | True |
| network.allowed_methods | [GET, POST] | [GET] |
| network.max_egress_bytes | 10,000,000,000 | 1,000,000,000 |
| credentials.ttl_seconds | 86400 | 3600 |

New fields added: 0
Values narrowed: 4

## Schema size

| | Fields |
|---|---|
| Envelope v1 | 13 |
| Envelope v2 | 13 |
| Enumerated rule set | 12 and growing |

## Effect on verifiability

| | Findings | Coverage gaps |
|---|---|---|
| v1 | 10 | 1 |
| v2 | 9 | 0 |

Recalibration closed the V2 coverage gap without adding a
field: allowed_methods became externally verifiable because an
existing boolean was narrowed, not because a rule was written.

## Limit

Recalibration does not close V8. Narrowing a ceiling moves the
threshold; it does not make a within-limit action distinguishable
from a legitimate one. Parameterisation bounds how many rules a
standard needs. It does not extend what aggregates can observe.