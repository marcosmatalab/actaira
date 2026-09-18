# The SARIF 2.1.0 schema, vendored

`sarif-schema-2.1.0.json` is the normative JSON Schema for SARIF 2.1.0, as OASIS
serves it. It is here so `tests/test_seal_and_report.py` can validate what
`report/sarif.py` writes against the specification rather than against another
function of ours, which is the shape `docs/DESIGN.md` D-15 warns about: a writer
and a reader that share a mistake agree with each other perfectly.

| | |
|---|---|
| URL | <https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json> |
| Retrieved | 2026-09-18 |
| sha256 | `c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e` |
| Bytes | 112 768 |
| Licence | OASIS Standard, Errata 01. Redistributable under the OASIS IPR policy, which permits copying and distribution of the specification and its artifacts in full, with the copyright notice the file itself carries. |

Reproduce it:

```sh
curl -sL https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json \
  | sha256sum
```

The same bytes are served from
`https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json`;
both were fetched on 2026-09-18 and their digests were identical, which is why
the OASIS URL is the one recorded: it is the normative one, and the GitHub copy
tracks a branch that can move.

It is a schema and not a configuration, so the rule about fixtures carrying no
malicious payload does not need an exception for it: there is nothing here to
execute. It is also not read by anything in `src/`. Validating what this tool
emits is a property of the test suite; `jsonschema` is a dev dependency and the
package still installs with `cryptography` alone.
