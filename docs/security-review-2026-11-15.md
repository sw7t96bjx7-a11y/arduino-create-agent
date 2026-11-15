# Build and security validation — 2026-11-15

This review applies to the changes based on commit
`5f84f30fb63c4b35674a0d86fb868bc1914d3589` in this fork. It records local
validation of the candidate source. GitHub Actions results are recorded
separately on the pull request. A successful scan does not establish that all
possible vulnerabilities have been found.

## Changes

| Area | Problem addressed | Resulting behavior |
|---|---|---|
| Upload cancellation | An unsynchronized command map exposed commands before their processes existed. | Start/register and removal are synchronized; cancellation snapshots only started processes. |
| Local HTTP requests | CORS alone could accept a matching hostile Host/Origin pair. | Default loopback listeners reject unrelated Host authorities before CORS and routes run. |
| Proxy setup | HTTPS used the HTTP setting, setup followed the first index request, and logs included proxy URLs. | Independent HTTP/HTTPS settings are applied before downloads; logs omit URLs and credentials. |
| Hardware tests | A short test run could reach an upload fixture. | Short Go tests always skip it; hardware tests otherwise require explicit opt-in. |
| DNS audit | Aliases and errors could be counted as TXT records, and failures could appear as zero. | Structured answer parsing counts TXT resource records; failures retain a report and fail the job. |
| Cloudflare audit | The workflow did not reference its intended secret environment. | A separate optional job references `cloudflare-audit` and rejects refs other than `main`. Environment settings still require account configuration. |
| Dependencies | The original dependency versions produced known-vulnerability findings. | Patched versions and necessary transitive updates are used with a supported compiler. |
| Automation | Mutable action references, broad token defaults, and obsolete runners weakened reproducibility. | Actions are pinned, validation permissions are read-only, checkout credentials are not persisted, and obsolete runner labels are replaced. |

## Go validation

Validation used **Go 1.27.4** on Linux/amd64 with the `cli` build tag.
The module now requires **Go 1.26.0 or later** because of the updated
dependencies. The CLI target excludes the operating-system tray interface;
native desktop builds are a separate CI matrix.

The full race-enabled short test suite passed **105 tests/subtests**, including
**26 top-level tests**, with one intentional hardware upload test skip.
Compilation, full-package `go vet`, formatting, the existing `golint` gate,
and the existing `go fix` gate also passed.

After adding explicit temporary data/config directory overrides, focused
race-enabled config checks passed another **8 top-level tests / 14 including
subtests**. Full-package vet and a fresh CLI compilation also passed on that
final source. The earlier full-suite count and this focused count describe
their respective verification runs, rather than one combined suite run.

```sh
go build -tags cli -trimpath -o arduino-cloud-agent_cli .
go test -race -short -tags cli -mod=readonly -timeout 5m ./...
go vet -tags cli -mod=readonly ./...
govulncheck -tags cli ./...
```

The final full vulnerability scan covered **19 root packages** and reported
**no vulnerabilities found**. It used **govulncheck 1.9.0** and the database
snapshot reported as **2026-11-11T02:51:11Z**.

For a comparable dependency check, the same 13 Taskfile-supported packages
were scanned before and after the manifest updates using that same toolchain,
build tag, scanner, and database snapshot:

| Distinct advisory classification | Original manifests | Updated manifests |
|---|---:|---:|
| Called symbols | 14 | 0 |
| Imported packages only | 11 | 0 |
| Required modules only | 28 | 0 |
| Total | 53 | 0 |

These categories are mutually exclusive at each advisory's highest observed
reachability. The baseline used the original dependency manifests with the
candidate source hardening already present, rather than a pristine checkout.
The counts describe scanner results, not observed exploitation.

## License and workflow checks

Licensed 5.1.0 validated **143 of 143 dependency records** with no errors.
Enumeration used the default desktop dependency graph, including its GUI
dependencies. A second cache-generation run changed no files or bytes.
Nine explicit package review entries and four changed-text acknowledgments
were supported by license-text comparisons; the license allowlist was not
broadened. The exact root license check also passed with licensee 9.20.0,
matching `LICENSE.txt` and `AGPL-3.0` at confidence 100.

Actionlint 1.7.12 validated the workflow schemas and GitHub expressions.
All 86 external action references are full commit SHAs, and all 24 checkout
steps disable credential persistence. Release and signing workflows received
static review; they were not executed.

## Python integration validation

Python 3.12.14 / pytest 7.4.4 completed **4 passing tests and 10 intentional
hardware skips** in 15.47 seconds. Passing tests checked the agent version,
installed tools, actual WebSocket transport, and port-list messages. Hardware
opt-in was explicitly disabled. The loopback listener was closed after the
suite, and no copied test process remained running.

The final CLI used for this run included both directory overrides and reported
the development version `0.0.0-dev`. Its local build SHA-256 was:

```text
1998f4a7db847e4821bee4e7f94540ba453f8400604340bc1dd2e3446ced0708
```

Poetry's lock-consistency check and `pip check` passed. This execution was on
Linux; existing macOS test skips remain, and cross-platform native builds have
separate GitHub Actions jobs.

## DNS helper

All **20 offline regression tests** passed. Tests cover input validation,
CNAME/TXT distinctions, multiple TXT strings, negative DNS answers versus
lookup failures, retained error reports, Cloudflare response limits and
redirect rejection, pagination counts, and credential/output redaction.

```sh
python3 -m unittest discover -s scripts -p 'test_dns_audit.py' -v
```

No Cloudflare credential was needed for these tests. They do not verify live
zone access, token privileges, registrar delegation, or environment settings.

## Sketch compilation

The existing `tests/testdata/SerialEcho` fixture compiled using
**Arduino CLI 1.6.0**, **Arduino AVR core 1.8.8**, and target
**`arduino:avr:leonardo`**:

| Resource | Used | Target capacity |
|---|---:|---:|
| Flash | 3,506 bytes | 28,672 bytes |
| RAM | 149 bytes | 2,560 bytes |

This board target comes from the repository's upload fixture. It does not
identify a connected or user-owned board. No board was flashed, and physical
serial communication, wiring, radio behavior, or electrical safety was not
tested.

## Remaining boundaries

The loopback Host check is not authentication for explicitly network-bound
listeners. Production installer signing, notarization, releases, and actual
device operations require their own environments and validation. No release
or system-wide agent installation is part of this check.

GitHub environment branch restrictions, secrets, branch protection,
repository visibility, and account MFA are settings outside these source
changes. See [DNS audit setup](dns-audit.md) for the exact optional Cloudflare
prerequisites and [build instructions](security-validation.md) for repeatable
validation and hardware-test safeguards.

The legacy Python integration client retains published server-side advisory
version ranges for protocol compatibility. Its client-only use, lack of Python
server/message-queue deployment, and required coordinated protocol migration
are documented in the build instructions. The zero-finding Go scan above does
not include these Python packages.
