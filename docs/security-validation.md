# Building and validating this fork

The repository contains the desktop Arduino Cloud Agent. Its bundled
`tests/testdata/SerialEcho` sketch is a serial-test fixture. Building either
component does not install it, flash a board, or change account settings.

## Local build and checks

Use Go 1.27.4 or a later compatible, supported security release. The CLI build
avoids the operating-system tray dependencies used by the desktop build.

```bash
go mod verify
go build -tags cli -trimpath -o arduino-cloud-agent_cli .
go test -tags cli -short -race -timeout 10m ./...
go vet -tags cli ./...
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
govulncheck -tags cli ./...
python3 -m unittest discover -s scripts -p 'test_dns_audit.py' -v
```

Some existing Go tests download signed Arduino package indexes and uploader
archives. They require network access. The DNS helper's regression tests use
simulated responses and require no Cloudflare token or public DNS access.

The `Security Validation` workflow runs on pull requests and pushes to `main`.
It checks DNS regressions, workflow syntax, Go module integrity, race tests,
the CLI build, and reachable vulnerable functions. Its Linux CLI artifact
includes a SHA-256 checksum and expires after three days. The scanner uses text
mode so a finding fails the job; JSON output alone is not used as a success gate.

## Python integration tests and isolation

The integration workflow uses Python 3.12 and a CLI build with a development
version such as `0.0.0-dev`. Run `task go:build-cli` followed by
`task go:test-integration`, or select an existing compatible binary with the
`ARDUINO_AGENT_TEST_BINARY` environment variable before invoking `poetry run
pytest tests`. Install the locked test dependencies with `poetry install
--no-root`. The standard-library process fixture replaces Invoke and psutil;
the obsolete third-party asyncio backport is also removed.

Each test starts its own copied executable with a temporary config file,
`ARDUINO_CREATE_AGENT_DATA_DIR`, and `ARDUINO_CREATE_AGENT_CONFIG_DIR`. Both
directory overrides require nonempty absolute paths when supplied and preserve
the normal locations when absent. The fixture disables autostart, certificate
installation, crash reporting, and the update URL. Its startup update copy also
stays inside the temporary test directory. It does not repurpose `HOME`.
Startup waits for the loopback `/info` endpoint with a deadline; teardown
terminates and waits for the process it started. An existing listener on port
8991 makes the test fail rather than attach to another agent.

Safe tests check version information, installed-tool listing, and actual
WebSocket connection and port-list messages at `127.0.0.1`. Hardware tests
remain opt-in. Existing macOS integration skip conditions remain; a Linux run
does not establish macOS or Windows runtime behavior.

The Python client remains on Socket.IO 4.6.1 / Engine.IO 3.14.2 to match the
legacy Go server's wire protocol. This retains versions within the ranges of
published advisories
[GHSA-5w7q-77mv-v69f](https://github.com/advisories/GHSA-5w7q-77mv-v69f),
[GHSA-g8c6-8fjj-2r4m](https://github.com/advisories/GHSA-g8c6-8fjj-2r4m),
[GHSA-cgwc-pv48-fhj5](https://github.com/advisories/GHSA-cgwc-pv48-fhj5), and
[GHSA-m9gh-vj53-gvh9](https://github.com/advisories/GHSA-m9gh-vj53-gvh9).
These test files use the Python `Client` against their own loopback Go process;
they do not instantiate Python servers, message-queue managers, or the affected
server/queue paths. They are test dependencies, not components of the shipped
Go binary. A complete dependency migration requires upgrading the Go server and
Python client together and checking protocol compatibility. Go vulnerability
scan results must not be presented as a clean bill of health for all Python
test dependencies; no advisory is suppressed here.

## Hardware tests and sketch compilation

Ordinary short tests always skip the upload test. Other hardware-dependent
tests require an explicit `ARDUINO_AGENT_HARDWARE_TESTS=1` environment variable.
Use that option only on a bench setup whose board, serial port, and uploader
configuration match the test. The legacy upload fixture targets a Leonardo and
contains a fixed serial-port configuration; inspect it before opting in.

To compile the bundled fixture without uploading it:

```bash
arduino-cli core update-index
arduino-cli core install arduino:avr@1.8.8
arduino-cli compile --fqbn arduino:avr:leonardo tests/testdata/SerialEcho
```

This is a fixture compatibility check. A different physical board needs its own
verified board identifier, core, wiring, and firmware configuration.

## Security boundaries

- The default listener binds to `127.0.0.1`. Loopback bindings now reject HTTP
  Host values that are not `localhost` or a numeric loopback address, before
  CORS and route handlers run. This closes the matching Host/Origin condition
  that can undermine an origin allowlist during DNS rebinding.
- Explicit nonloopback or wildcard bind settings retain their previous
  behavior. They require access controls appropriate to the actual network;
  the loopback Host check is not authentication for a network-facing service.
- HTTP and HTTPS proxy settings are applied independently before initial
  downloads. Blank settings preserve inherited proxy variables, and logs omit
  proxy URLs and credentials.
- Upload-stop operations synchronize the process registry and operate only on
  successfully started upload processes. Existing signature checks remain part
  of the upload and package-download paths.
- Workflow actions use immutable commit references. Dependabot is already
  configured to propose action and Go dependency updates. Review updates and
  keep the explicit Go and scanner versions current.
- Validation workflows use a read-only GitHub token and do not persist checkout
  credentials. Jobs that actually publish releases or sync labels retain only
  their required additional permissions.

See [DNS audit setup](dns-audit.md) for the optional Cloudflare environment and
the distinction between empty DNS answers and failed lookups. Protected
environment settings, token scopes, branch rules, repository visibility, and
personal-account MFA are separate GitHub or Cloudflare settings; source-code
changes alone do not verify or configure them.

## References

- [GitHub Actions security guidance](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub environment protection](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [Go vulnerability scanning](https://go.dev/doc/tutorial/govulncheck)
- [Go release history](https://go.dev/doc/devel/release)
