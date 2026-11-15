# Public DNS and Cloudflare audit

The **Cloudflare DNS Audit (read-only)** workflow collects public DNS snapshots and can optionally check whether a narrowly scoped Cloudflare token can see a zone and its DNS record count. It does not change DNS, restore deleted zones, or establish whether registrar delegation is correct.

## Run the public audit

1. Open **Actions → Cloudflare DNS Audit (read-only) → Run workflow**.
2. Select the reviewed `main` branch.
3. Enter one to eight comma-separated DNS names. The default `example.com` is a placeholder.
4. Leave **check_cloudflare** disabled unless the environment described below has been configured.

Inputs are passed through environment variables, validated again by the Python helper, and supplied to `dig` as an argument list. Hostnames are normalized to lowercase and deduplicated; a single trailing dot is accepted. URLs, IP addresses, wildcard names, path fragments, shell syntax, malformed labels, and common nonpublic suffixes are rejected. Internationalized names must use their ASCII IDNA A-label representation. Syntactic validation does not prove that a domain is registered or public.

The public job has no Cloudflare credentials and does not depend on the optional Cloudflare job. It queries the runner's configured resolver for NS, A, AAAA, CNAME, MX, and CAA records, plus `www` CNAME and root/`_dmarc` TXT information. Responses represent that resolver's view at the reported time and may be cached; this is not an authoritative delegation trace.

## Read the report

Download the **public-dns-audit** artifact. Reports use indexed names such as `domain-01.txt`; each file identifies its domain and UTC collection time. Artifact retention is three days. The job summary lists how many queries completed with each status.

| Result | Meaning | TXT/policy count |
|---|---|---|
| `NOERROR` with no matching records | The resolver answered successfully without that record type. | `0` |
| `NOERROR` with matching records | The resolver returned the requested record type. | Number of matching records |
| `NXDOMAIN` | The queried name does not exist in the resolver's response. | `n/a` |
| `SERVFAIL`, `REFUSED`, `TIMEOUT`, or another error | The lookup could not establish a usable answer. | `n/a`; the public job fails after report upload |

`NXDOMAIN` is a completed negative response, not a transport failure. It is shown explicitly; an optional absent name such as `www` or `_dmarc` does not by itself fail the workflow. A successful workflow means the lookups completed, not that a website or email configuration is healthy.

TXT counts include only TXT resource records. CNAME aliases do not increase them, and multiple quoted character-strings within one TXT record count as one record. SPF and DMARC counts identify their respective `v=spf1` and `v=DMARC1` version prefixes after joining TXT character-strings. These counts are not a complete validation of policy syntax, policy effectiveness, SPF DNS lookup limits, DKIM configuration, or email delivery.

TXT contents are excluded from artifacts and summaries. Public non-TXT DNS answers remain in the reports. Resolver failures do not become an apparently successful zero count: useful reports are uploaded first, then the workflow is marked failed.

## Configure the optional Cloudflare job

**Prerequisites are not established by this code change.** Confirm the following in the connected accounts before enabling the optional check:

1. In GitHub repository settings, create an Actions environment named exactly **`cloudflare-audit`**.
2. Restrict that environment's deployment branches to **Selected branches and tags → branch `main`**. Do not add a wildcard branch or tag rule. Review the `main` branch and protect it from unreviewed workflow changes. If required reviewers are supported and configured, the Cloudflare job waits for their approval; the independent public DNS job can still complete.
3. In Cloudflare, create a custom API token with only **Zone → Zone → Read** and **Zone → DNS → Read**, scoped to **Include → Specific zone → the intended zone**. If auditing several owned zones, explicitly include only those intended zones. Do not use a global API key or a token with write permissions.
4. Save that token as the **environment secret `CF_API_TOKEN` inside `cloudflare-audit`**. Avoid a repository-wide or organization-wide secret with this name, which would make the intended environment scoping less clear. Enter the token directly into GitHub's secret form; do not place it in workflow inputs, files, issue text, or command history.
5. Run the reviewed `main` workflow with the exact Cloudflare zone names and enable **check_cloudflare**.

The workflow references the environment but does not create its branch restrictions, reviewers, or secrets. An automatically created empty environment is not proof that these protections are configured. These repository settings and the token configuration have not been verified by this change. Environment protection availability can depend on the repository and GitHub plan; verify it in settings. The code can restrict requests to GET, but cannot prove the supplied token has no extra privileges. Verify the token's scope in Cloudflare.

The Cloudflare job also checks that the workflow ref is exactly `refs/heads/main` before checking out code or placing the token in a step environment. An opt-in run on another branch fails with an explicit message; public DNS runs remain available. This guard makes the intended behavior visible, but a workflow edit could remove it. GitHub's environment branch restriction and review controls are therefore still required to protect the secret from other branches and unreviewed changes.

The optional job reports only whether an exact zone name is visible to the token and the total DNS record count. A hostname such as `www.example.com` is not automatically converted to the `example.com` zone. **No exact zone visible** can mean the zone is absent, outside token scope, or the input is not the zone name; it does not prove deletion. Visibility does not prove that the zone is active or that the registrar delegates to it.

The helper accepts only fixed HTTPS Cloudflare zone endpoints, makes GET requests, refuses HTTP redirects, bounds each JSON response to 1 MiB, validates identifiers and counts, and rejects ambiguous zone matches. It uses the API's total count, not the number of records in the returned page. Tokens, zone IDs, raw API responses, and DNS record values from the API are not printed or uploaded. Cloudflare results appear only as counts and fixed diagnostic messages in the job summary.

## Local validation

Python 3.8 or newer is sufficient for the helper and offline tests. Public lookups also need BIND `dig` (Ubuntu package `dnsutils`).

```sh
python3 -m unittest discover -s scripts -p 'test_dns_audit.py' -v
DOMAINS_INPUT='example.com' python3 scripts/dns_audit.py validate
DOMAINS_INPUT='example.com' python3 scripts/dns_audit.py public
```

The tests use synthetic DNS responses and mocked Cloudflare transport. They cover injection rejection, CNAME/TXT counting, multi-string TXT records, DNS status distinctions, error report retention, total-count pagination, response limits, redirect refusal, and output redaction. They require no credentials and do not perform network requests. Run the GitHub workflow separately to validate the actual runner, resolver, artifact upload, environment protections, and token access.

## References

- [GitHub Actions environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
- [GitHub Actions job environments](https://docs.github.com/en/actions/reference/workflow-syntax-for-github-actions#jobsjob_idenvironment)
- [Cloudflare API token permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/)
- [Cloudflare list zones API](https://developers.cloudflare.com/api/resources/zones/methods/list/)
- [Cloudflare DNS records API](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)
- [BIND `dig` manual](https://bind9.readthedocs.io/en/stable/manpages.html#dig-dns-lookup-utility)
