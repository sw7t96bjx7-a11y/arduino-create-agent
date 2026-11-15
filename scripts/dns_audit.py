#!/usr/bin/env python3
# Copyright 2026 Arduino Cloud Agent contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Read-only public DNS and optional Cloudflare audit; Python standard library only."""

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener


MAX_API_BYTES = 1024 * 1024
COMPLETED_DNS_STATUSES = {"NOERROR", "NXDOMAIN"}
PUBLIC_RECORD_TYPES = {"NS", "A", "AAAA", "CNAME", "DNAME", "MX", "CAA"}


class AuditError(Exception):
    """An error with a fixed, safe-to-display message (never an API response)."""


def validate_domains(raw):
    if not isinstance(raw, str) or len(raw) > 4096:
        raise AuditError("Supply between 1 and 8 comma-separated public DNS names.")
    domains = []
    for piece in raw.split(","):
        name = piece.strip().lower()
        if name.endswith("."):
            name = name[:-1]
        labels = name.split(".")
        if (
            not name
            or len(name) > 253
            or len(labels) < 2
            or name.endswith((".local", ".internal", ".test", ".invalid", ".localhost", ".onion", ".home.arpa"))
            or any(not re.fullmatch(r"(?!-)[a-z0-9-]{1,63}(?<!-)", label) for label in labels)
            or labels[-1].isdigit()
        ):
            raise AuditError("Invalid public DNS name; use ASCII names or IDNA A-labels, without URLs or shell syntax.")
        if name not in domains:
            domains.append(name)
    if not 1 <= len(domains) <= 8:
        raise AuditError("Supply between 1 and 8 distinct public DNS names.")
    return domains


@dataclass
class Record:
    owner: str
    rtype: str
    value: str


@dataclass
class DNSResult:
    name: str
    rtype: str
    status: str
    records: list = field(default_factory=list)

    @property
    def failed(self):
        return self.status not in COMPLETED_DNS_STATUSES


def decode_txt(value):
    """Join DNS character-strings, including escaped characters and decimal octets."""
    chunks = []
    position = 0
    while position < len(value):
        if value[position].isspace():
            position += 1
            continue
        if value[position] != '"':
            raise AuditError("Malformed DNS TXT presentation.")
        position += 1
        chunk = []
        while position < len(value) and value[position] != '"':
            char = value[position]
            position += 1
            if char == "\\":
                if position == len(value):
                    raise AuditError("Malformed DNS TXT presentation.")
                escaped = value[position:position + 3]
                if len(escaped) == 3 and escaped.isascii() and escaped.isdigit():
                    number = int(escaped)
                    if number > 255:
                        raise AuditError("Malformed DNS TXT presentation.")
                    char = chr(number)
                    position += 3
                else:
                    char = value[position]
                    position += 1
            chunk.append(char)
        if position == len(value):
            raise AuditError("Malformed DNS TXT presentation.")
        position += 1
        chunks.append("".join(chunk))
    if not chunks:
        raise AuditError("Malformed DNS TXT presentation.")
    return "".join(chunks)


def parse_dig(name, rtype, stdout, returncode=0):
    if returncode:
        return DNSResult(name, rtype, "TIMEOUT" if returncode == 9 else "QUERY_FAILED")
    headers = re.findall(r"^;; ->>HEADER<<- .*status: ([A-Z][A-Z0-9]*),", stdout, re.MULTILINE)
    if len(headers) != 1:
        return DNSResult(name, rtype, "PARSE_ERROR")
    records = []
    for line in stdout.splitlines():
        if not line.strip() or line.startswith(";"):
            continue
        fields = line.split(None, 4)
        if len(fields) != 5 or not fields[1].isdigit() or fields[2] != "IN":
            return DNSResult(name, rtype, "PARSE_ERROR")
        record = Record(fields[0], fields[3], fields[4])
        if record.rtype == "TXT":
            try:
                decode_txt(record.value)
            except AuditError:
                return DNSResult(name, rtype, "PARSE_ERROR")
        records.append(record)
    return DNSResult(name, rtype, headers[0], records)


def query_dns(name, rtype):
    if len(name) > 253:
        return DNSResult(name, rtype, "INVALID_NAME")
    try:
        result = subprocess.run(
            ["dig", "-r", "+noall", "+comments", "+answer", "+nomultiline", "+time=5", "+tries=2", name + ".", rtype],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except subprocess.TimeoutExpired:
        return DNSResult(name, rtype, "TIMEOUT")
    except (OSError, UnicodeError):
        return DNSResult(name, rtype, "TOOL_ERROR")
    return parse_dig(name, rtype, result.stdout, result.returncode)


def txt_counts(result):
    if result.status != "NOERROR":
        return {"TXT": None, "SPF": None, "DMARC": None}
    texts = [decode_txt(record.value) for record in result.records if record.rtype == "TXT"]
    return {
        "TXT": len(texts),
        "SPF": sum(bool(re.match(r"^v=spf1(?:[ \t]|$)", text, re.IGNORECASE)) for text in texts),
        "DMARC": sum(bool(re.match(r"^v=DMARC1(?:[ \t]*;|$)", text, re.IGNORECASE)) for text in texts),
    }


def render_dns(result):
    lines = [f"## {result.name} {result.rtype}", f"Status: {result.status}"]
    if result.rtype == "TXT":
        counts = txt_counts(result)
        for label in ("TXT", "SPF", "DMARC"):
            count = counts[label]
            lines.append(f"{label} {'policy' if label != 'TXT' else 'record'} count: {count if count is not None else 'n/a'}")
        lines.append("TXT contents excluded. Policy counts identify version prefixes; they do not validate policies.")
    else:
        count = sum(record.rtype == result.rtype for record in result.records) if result.status == "NOERROR" else None
        lines.append(f"{result.rtype} record count: {count if count is not None else 'n/a'}")
        for record in result.records:
            if record.rtype in PUBLIC_RECORD_TYPES:
                lines.append(f"{record.owner}\tIN\t{record.rtype}\t{record.value}")
    return "\n".join(lines)


def write_summary(text):
    destination = os.environ.get("GITHUB_STEP_SUMMARY")
    if destination:
        with Path(destination).open("a", encoding="utf-8") as output:
            output.write(text + "\n")
    else:
        print(text)


def audit_public(domains, output_dir=Path("reports/public")):
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = ["### Public DNS audit", "", "| Domain | NOERROR | NXDOMAIN | Failed queries |", "|---|---:|---:|---:|"]
    failures = 0
    timestamp = datetime.now(timezone.utc).isoformat()
    for index, domain in enumerate(domains, 1):
        requests = [(domain, rtype) for rtype in ("NS", "A", "AAAA", "CNAME", "MX", "CAA")]
        requests += [("www." + domain, "CNAME"), ("_dmarc." + domain, "TXT"), (domain, "TXT")]
        results = [query_dns(name, rtype) for name, rtype in requests]
        domain_failures = sum(result.failed for result in results)
        failures += domain_failures
        # Indexed names also support valid 253-character DNS names within filesystem limits.
        report = f"# Public DNS snapshot: {domain}\nGenerated at: {timestamp}\n\n"
        report += "\n\n".join(render_dns(result) for result in results) + "\n"
        (output_dir / f"domain-{index:02}.txt").write_text(report, encoding="utf-8")
        rows.append(f"| {domain} | {sum(r.status == 'NOERROR' for r in results)} | {sum(r.status == 'NXDOMAIN' for r in results)} | {domain_failures} |")
    rows += ["", "NXDOMAIN is an explicit negative DNS answer; it is not a zero-record NOERROR response.", "TXT values are excluded. Per-query status is recorded in the public-dns-audit artifact."]
    write_summary("\n".join(rows))
    print(f"Public DNS audit complete: {len(domains)} domain(s), {failures} failed query(s).")
    return int(failures > 0)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        # urllib raises HTTPError instead; Authorization is never sent to a redirect target.
        return None


class CloudflareClient:
    def __init__(self, token, opener=None):
        if not token or len(token) > 4096 or not all(33 <= ord(character) <= 126 for character in token):
            raise AuditError("CF_API_TOKEN is missing or invalid; configure the cloudflare-audit environment.")
        self.token = token
        self.opener = opener if opener is not None else build_opener(NoRedirect())

    def get(self, endpoint, parameters):
        if not re.fullmatch(r"/zones(?:/[a-f0-9]{32}/dns_records)?", endpoint):
            raise AuditError("Invalid Cloudflare API endpoint.")
        url = "https://api.cloudflare.com/client/v4" + endpoint + "?" + urlencode(parameters)
        request = Request(url, headers={"Authorization": "Bearer " + self.token, "Accept": "application/json"}, method="GET")
        try:
            with self.opener.open(request, timeout=20) as response:
                if response.status != 200:
                    raise AuditError("Unexpected Cloudflare HTTP response.")
                body = response.read(MAX_API_BYTES + 1)
        except HTTPError as error:
            if 300 <= error.code < 400:
                raise AuditError("Cloudflare HTTP redirect refused.") from None
            raise AuditError(f"Cloudflare HTTP {error.code}; verify token permissions and service availability.") from None
        except (URLError, TimeoutError, OSError):
            raise AuditError("Cloudflare request failed; verify connectivity.") from None
        if len(body) > MAX_API_BYTES:
            raise AuditError("Cloudflare response exceeded the size limit.")
        try:
            data = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeError, RecursionError):
            raise AuditError("Cloudflare returned invalid JSON.") from None
        if not isinstance(data, dict) or data.get("success") is not True:
            raise AuditError("Cloudflare API indicated an error; verify read-only token scope.")
        return data

    @staticmethod
    def results(data, maximum_results):
        results = data.get("result")
        if not isinstance(results, list) or len(results) > maximum_results or not all(isinstance(item, dict) for item in results):
            raise AuditError("Cloudflare returned malformed result data.")
        return results

    @classmethod
    def result_info(cls, data, maximum_results):
        results = cls.results(data, maximum_results)
        information = data.get("result_info")
        count = information.get("total_count") if isinstance(information, dict) else None
        if type(count) is not int or count < len(results):
            raise AuditError("Cloudflare returned an invalid record count.")
        return results, count

    def zone_record_count(self, domain):
        data = self.get("/zones", {"name": domain, "per_page": 50})
        zones = self.results(data, 50)
        information = data.get("result_info", {})
        if not isinstance(information, dict):
            raise AuditError("Cloudflare returned malformed pagination data.")
        # total_count may describe the unfiltered zone inventory, not this name filter.
        pages = information.get("total_pages")
        if pages is not None and (type(pages) is not int or pages < 0 or pages > 1):
            raise AuditError("Cloudflare zone response is incomplete; narrow token scope.")
        if len(zones) == 50:
            raise AuditError("Cloudflare zone response reached its limit; narrow token scope.")
        if any(zone.get("name") != domain for zone in zones):
            raise AuditError("Cloudflare returned an unexpected zone name.")
        matches = [zone for zone in zones if zone.get("name") == domain]
        if not matches:
            return None
        if len(matches) != 1:
            raise AuditError("Multiple Cloudflare zones matched; scope the token to one intended zone.")
        zone_id = matches[0].get("id")
        if not isinstance(zone_id, str) or not re.fullmatch(r"[a-f0-9]{32}", zone_id):
            raise AuditError("Cloudflare returned an invalid zone identifier.")
        records = self.get(f"/zones/{zone_id}/dns_records", {"per_page": 5})
        _, count = self.result_info(records, 5)
        return count


def audit_cloudflare(domains):
    client = CloudflareClient(os.environ.get("CF_API_TOKEN", ""))
    rows = ["### Cloudflare read-only API check", "", "| Domain | Zone visible to token | DNS record count |", "|---|---|---:|"]
    failures = 0
    for domain in domains:
        try:
            count = client.zone_record_count(domain)
            rows.append(f"| {domain} | {'No exact zone visible' if count is None else 'Yes'} | {count if count is not None else 'n/a'} |")
        except AuditError as error:
            failures += 1
            rows.append(f"| {domain} | Error: {error} | n/a |")
    rows += ["", "Zone visibility does not prove active DNS delegation. Raw API data and tokens are excluded."]
    write_summary("\n".join(rows))
    print(f"Cloudflare read-only audit complete: {len(domains)} domain(s), {failures} failed check(s).")
    return int(failures > 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("validate", "public", "cloudflare"))
    arguments = parser.parse_args()
    try:
        domains = validate_domains(os.environ.get("DOMAINS_INPUT", ""))
        if arguments.mode == "validate":
            print(f"Validated {len(domains)} domain(s).")
            return 0
        if arguments.mode == "public":
            return audit_public(domains)
        return audit_cloudflare(domains)
    except AuditError as error:
        print(f"Audit failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
