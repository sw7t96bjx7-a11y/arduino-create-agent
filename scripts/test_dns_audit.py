# Copyright 2026 Arduino Cloud Agent contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regression tests; no network, credentials, dig installation, or third-party packages."""

import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

import dns_audit as audit


def dig_output(status="NOERROR", answers=()):
    return f";; ->>HEADER<<- opcode: QUERY, status: {status}, id: 123\n;; flags: qr rd ra; QUERY: 1\n\n" + "\n".join(answers) + "\n"


class DomainTests(unittest.TestCase):
    def test_normalizes_deduplicates_and_accepts_idna_alabels(self):
        self.assertEqual(audit.validate_domains(" Example.COM.,example.com, xn--bcher-kva.example.com "), ["example.com", "xn--bcher-kva.example.com"])

    def test_rejects_injection_paths_invalid_labels_and_nonpublic_names(self):
        values = ["", "example.com,", "../example.com", "example.com/../../file", "$(id).com", "example.com;id", "`id`.com", "example.com\n::error::bad", "https://example.com", "-bad.example", "bad-.example", "bad..example", "example.com..", "*.example.com", "127.0.0.1", "host.local", "host.localhost", "host.home.arpa", "host.internal", "münich.example.com", "a" * 64 + ".com"]
        for value in values:
            with self.subTest(value=value), self.assertRaises(audit.AuditError):
                audit.validate_domains(value)

    def test_bounds(self):
        eight = [f"host{i}.example.com" for i in range(8)]
        self.assertEqual(audit.validate_domains(",".join(eight)), eight)
        for value in (",".join(eight + ["ninth.example.com"]), "a" * 4097):
            with self.assertRaises(audit.AuditError):
                audit.validate_domains(value)
        maximum = ".".join(["a" * 63] * 3 + ["b" * 61])
        self.assertEqual(len(maximum), 253)
        self.assertEqual(audit.validate_domains(maximum), [maximum])


class DNSTests(unittest.TestCase):
    def test_alias_does_not_count_as_txt_or_as_a_policy(self):
        alias = "_dmarc.example.com. 60 IN CNAME policy.example.net."
        txt = 'policy.example.net. 60 IN TXT "v=DMARC1; p=reject"'
        with_txt = audit.parse_dig("_dmarc.example.com", "TXT", dig_output(answers=[alias, txt]))
        self.assertEqual(audit.txt_counts(with_txt), {"TXT": 1, "SPF": 0, "DMARC": 1})
        alias_only = audit.parse_dig("_dmarc.example.com", "TXT", dig_output(answers=[alias]))
        self.assertEqual(audit.txt_counts(alias_only), {"TXT": 0, "SPF": 0, "DMARC": 0})

    def test_multichunk_and_escaped_txt_policies_are_single_records(self):
        answers = [
            'example.com. 60 IN TXT "v=sp" "f1 -all"',
            'example.com. 60 IN TXT "v=DMA" "RC1; p=none"',
            r'example.com. 60 IN TXT "\118=spf1 -all"',
            'example.com. 60 IN TXT "v=spf10 fake"',
            'example.com. 60 IN TXT "v=DMARC10; p=none"',
            'example.com. 60 IN TXT "private-verification-value"',
        ]
        result = audit.parse_dig("example.com", "TXT", dig_output(answers=answers))
        self.assertEqual(audit.txt_counts(result), {"TXT": 6, "SPF": 2, "DMARC": 1})
        output = audit.render_dns(result)
        self.assertNotIn("private-verification-value", output)
        self.assertNotIn("p=none", output)
        self.assertEqual(audit.decode_txt(r'"quoted\"value" " and \\ slash"'), 'quoted"value and \\ slash')

    def test_empty_success_and_negative_response_are_distinct(self):
        empty = audit.parse_dig("example.com", "TXT", dig_output())
        self.assertEqual(audit.txt_counts(empty)["TXT"], 0)
        for status in ("NXDOMAIN", "SERVFAIL", "REFUSED"):
            result = audit.parse_dig("example.com", "TXT", dig_output(status))
            self.assertEqual(result.status, status)
            self.assertIsNone(audit.txt_counts(result)["TXT"])
            self.assertEqual(result.failed, status != "NXDOMAIN")

    def test_error_text_is_not_a_record_count(self):
        failure = audit.parse_dig("example.com", "TXT", ";; communications error: timed out\n;; no servers could be reached\n", 9)
        self.assertEqual(failure.status, "TIMEOUT")
        self.assertIsNone(audit.txt_counts(failure)["TXT"])
        self.assertTrue(failure.failed)
        self.assertEqual(audit.parse_dig("example.com", "TXT", '"v=spf1 -all"\n').status, "PARSE_ERROR")

    def test_malformed_txt_fails_closed(self):
        for value in ('"unclosed', 'unquoted', r'"\999"'):
            result = audit.parse_dig("example.com", "TXT", dig_output(answers=["example.com. 60 IN TXT " + value]))
            self.assertEqual(result.status, "PARSE_ERROR")

    def test_query_uses_argument_array_absolute_name_and_bounded_timeout(self):
        completed = subprocess.CompletedProcess([], 0, dig_output(), "")
        with patch.object(audit.subprocess, "run", return_value=completed) as run:
            result = audit.query_dns("example.com", "TXT")
        self.assertEqual(result.status, "NOERROR")
        self.assertEqual(run.call_args.args[0][-2:], ["example.com.", "TXT"])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs["timeout"], 15)

    def test_timeout_and_missing_tool_are_safe_results(self):
        for error, status in ((subprocess.TimeoutExpired("dig", 15), "TIMEOUT"), (FileNotFoundError(), "TOOL_ERROR")):
            with patch.object(audit.subprocess, "run", side_effect=error):
                self.assertEqual(audit.query_dns("example.com", "TXT").status, status)

    def test_failed_queries_still_write_redacted_artifact_and_summary(self):
        def query(name, rtype):
            if rtype == "NS":
                return audit.DNSResult(name, rtype, "SERVFAIL")
            records = [audit.Record(name, "TXT", '"private-verification-value"')] if rtype == "TXT" else []
            return audit.DNSResult(name, rtype, "NOERROR", records)

        with tempfile.TemporaryDirectory() as directory, patch.object(audit, "query_dns", side_effect=query), patch.object(audit, "write_summary") as summary, contextlib.redirect_stdout(io.StringIO()):
            exit_status = audit.audit_public(["example.com"], Path(directory))
            report = (Path(directory) / "domain-01.txt").read_text()
        self.assertEqual(exit_status, 1)
        self.assertIn("Status: SERVFAIL", report)
        self.assertIn("NS record count: n/a", report)
        self.assertNotIn("private-verification-value", report)
        self.assertIn("| example.com | 8 | 0 | 1 |", summary.call_args.args[0])


class Response(io.BytesIO):
    status = 200


class Opener:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        result = next(self.responses)
        if isinstance(result, Exception):
            raise result
        return Response(result if isinstance(result, bytes) else json.dumps(result).encode())


def api_result(results, count):
    return {"success": True, "result": results, "result_info": {"total_count": count}}


class CloudflareTests(unittest.TestCase):
    zone = {"id": "a" * 32, "name": "example.com"}

    def test_only_get_and_total_count_instead_of_page_length(self):
        opener = Opener([api_result([self.zone], 1), api_result([{"content": "private-api-data"}] * 5, 37)])
        client = audit.CloudflareClient("test-token", opener)
        self.assertEqual(client.zone_record_count("example.com"), 37)
        self.assertTrue(all(request.get_method() == "GET" for request in opener.requests))
        self.assertTrue(all(request.full_url.startswith("https://api.cloudflare.com/client/v4/") for request in opener.requests))
        self.assertTrue(all(request.get_header("Authorization") == "Bearer test-token" for request in opener.requests))

    def test_no_visible_zone_is_not_zero_records(self):
        self.assertIsNone(audit.CloudflareClient("test-token", Opener([api_result([], 0)])).zone_record_count("example.com"))
        self.assertEqual(audit.CloudflareClient("test-token", Opener([api_result([self.zone], 1), api_result([], 0)])).zone_record_count("example.com"), 0)

    def test_ambiguous_incomplete_and_invalid_zone_responses_fail(self):
        incomplete = api_result([self.zone], 2)
        incomplete["result_info"]["total_pages"] = 2
        cases = [api_result([self.zone, self.zone], 2), incomplete, api_result([dict(self.zone, id="../../secrets")], 1), api_result([dict(self.zone, name="unexpected.example.com")], 1), api_result("not a list", 1)]
        for response in cases:
            with self.subTest(response=response), self.assertRaises(audit.AuditError):
                audit.CloudflareClient("test-token", Opener([response])).zone_record_count("example.com")

    def test_filtered_zone_lookup_does_not_require_unfiltered_count_to_match(self):
        opener = Opener([api_result([self.zone], 100), api_result([], 0)])
        self.assertEqual(audit.CloudflareClient("test-token", opener).zone_record_count("example.com"), 0)

    def test_counts_must_be_nonnegative_integers_with_consistent_results(self):
        for count in (None, True, "12", -1):
            with self.subTest(count=count), self.assertRaises(audit.AuditError):
                audit.CloudflareClient("test-token", Opener([api_result([self.zone], 1), api_result([], count)])).zone_record_count("example.com")

    def test_bounded_response_and_safe_error_messages(self):
        cases = [b"x" * (audit.MAX_API_BYTES + 1), b"[" * 2000 + b"]" * 2000, b"private-api-data", {"success": False, "errors": ["private-api-data"]}, ["private-api-data"], HTTPError("https://api.cloudflare.com/", 403, "private-api-data", {}, None), URLError("private-api-data")]
        for response in cases:
            with self.subTest(kind=type(response).__name__), self.assertRaises(audit.AuditError) as caught:
                audit.CloudflareClient("test-token", Opener([response])).get("/zones", {"name": "example.com"})
            self.assertNotIn("private-api-data", str(caught.exception))
            self.assertNotIn("test-token", str(caught.exception))

    def test_redirects_are_refused_before_credentials_can_be_forwarded(self):
        request = Request("https://api.cloudflare.com/client/v4/zones", headers={"Authorization": "Bearer test-token"})
        self.assertIsNone(audit.NoRedirect().redirect_request(request, None, 302, "Found", {}, "https://other.example/"))
        self.assertTrue(any(isinstance(handler, audit.NoRedirect) for handler in audit.CloudflareClient("test-token").opener.handlers))
        with self.assertRaisesRegex(audit.AuditError, "redirect refused"):
            audit.CloudflareClient("test-token", Opener([HTTPError(request.full_url, 302, "Found", {}, None)])).get("/zones", {})

    def test_endpoint_and_token_validation(self):
        for token in ("", "token\nheader", "token value", "token\x00", "tokené", "t" * 4097):
            with self.assertRaises(audit.AuditError):
                audit.CloudflareClient(token)
        with self.assertRaises(audit.AuditError):
            audit.CloudflareClient("test-token", Opener([])).get("//other.example/", {})

    def test_summary_excludes_raw_api_values(self):
        responses = [api_result([self.zone], 1), api_result([{"content": "private-api-data"}], 1)]
        with patch.object(audit, "build_opener", return_value=Opener(responses)), patch.dict(audit.os.environ, {"CF_API_TOKEN": "test-token"}), patch.object(audit, "write_summary") as summary, contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(audit.audit_cloudflare(["example.com"]), 0)
        combined = summary.call_args.args[0] + output.getvalue()
        self.assertNotIn("private-api-data", combined)
        self.assertNotIn("test-token", combined)
        self.assertNotIn(self.zone["id"], combined)
        self.assertIn("| example.com | Yes | 1 |", combined)


if __name__ == "__main__":
    unittest.main()
