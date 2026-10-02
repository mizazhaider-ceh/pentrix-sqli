#!/usr/bin/env python3
"""pentrix-sqli: error-based SQL injection prober.

For each query parameter of a URL, sends a small set of classic break-out
payloads and compares each response against the baseline (the unmodified
request). Response bodies are matched against a table of DBMS error
signatures to identify the likely database engine.

Only detects error-based injection indicators. It never attempts data
extraction, authentication bypass, or anything destructive.
"""

import argparse
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PAYLOADS = [
    "'",
    '"',
    "\\",
    "' OR '1'='1",
    '" OR "1"="1',
    "') OR ('1'='1",
]

# Maps a DBMS label to the list of substrings that, when found in a response
# body, indicate an error message from that engine. Entries are ordered by how
# specific they are so generic matches lose to specific ones.
DBMS_SIGNATURES = [
    ("MySQL", [
        "You have an error in your SQL syntax",
        "mysql_fetch",
        "MySQL server",
        "Warning: mysql_",
        "mysqli::",
    ]),
    ("PostgreSQL", [
        "pg_query()",
        "unterminated quoted string",
        "PostgreSQL",
        "pg_fetch_",
    ]),
    ("MSSQL", [
        "Unclosed quotation mark",
        "Microsoft SQL Server",
        "ODBC SQL Server",
        "SqlException",
        "ODBC Microsoft Access Driver",
    ]),
    ("Oracle", [
        "ORA-",
        "Oracle error",
        "Oracle() query",
    ]),
    ("SQLite", [
        "sqlite3",
        "SQLITE_ERROR",
        'near "syntax error"',
        "SQLite3::",
    ]),
]

EXIT_CLEAN = 0       # scan completed, no injection indicators found
EXIT_VULNERABLE = 1  # at least one parameter flagged as vulnerable
EXIT_ERROR = 2       # usage or operational error


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fetch(url, timeout):
    """GET a URL and return (status_code, body_text) as strings.

    Raises RuntimeError with a human-readable message on network failure,
    HTTP errors, or timeouts.
    """
    request = urllib.request.Request(url, headers={"User-Agent": "pentrix-sqli/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            charset = response.headers.get_content_charset() or "utf-8"
            return response.status, raw.decode(charset, errors="replace")
    except urllib.error.HTTPError as exc:
        # Read the error page too: many apps return DBMS errors with
        # 4xx/5xx status codes.
        try:
            raw = exc.read()
            charset = exc.headers.get_content_charset() or "utf-8"
            return exc.code, raw.decode(charset, errors="replace")
        except Exception:
            raise RuntimeError("HTTP %s from server (unreadable body)" % exc.code)
    except urllib.error.URLError as exc:
        reason = exc.reason
        message = reason.strerror if hasattr(reason, "strerror") else str(reason)
        raise RuntimeError("request failed: %s" % message)
    except TimeoutError:
        raise RuntimeError("request timed out after %ss" % timeout)
    except Exception as exc:  # socket.timeout and friends
        text = str(exc)
        if "timed out" in text.lower():
            raise RuntimeError("request timed out after %ss" % timeout)
        raise RuntimeError("request failed: %s" % text)


def match_dbms(body):
    """Return (dbms_label, signature) for the first matching DBMS, else None."""
    for label, signatures in DBMS_SIGNATURES:
        for signature in signatures:
            if signature in body:
                return label, signature
    return None


def build_probe_url(base, params, target_param, payload):
    """Return a URL where target_param carries the payload.

    params is a list of (name, value) pairs preserving order and duplicates.
    """
    probed = [
        (name, payload if name == target_param else value)
        for name, value in params
    ]
    query = urllib.parse.urlencode(probed)
    return "%s?%s" % (base, query)


def probe_param(base, params, param, baseline_signatures, timeout):
    """Probe one parameter with every payload.

    Returns (verdict, details) where verdict is "VULNERABLE" or "NOT VULNERABLE"
    and details is a list of (payload, dbms, signature) hits.
    """
    hits = []
    for payload in PAYLOADS:
        url = build_probe_url(base, params, param, payload)
        status, body = fetch(url, timeout)
        match = match_dbms(body)
        if match is None:
            continue
        dbms, signature = match
        if signature in baseline_signatures:
            # The signature is already present in the baseline response,
            # so it is not caused by our payload. Skip it.
            continue
        hits.append((payload, dbms, signature, status))
    if hits:
        return "VULNERABLE", hits
    return "NOT VULNERABLE", hits


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="sqli.py",
        description=(
            "Probe a URL's query parameters for error-based SQL injection "
            "indicators. For each parameter, classic break-out payloads are "
            "sent and responses are matched against a DBMS error-signature "
            "table. Reports per-parameter verdicts: VULNERABLE (with likely "
            "DBMS) or NOT VULNERABLE. Detection only: no data extraction."
        ),
        epilog=(
            "Examples:\n"
            "  python3 sqli.py \"http://localhost:8000/search?q=test&id=1\"\n"
            "  python3 sqli.py \"http://localhost:8000/search?q=test\" --param q\n"
            "  python3 sqli.py \"http://localhost:8000/search?q=test\" --timeout 5 -o report.txt\n"
            "\nExit codes: 0 = clean, no indicators; 1 = at least one vulnerable "
            "parameter; 2 = error (no params, baseline failed, network error)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", help="target URL including query parameters, e.g. http://host/page?id=1")
    parser.add_argument("--timeout", type=float, default=10,
                        help="request timeout in seconds (default: 10)")
    parser.add_argument("--param", dest="param", default=None,
                        help="test only this parameter name (default: test all parameters)")
    parser.add_argument("-o", "--output", default=None,
                        help="write the report to this file as well as stdout")
    return parser.parse_args(argv)


def run_scan(url, timeout, only_param):
    """Run the full scan. Returns (report_lines, any_vulnerable)."""
    lines = []

    parts = urllib.parse.urlsplit(url)
    if not parts.scheme or not parts.netloc:
        raise RuntimeError("URL must include a scheme and host, e.g. http://host/page?id=1")

    params = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not params:
        raise RuntimeError("URL has no query parameters to test")

    base = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", parts.fragment))
    names = [name for name, _ in params]
    if only_param is not None:
        if only_param not in names:
            raise RuntimeError("parameter '%s' not found in URL (available: %s)"
                               % (only_param, ", ".join(names)))
        names = [only_param]

    lines.append("Target: %s" % url)
    lines.append("Parameters: %s" % ", ".join(sorted(set(n for n, _ in params))))
    lines.append("Testing: %s" % ", ".join(names))
    lines.append("")

    # Baseline: the unmodified request. Anything the baseline already shows
    # cannot be blamed on our payloads.
    try:
        baseline_status, baseline_body = fetch(url, timeout)
    except RuntimeError as exc:
        raise RuntimeError("baseline request failed: %s" % exc)
    baseline_match = match_dbms(baseline_body)
    baseline_signatures = set()
    if baseline_match:
        baseline_signatures.add(baseline_match[1])
    lines.append("Baseline: HTTP %s, %d bytes" % (baseline_status, len(baseline_body)))
    if baseline_match:
        lines.append("Baseline note: already contains signature '%s' (%s); "
                     "payloads must trigger something new" % (baseline_match[1], baseline_match[0]))
    lines.append("")

    any_vulnerable = False
    for name in names:
        verdict, hits = probe_param(base, params, name, baseline_signatures, timeout)
        if verdict == "VULNERABLE":
            any_vulnerable = True
            dbms_votes = {}
            for _, dbms, _, _ in hits:
                dbms_votes[dbms] = dbms_votes.get(dbms, 0) + 1
            likely = max(dbms_votes, key=dbms_votes.get)
            lines.append("[!] param '%s': VULNERABLE (likely DBMS: %s)" % (name, likely))
            for payload, dbms, signature, status in hits:
                lines.append("    payload %-18s -> HTTP %s, matched '%s' (%s)"
                             % (repr(payload), status, signature, dbms))
        else:
            lines.append("[+] param '%s': NOT VULNERABLE (no DBMS error signatures triggered)" % name)
        lines.append("")

    lines.append("Result: %s" % ("VULNERABLE" if any_vulnerable else "NOT VULNERABLE"))
    return lines, any_vulnerable


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])

    try:
        lines, any_vulnerable = run_scan(args.url, args.timeout, args.param)
    except RuntimeError as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR

    report = "\n".join(lines)
    print(report)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                handle.write(report + "\n")
            print("\nReport saved to %s" % args.output)
        except OSError as exc:
            print("Error: could not write output file: %s" % exc, file=sys.stderr)
            return EXIT_ERROR

    return EXIT_VULNERABLE if any_vulnerable else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
