#!/usr/bin/env python3
"""
Backend Testing Agent — Black-box tester for the Mini Social API.

Inputs : base URL, OpenAPI spec, credentials
Output : report.json validated against report.schema.json

Coverage of 14 categories defined by the exam:
  status_code, schema_contract, endpoint_existence, input_validation,
  authentication, authorization, error_handling, headers_cors,
  rate_limiting, business_logic, consistency, performance,
  documentation_drift, http_protocol
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_LINES: List[str] = []


def log(msg: str) -> None:
    line = f"[{datetime.now(timezone.utc).isoformat()}] {msg}"
    LOG_LINES.append(line)
    print(line, file=sys.stderr)


# ---------------------------------------------------------------------------
# HTTP helper — every request is recorded so we can build evidence dicts.
# ---------------------------------------------------------------------------


@dataclass
class Resp:
    method: str
    url: str
    status: int
    headers: Dict[str, str]
    body: Any
    raw_text: str
    elapsed_ms: float
    request_headers: Dict[str, str]
    request_body: Any


class Client:
    def __init__(self, base_url: str, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update(
            {"User-Agent": "BackendTestAgent/1.0 (+https://github.com/nafiulislam)"}
        )
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        token: Optional[str] = None,
        json_body: Any = None,
        params: Any = None,
        headers: Optional[Dict[str, str]] = None,
        raw_body: Optional[bytes] = None,
        allow_redirects: bool = False,
    ) -> Resp:
        url = path if path.startswith("http") else f"{self.base_url}{path}"
        h: Dict[str, str] = dict(headers or {})
        if token:
            h.setdefault("Authorization", f"Bearer {token}")
        kwargs: Dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": h,
            "params": params,
            "timeout": self.timeout,
            "allow_redirects": allow_redirects,
        }
        if raw_body is not None:
            kwargs["data"] = raw_body
        elif json_body is not None:
            kwargs["json"] = json_body
            h.setdefault("Content-Type", "application/json")

        t0 = time.perf_counter()
        try:
            r = self.session.request(**kwargs)
        except requests.exceptions.RequestException as e:
            elapsed = (time.perf_counter() - t0) * 1000
            log(f"{method} {path} → EXC {e.__class__.__name__}: {e}")
            return Resp(
                method=method, url=url, status=-1,
                headers={}, body=None, raw_text=str(e),
                elapsed_ms=elapsed, request_headers=h,
                request_body=json_body if raw_body is None else "<raw>",
            )
        elapsed = (time.perf_counter() - t0) * 1000
        body: Any
        try:
            body = r.json()
        except Exception:
            body = None
        snippet = (r.text or "")[:120].replace("\n", " ")
        log(f"{method} {path} → {r.status_code} ({elapsed:.0f}ms) {snippet}")
        return Resp(
            method=method, url=url, status=r.status_code,
            headers=dict(r.headers), body=body, raw_text=r.text,
            elapsed_ms=elapsed, request_headers=h,
            request_body=json_body if raw_body is None else "<raw>",
        )


# ---------------------------------------------------------------------------
# Finding helpers
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    id: str
    category: str
    severity: str
    endpoint: str
    method: str
    title: str
    description: str
    request: Dict[str, Any]
    response: Dict[str, Any]
    reproduction: str
    expected: str
    actual: str
    spec_reference: Optional[str] = None
    confidence: str = "high"
    suggested_fix: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "id": self.id,
            "category": self.category,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "method": self.method,
            "title": self.title,
            "description": self.description,
            "evidence": {"request": self.request, "response": self.response},
            "reproduction": self.reproduction,
            "expected": self.expected,
            "actual": self.actual,
            "confidence": self.confidence,
        }
        if self.spec_reference:
            d["spec_reference"] = self.spec_reference
        if self.suggested_fix:
            d["suggested_fix"] = self.suggested_fix
        return d


def evidence_request(resp: Resp) -> Dict[str, Any]:
    return {
        "method": resp.method,
        "url": resp.url,
        "headers": _sanitize_headers(resp.request_headers),
        "body": resp.request_body,
    }


def evidence_response(resp: Resp) -> Dict[str, Any]:
    body: Any
    if resp.body is not None:
        body = resp.body
    else:
        body = (resp.raw_text or "")[:1000]
    return {
        "status": resp.status,
        "headers": _sanitize_headers(resp.headers),
        "body": body,
        "elapsed_ms": round(resp.elapsed_ms, 1),
    }


def _sanitize_headers(h: Dict[str, str]) -> Dict[str, str]:
    redacted = {}
    for k, v in (h or {}).items():
        if k.lower() == "authorization" and v:
            redacted[k] = re.sub(r"(Bearer\s+\S{8})\S+", r"\1...REDACTED", v)
        else:
            redacted[k] = v
    return redacted


# ---------------------------------------------------------------------------
# OpenAPI helpers
# ---------------------------------------------------------------------------


def load_spec(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def spec_endpoints(spec: Dict[str, Any]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for path, ops in spec.get("paths", {}).items():
        for method in ops:
            if method.lower() in {"get", "post", "patch", "put", "delete", "options", "head"}:
                out.append((method.upper(), path))
    return out


# ---------------------------------------------------------------------------
# Auth bootstrap — register fresh users (UUID suffix) so the run is hermetic
# ---------------------------------------------------------------------------


@dataclass
class TestUser:
    username: str
    password: str
    email: str
    token: Optional[str] = None
    user_id: Optional[int] = None
    profile: Dict[str, Any] = field(default_factory=dict)


def auth_login(client: Client, username: str, password: str) -> Resp:
    return client.request("POST", "/auth/login",
                          json_body={"username": username, "password": password})


def auth_register(client: Client, u: TestUser) -> Resp:
    return client.request(
        "POST", "/auth/register",
        json_body={"username": u.username, "password": u.password, "email": u.email},
    )


def bootstrap_users(client: Client, seeded: List[Tuple[str, str]]) -> List[TestUser]:
    """Return a list of authenticated TestUser objects.

    First attempts the README's seeded credentials. Any account that fails to
    login (because shared infrastructure is in unknown state) is replaced with
    a freshly-registered UUID-suffixed account.
    """
    users: List[TestUser] = []
    for name, pw in seeded:
        u = TestUser(username=name, password=pw, email=f"{name}@example.test")
        r = auth_login(client, name, pw)
        if r.status == 200 and isinstance(r.body, dict) and r.body.get("access_token"):
            u.token = r.body["access_token"]
            log(f"Logged in seeded user '{name}'")
        else:
            suffix = uuid.uuid4().hex[:8]
            u = TestUser(
                username=f"{name}_{suffix}",
                password=f"Pw_{suffix}!",
                email=f"{name}_{suffix}@example.test",
            )
            rr = auth_register(client, u)
            if rr.status in (200, 201) and isinstance(rr.body, dict) and rr.body.get("access_token"):
                u.token = rr.body["access_token"]
                log(f"Registered fallback user '{u.username}'")
            else:
                log(f"WARN failed to bootstrap user (seed={name}): {rr.status} {rr.raw_text[:120]}")
        if u.token:
            me = client.request("GET", "/users/me", token=u.token)
            if me.status == 200 and isinstance(me.body, dict):
                u.profile = me.body
                if isinstance(me.body.get("id"), int):
                    u.user_id = me.body["id"]
        users.append(u)
    return users


# ---------------------------------------------------------------------------
# Probes — each probe appends Finding objects to `findings`.
# ---------------------------------------------------------------------------


class Agent:
    def __init__(self, base_url: str, spec_path: str, seeded_creds: List[Tuple[str, str]]):
        self.client = Client(base_url)
        self.base_url = base_url.rstrip("/")
        self.spec = load_spec(spec_path)
        self.seeded = seeded_creds
        self.findings: List[Finding] = []
        self._fid_counter = 0
        self.endpoints = spec_endpoints(self.spec)
        self.tested_endpoint_keys: set = set()

    def fid(self, category: str) -> str:
        self._fid_counter += 1
        return f"BUG-{self._fid_counter:03d}-{category}"

    def add(self, **kwargs: Any) -> None:
        cat = kwargs["category"]
        kwargs.setdefault("id", self.fid(cat))
        self.findings.append(Finding(**kwargs))

    def mark_tested(self, method: str, path: str) -> None:
        self.tested_endpoint_keys.add(f"{method.upper()} {path}")

    # ---------------- run ---------------- #

    def run(self) -> None:
        log("=== bootstrapping users ===")
        self.users = bootstrap_users(self.client, self.seeded)
        self.alice = next((u for u in self.users if u.token), None)
        self.bob = next((u for u in self.users if u.token and u is not self.alice), None)
        self.carol = next(
            (u for u in self.users if u.token and u is not self.alice and u is not self.bob),
            None,
        )
        if not self.alice or not self.bob:
            log("FATAL: could not bootstrap two authed users")
            return

        log("=== probe: headers / CORS ===")
        self.probe_headers_cors()
        log("=== probe: endpoint existence (undocumented + docs leak) ===")
        self.probe_endpoint_existence()
        log("=== probe: status codes & schema contracts ===")
        self.probe_status_and_schema()
        log("=== probe: authentication ===")
        self.probe_authentication()
        log("=== probe: authorization & business logic ===")
        self.probe_authorization_and_logic()
        log("=== probe: input validation ===")
        self.probe_input_validation()
        log("=== probe: error handling ===")
        self.probe_error_handling()
        log("=== probe: rate limiting ===")
        self.probe_rate_limiting()
        log("=== probe: performance ===")
        self.probe_performance()
        log("=== probe: HTTP protocol ===")
        self.probe_http_protocol()
        log("=== probe: documentation drift ===")
        self.probe_documentation_drift()
        log("=== probe: consistency ===")
        self.probe_consistency()

    # ---------------- probes ---------------- #

    # ---- headers / cors ----
    def probe_headers_cors(self) -> None:
        r = self.client.request("GET", "/")
        self.mark_tested("GET", "/")
        h = {k.lower(): v for k, v in r.headers.items()}

        # Missing security headers (defensive for an HTTPS API).
        missing = []
        for hdr, label in [
            ("strict-transport-security", "HSTS"),
            ("x-content-type-options", "X-Content-Type-Options"),
            ("x-frame-options", "X-Frame-Options"),
            ("content-security-policy", "Content-Security-Policy"),
            ("referrer-policy", "Referrer-Policy"),
        ]:
            if hdr not in h:
                missing.append(label)
        if missing:
            self.add(
                category="headers_cors",
                severity="medium",
                endpoint="/",
                method="GET",
                title=f"Missing security headers: {', '.join(missing)}",
                description=(
                    "Several recommended HTTP security headers are absent on responses. "
                    "Without HSTS the API can be downgrade-attacked; without "
                    "X-Content-Type-Options browsers may MIME-sniff JSON; without "
                    "X-Frame-Options/CSP, embedded contexts are not restricted."
                ),
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction=f"curl -I {self.base_url}/ and inspect response headers.",
                expected="Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Content-Security-Policy, Referrer-Policy headers present.",
                actual=f"Missing: {', '.join(missing)}",
                confidence="high",
                suggested_fix="Add a middleware that injects HSTS, nosniff, frame-deny, CSP and Referrer-Policy headers on every response.",
            )

        # CORS: ACAO=* with ACAC=true is a real misconfig.
        acao = h.get("access-control-allow-origin", "")
        acac = h.get("access-control-allow-credentials", "").lower()
        if acao == "*" and acac == "true":
            self.add(
                category="headers_cors",
                severity="high",
                endpoint="/",
                method="GET",
                title="CORS allows wildcard origin together with credentials",
                description=(
                    "The server returns Access-Control-Allow-Origin: * together with "
                    "Access-Control-Allow-Credentials: true. Browsers will refuse this "
                    "combination, but proxies / non-browser clients will not, and it "
                    "indicates the CORS policy was not threat-modelled."
                ),
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction="GET / and inspect Access-Control-Allow-Origin and Access-Control-Allow-Credentials.",
                expected="ACAO must be a specific origin (or omit ACAC) when credentials are allowed.",
                actual=f"ACAO={acao!r}, ACAC={acac!r}",
                confidence="high",
                suggested_fix="Echo a vetted origin list rather than '*' when credentials are enabled, or set credentials=false.",
            )

        # Server / framework disclosure
        server = h.get("x-render-origin-server") or h.get("server")
        if server and any(t in server.lower() for t in ("uvicorn", "gunicorn", "fastapi", "werkzeug", "express")):
            self.add(
                category="headers_cors",
                severity="low",
                endpoint="/",
                method="GET",
                title="Server fingerprint disclosed via headers",
                description=(
                    "Response headers reveal the underlying application server "
                    "implementation, which assists attackers in selecting CVEs."
                ),
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction="GET / and inspect 'x-render-origin-server' / 'server'.",
                expected="No internal server identification in production responses.",
                actual=f"Server hint: {server!r}",
                confidence="medium",
                suggested_fix="Strip the x-render-origin-server / Server header at the edge.",
            )

    # ---- endpoint existence ----
    def probe_endpoint_existence(self) -> None:
        # Undocumented endpoints — anything that returns 200/401/403 is "exists"
        candidates = [
            "/admin", "/admin/users", "/debug", "/metrics", "/health",
            "/healthz", "/ready", "/status", "/users", "/posts/feed",
            "/.env", "/v1/users", "/api/users",
        ]
        suspicious: List[Tuple[str, Resp]] = []
        for p in candidates:
            r = self.client.request("GET", p)
            self.mark_tested("GET", p)
            if r.status in (200, 401, 403):
                suspicious.append((p, r))

        for path, r in suspicious:
            if r.status == 200:
                self.add(
                    category="endpoint_existence",
                    severity="medium",
                    endpoint=path,
                    method="GET",
                    title=f"Undocumented endpoint reachable: {path}",
                    description=(
                        f"GET {path} responds with 200 but is not declared in the "
                        "OpenAPI specification. Undocumented surface area suggests "
                        "documentation drift or an internal endpoint that should not "
                        "be exposed."
                    ),
                    request=evidence_request(r),
                    response=evidence_response(r),
                    reproduction=f"curl -i {self.base_url}{path}",
                    expected="404 (endpoint not in spec) or the endpoint must be documented.",
                    actual=f"HTTP {r.status}, body={(r.raw_text or '')[:120]!r}",
                    confidence="high",
                    suggested_fix="Either document the endpoint in openapi.json or remove it.",
                )

        # /openapi.json and /docs / /redoc — FastAPI default surfaces. They are
        # not declared in the supplied spec but FastAPI usually exposes them.
        for path in ("/openapi.json", "/docs", "/redoc"):
            r = self.client.request("GET", path)
            self.mark_tested("GET", path)
            if r.status == 200:
                self.add(
                    category="documentation_drift",
                    severity="low",
                    endpoint=path,
                    method="GET",
                    title=f"Framework default endpoint {path} exposed but not documented",
                    description=(
                        f"{path} is reachable in production. It is not part of the "
                        "supplied OpenAPI spec but is a FastAPI default. Either "
                        "disable it in production or list it in the spec."
                    ),
                    request=evidence_request(r),
                    response=evidence_response(r),
                    reproduction=f"curl -i {self.base_url}{path}",
                    expected=f"{path} declared in openapi.json or disabled.",
                    actual=f"HTTP 200 returned for {path}",
                    confidence="high",
                    suggested_fix="Set docs_url=None / redoc_url=None in production or document them.",
                )

    # ---- status & schema ----
    def probe_status_and_schema(self) -> None:
        # Per spec: register → 201, login → 200, create-post → 201, create-comment → 201
        u = self.alice

        # 1) Register fresh user — verify status code matches spec
        new_user = TestUser(
            username=f"probe_{uuid.uuid4().hex[:8]}",
            password=f"Pw_{uuid.uuid4().hex[:8]}!",
            email=f"probe_{uuid.uuid4().hex[:6]}@example.test",
        )
        r = auth_register(self.client, new_user)
        self.mark_tested("POST", "/auth/register")
        if r.status == 200:
            self.add(
                category="status_code",
                severity="medium",
                endpoint="/auth/register",
                method="POST",
                title="POST /auth/register returns 200 instead of documented 201",
                description="OpenAPI spec declares 201 Created for successful registration; API returns 200.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl -X POST $BASE/auth/register -H "Content-Type: application/json" -d \'{"username":"x","password":"y","email":"z@z"}\'',
                expected="201 Created",
                actual=f"{r.status}",
                spec_reference="paths./auth/register.post.responses.201",
                confidence="high",
                suggested_fix="Return HTTP 201 from the register handler.",
            )
        elif r.status not in (200, 201):
            self.add(
                category="status_code",
                severity="medium",
                endpoint="/auth/register",
                method="POST",
                title=f"Register returns unexpected status {r.status}",
                description="Successful registration should return 201; observed status is unexpected.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl -X POST $BASE/auth/register -H "Content-Type: application/json" -d ...',
                expected="201 Created",
                actual=f"{r.status} {r.raw_text[:100]}",
                spec_reference="paths./auth/register.post.responses.201",
            )

        new_token = (r.body or {}).get("access_token") if isinstance(r.body, dict) else None

        # 2) Login → 200
        r = auth_login(self.client, u.username, u.password)
        self.mark_tested("POST", "/auth/login")

        # 3) /users/me — schema contract
        r = self.client.request("GET", "/users/me", token=u.token)
        self.mark_tested("GET", "/users/me")
        if r.status == 200 and isinstance(r.body, dict):
            required = ["id", "username", "email", "role"]
            missing = [k for k in required if k not in r.body]
            if missing:
                self.add(
                    category="schema_contract",
                    severity="high",
                    endpoint="/users/me",
                    method="GET",
                    title=f"/users/me response missing required fields: {missing}",
                    description="UserPrivate schema requires id/username/email/role; response omits one or more.",
                    request=evidence_request(r),
                    response=evidence_response(r),
                    reproduction='curl $BASE/users/me -H "Authorization: Bearer $TOKEN"',
                    expected="UserPrivate object with id, username, email, role.",
                    actual=f"Missing: {missing}",
                    spec_reference="components.schemas.UserPrivate",
                )
            # Type checks
            for k, t in [("id", int), ("username", str), ("email", str), ("role", str)]:
                if k in r.body and not isinstance(r.body[k], t):
                    self.add(
                        category="schema_contract",
                        severity="medium",
                        endpoint="/users/me",
                        method="GET",
                        title=f"/users/me field '{k}' has wrong type",
                        description=f"Field '{k}' should be {t.__name__}, got {type(r.body[k]).__name__}.",
                        request=evidence_request(r),
                        response=evidence_response(r),
                        reproduction='curl $BASE/users/me -H "Authorization: Bearer $TOKEN"',
                        expected=f"{k} of type {t.__name__}",
                        actual=f"{k}={r.body[k]!r}",
                        spec_reference="components.schemas.UserPrivate",
                    )

        # 4) /posts list — basic shape
        r_list = self.client.request("GET", "/posts")
        self.mark_tested("GET", "/posts")

        # 5) Create post → expected 201
        r = self.client.request(
            "POST", "/posts",
            token=u.token,
            json_body={"body": "agent-test post body"},
        )
        self.mark_tested("POST", "/posts")
        post_id: Optional[int] = None
        if r.status not in (200, 201):
            self.add(
                category="status_code",
                severity="medium",
                endpoint="/posts",
                method="POST",
                title=f"POST /posts returned {r.status}",
                description="Could not create a post; expected 201.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl -X POST $BASE/posts -H "Authorization: Bearer $TOKEN" -d ...',
                expected="201 Created",
                actual=f"{r.status} {r.raw_text[:120]}",
                spec_reference="paths./posts.post.responses.201",
            )
        else:
            if r.status == 200:
                self.add(
                    category="status_code",
                    severity="medium",
                    endpoint="/posts",
                    method="POST",
                    title="POST /posts returns 200 instead of documented 201",
                    description="Spec declares 201 Created for the success path; the API returns 200.",
                    request=evidence_request(r),
                    response=evidence_response(r),
                    reproduction='curl -X POST $BASE/posts -H "Authorization: Bearer $TOKEN" -d \'{"body":"hi"}\'',
                    expected="201 Created",
                    actual="200 OK",
                    spec_reference="paths./posts.post.responses.201",
                )
            if isinstance(r.body, dict) and isinstance(r.body.get("id"), int):
                post_id = r.body["id"]
                self.alice_post_id = post_id

        # 6) Create comment → 201
        if post_id:
            rc = self.client.request(
                "POST", f"/posts/{post_id}/comments",
                token=u.token,
                json_body={"body": "agent comment"},
            )
            self.mark_tested("POST", "/posts/{post_id}/comments")
            if rc.status not in (200, 201):
                self.add(
                    category="status_code",
                    severity="medium",
                    endpoint="/posts/{post_id}/comments",
                    method="POST",
                    title=f"POST /posts/{{post_id}}/comments returned {rc.status}",
                    description="Comment creation should return 201.",
                    request=evidence_request(rc),
                    response=evidence_response(rc),
                    reproduction='curl -X POST $BASE/posts/<id>/comments -H "Authorization: Bearer $TOKEN" -d \'{"body":"hi"}\'',
                    expected="201 Created",
                    actual=f"{rc.status}",
                    spec_reference="paths./posts/{post_id}/comments.post.responses.201",
                )
            elif rc.status == 200:
                self.add(
                    category="status_code",
                    severity="low",
                    endpoint="/posts/{post_id}/comments",
                    method="POST",
                    title="POST /posts/{post_id}/comments returns 200 instead of documented 201",
                    description="Spec says 201 Created for new comments.",
                    request=evidence_request(rc),
                    response=evidence_response(rc),
                    reproduction='curl -X POST $BASE/posts/<id>/comments -H "Authorization: Bearer $TOKEN" -d \'{"body":"hi"}\'',
                    expected="201 Created",
                    actual="200 OK",
                    spec_reference="paths./posts/{post_id}/comments.post.responses.201",
                )
            # CommentResponse schema
            if isinstance(rc.body, dict):
                req = ["id", "post_id", "author_id", "body"]
                missing = [k for k in req if k not in rc.body]
                if missing:
                    self.add(
                        category="schema_contract",
                        severity="high",
                        endpoint="/posts/{post_id}/comments",
                        method="POST",
                        title=f"CommentResponse missing fields: {missing}",
                        description="CommentResponse schema requires id, post_id, author_id, body.",
                        request=evidence_request(rc),
                        response=evidence_response(rc),
                        reproduction='curl -X POST $BASE/posts/<id>/comments -d ...',
                        expected="id, post_id, author_id, body present",
                        actual=f"missing={missing}, body keys={list(rc.body.keys())}",
                        spec_reference="components.schemas.CommentResponse",
                    )

        # 7) /posts/{id}/like and unlike — both expected 200
        if post_id:
            r = self.client.request("POST", f"/posts/{post_id}/like", token=u.token)
            self.mark_tested("POST", "/posts/{post_id}/like")
            r = self.client.request("DELETE", f"/posts/{post_id}/like", token=u.token)
            self.mark_tested("DELETE", "/posts/{post_id}/like")
            # Unlike a non-liked post — should be 404 or 409, often 200
            r2 = self.client.request("DELETE", f"/posts/{post_id}/like", token=u.token)
            if r2.status == 200 and r.status == 200:
                # Soft signal — second unlike succeeding is fine in some designs.
                pass

        # 7b) GET /posts/{id} — fetch the freshly created post
        if post_id:
            rgp = self.client.request("GET", f"/posts/{post_id}")
            self.mark_tested("GET", "/posts/{post_id}")
            if rgp.status == 200 and isinstance(rgp.body, dict):
                # Sanity: created_at should be a recent timestamp; the seeded
                # data on the server returns a fixed 2026-05-01 / 2026-05-06
                # value rather than now() — flag if we can detect this.
                ca = rgp.body.get("created_at")
                if isinstance(ca, str) and ca and ca[:7] not in datetime.now(timezone.utc).strftime("%Y-%m"):
                    # Not necessarily a bug — could be timezone offset.
                    pass

            # GET comments for that post
            rgc = self.client.request("GET", f"/posts/{post_id}/comments")
            self.mark_tested("GET", "/posts/{post_id}/comments")
            if rgc.status == 200 and isinstance(rgc.body, list):
                # CommentResponse shape check
                for c in rgc.body[:3]:
                    if isinstance(c, dict):
                        req = ["id", "post_id", "author_id", "body"]
                        miss = [k for k in req if k not in c]
                        if miss:
                            self.add(
                                category="schema_contract",
                                severity="medium",
                                endpoint="/posts/{post_id}/comments",
                                method="GET",
                                title=f"GET /posts/{{id}}/comments items missing required fields: {miss}",
                                description="CommentResponse requires id, post_id, author_id, body.",
                                request=evidence_request(rgc),
                                response=evidence_response(rgc),
                                reproduction='curl $BASE/posts/<id>/comments',
                                expected="Each item has id, post_id, author_id, body.",
                                actual=f"missing: {miss}, sample keys={list(c.keys())}",
                                spec_reference="components.schemas.CommentResponse",
                            )
                            break

        # 8) follow another user — expected 200
        if self.bob.user_id is not None:
            r = self.client.request("POST", f"/users/{self.bob.user_id}/follow",
                                    token=u.token)
            self.mark_tested("POST", "/users/{user_id}/follow")
            r = self.client.request("DELETE", f"/users/{self.bob.user_id}/follow",
                                    token=u.token)
            self.mark_tested("DELETE", "/users/{user_id}/follow")

        # 9) GET /users/{user_id} — public schema
        if self.bob.user_id is not None:
            r = self.client.request("GET", f"/users/{self.bob.user_id}")
            self.mark_tested("GET", "/users/{user_id}")
            if r.status == 200 and isinstance(r.body, dict):
                required = ["id", "username"]
                missing = [k for k in required if k not in r.body]
                if missing:
                    self.add(
                        category="schema_contract",
                        severity="medium",
                        endpoint="/users/{user_id}",
                        method="GET",
                        title=f"/users/{{user_id}} missing fields: {missing}",
                        description="UserPublic must contain at least id and username.",
                        request=evidence_request(r),
                        response=evidence_response(r),
                        reproduction='curl $BASE/users/<id>',
                        expected="UserPublic with id, username",
                        actual=f"missing={missing}",
                        spec_reference="components.schemas.UserPublic",
                    )
                # Information disclosure: should not leak email / role on public
                leaks = [k for k in ("email", "password", "password_hash", "role") if k in r.body]
                if leaks:
                    self.add(
                        category="schema_contract",
                        severity="high",
                        endpoint="/users/{user_id}",
                        method="GET",
                        title=f"GET /users/{{user_id}} discloses non-public fields: {leaks}",
                        description=(
                            "UserPublic only declares id, username, bio. Returning "
                            f"{leaks} on a public endpoint leaks information about other users."
                        ),
                        request=evidence_request(r),
                        response=evidence_response(r),
                        reproduction='curl $BASE/users/<id>',
                        expected="Only id, username, bio in the response.",
                        actual=f"leaked fields: {leaks}",
                        spec_reference="components.schemas.UserPublic",
                        suggested_fix="Strip non-public fields in the public user serializer.",
                    )

    # ---- authentication ----
    def probe_authentication(self) -> None:
        # /users/me without a token
        r = self.client.request("GET", "/users/me")
        if r.status == 200:
            self.add(
                category="authentication",
                severity="critical",
                endpoint="/users/me",
                method="GET",
                title="/users/me returns data without authentication",
                description="An anonymous request to /users/me should be rejected; instead it returns user data.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction=f"curl {self.base_url}/users/me",
                expected="401 Unauthorized",
                actual=f"{r.status} with body {r.raw_text[:120]}",
            )
        elif r.status == 422:
            self.add(
                category="authentication",
                severity="medium",
                endpoint="/users/me",
                method="GET",
                title="Missing auth on /users/me yields 422 instead of 401",
                description=(
                    "When no Authorization header is supplied, the API returns a 422 "
                    "validation error rather than 401 Unauthorized. This is a common "
                    "FastAPI footgun where the auth dep is exposed as an optional "
                    "header parameter."
                ),
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction=f"curl -i {self.base_url}/users/me",
                expected="401 Unauthorized",
                actual="422 Unprocessable Entity",
                spec_reference="paths./users/me.get",
                suggested_fix="Use a security dependency that raises 401 on missing/invalid tokens; do not expose 'authorization' as a header parameter.",
            )

        # Bad bearer token
        r = self.client.request("GET", "/users/me",
                                headers={"Authorization": "Bearer not.a.real.jwt"})
        if r.status == 200:
            self.add(
                category="authentication",
                severity="critical",
                endpoint="/users/me",
                method="GET",
                title="/users/me accepts arbitrary garbage tokens",
                description="A malformed JWT should be rejected; the API returned 200.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl -H "Authorization: Bearer not.a.real.jwt" $BASE/users/me',
                expected="401 Unauthorized",
                actual=f"{r.status}",
            )

        # Authorization without "Bearer "
        r = self.client.request("GET", "/users/me",
                                headers={"Authorization": self.alice.token or ""})
        if r.status == 200 and self.alice.token:
            self.add(
                category="authentication",
                severity="medium",
                endpoint="/users/me",
                method="GET",
                title="Authorization accepted without 'Bearer' scheme prefix",
                description="The API accepts a raw token in the Authorization header; standard requires 'Bearer <token>'.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl -H "Authorization: $TOKEN" $BASE/users/me',
                expected="401 (scheme missing) or strict prefix enforcement.",
                actual=f"{r.status} accepted",
            )

        # Logout invalidation
        if self.alice.token:
            tok = self.alice.token
            r_logout = self.client.request("POST", "/auth/logout", token=tok)
            self.mark_tested("POST", "/auth/logout")
            r_after = self.client.request("GET", "/users/me", token=tok)
            if r_logout.status in (200, 204) and r_after.status == 200:
                self.add(
                    category="authentication",
                    severity="high",
                    endpoint="/auth/logout",
                    method="POST",
                    title="Tokens remain valid after /auth/logout",
                    description=(
                        "After calling POST /auth/logout the same access token is "
                        "still accepted by /users/me. Logout is therefore a no-op "
                        "(no server-side revocation), which defeats user expectations "
                        "for a session ending."
                    ),
                    request=evidence_request(r_after),
                    response=evidence_response(r_after),
                    reproduction='POST /auth/logout, then GET /users/me with same token',
                    expected="401 Unauthorized after logout (token revoked).",
                    actual=f"GET /users/me still returns {r_after.status}",
                    suggested_fix="Track a server-side token denylist or rotate a per-session secret on logout.",
                )

        # Username enumeration on login
        r1 = self.client.request("POST", "/auth/login",
                                 json_body={"username": self.alice.username, "password": "definitely_wrong_xxx"})
        r2 = self.client.request("POST", "/auth/login",
                                 json_body={"username": f"nope_{uuid.uuid4().hex[:8]}", "password": "x"})
        if (r1.body or {}).get("detail") != (r2.body or {}).get("detail") and r1.status == r2.status:
            self.add(
                category="authentication",
                severity="medium",
                endpoint="/auth/login",
                method="POST",
                title="Login error messages enable username enumeration",
                description=(
                    "Different login error messages are returned for an existing "
                    "user (wrong password) vs a non-existent user. This lets an "
                    "attacker enumerate registered usernames."
                ),
                request=evidence_request(r2),
                response=evidence_response(r2),
                reproduction='POST /auth/login with valid user / bad password vs unknown user / any password',
                expected="Identical error message in both cases.",
                actual=f"Existing user msg={r1.body!r}, unknown msg={r2.body!r}",
                suggested_fix="Return a constant 'invalid credentials' error for both cases.",
            )

    # ---- authorization & business logic ----
    def probe_authorization_and_logic(self) -> None:
        u, v = self.alice, self.bob
        # Alice creates a post
        r = self.client.request(
            "POST", "/posts", token=u.token,
            json_body={"body": f"alice post {uuid.uuid4().hex[:6]}"},
        )
        post_id = (r.body or {}).get("id") if isinstance(r.body, dict) else None
        if not isinstance(post_id, int):
            return

        # Bob attempts to PATCH alice's post → expect 403/404
        r_pat = self.client.request(
            "PATCH", f"/posts/{post_id}", token=v.token,
            json_body={"body": "owned by bob"},
        )
        self.mark_tested("PATCH", "/posts/{post_id}")
        if r_pat.status == 200:
            self.add(
                category="authorization",
                severity="critical",
                endpoint="/posts/{post_id}",
                method="PATCH",
                title="IDOR: a non-owner can PATCH another user's post",
                description=(
                    "User Bob successfully edited a post authored by Alice. Posts "
                    "should be editable only by their author."
                ),
                request=evidence_request(r_pat),
                response=evidence_response(r_pat),
                reproduction='Login as bob, PATCH /posts/<alice_post_id> with new body.',
                expected="403 Forbidden (non-owner) or 404",
                actual=f"{r_pat.status} OK",
                suggested_fix="Compare post.author_id to current user before applying mutation.",
            )

        # Bob attempts to DELETE alice's post
        r_del = self.client.request("DELETE", f"/posts/{post_id}", token=v.token)
        self.mark_tested("DELETE", "/posts/{post_id}")
        if r_del.status in (200, 204):
            self.add(
                category="authorization",
                severity="critical",
                endpoint="/posts/{post_id}",
                method="DELETE",
                title="IDOR: a non-owner can DELETE another user's post",
                description="Bob was able to delete Alice's post.",
                request=evidence_request(r_del),
                response=evidence_response(r_del),
                reproduction='Login as bob, DELETE /posts/<alice_post_id>',
                expected="403 Forbidden",
                actual=f"{r_del.status}",
                suggested_fix="Reject DELETE when the requester is not the post author.",
            )

        # Recreate a post for further checks (the previous one may be deleted)
        r = self.client.request(
            "POST", "/posts", token=u.token,
            json_body={"body": f"alice post v2 {uuid.uuid4().hex[:6]}"},
        )
        post_id2 = (r.body or {}).get("id") if isinstance(r.body, dict) else None

        # Mass assignment / privilege escalation through PATCH /users/me
        r = self.client.request(
            "PATCH", "/users/me", token=u.token,
            json_body={"role": "admin", "id": 1, "email": "hacker@example.com"},
        )
        self.mark_tested("PATCH", "/users/me")
        if r.status in (200, 201):
            # PATCH response body itself may leak password_hash etc.
            if isinstance(r.body, dict):
                leaks = [k for k in ("password", "password_hash", "hashed_password",
                                     "salt", "secret", "token") if k in r.body]
                if leaks:
                    self.add(
                        category="schema_contract",
                        severity="critical",
                        endpoint="/users/me",
                        method="PATCH",
                        title=f"PATCH /users/me response leaks sensitive fields: {leaks}",
                        description=(
                            "The PATCH /users/me response body contains sensitive "
                            f"fields {leaks}. UserPrivate explicitly does not "
                            "declare a password / hash field — these must never be "
                            "serialized to the client."
                        ),
                        request=evidence_request(r),
                        response=evidence_response(r),
                        reproduction='PATCH /users/me with any body, inspect response keys.',
                        expected="UserPrivate fields only (id, username, email, role, bio, age).",
                        actual=f"Leaked fields: {leaks}",
                        spec_reference="components.schemas.UserPrivate",
                        suggested_fix="Use a response_model that excludes the password_hash column.",
                    )
            mer = self.client.request("GET", "/users/me", token=u.token)
            new_role = (mer.body or {}).get("role")
            if new_role == "admin":
                self.add(
                    category="authorization",
                    severity="critical",
                    endpoint="/users/me",
                    method="PATCH",
                    title="Mass assignment: PATCH /users/me allows role escalation",
                    description=(
                        "Submitting {role: 'admin'} in PATCH /users/me sets the user's "
                        "role to admin. The PATCH endpoint should only accept whitelisted "
                        "fields (bio, age)."
                    ),
                    request=evidence_request(r),
                    response=evidence_response(mer),
                    reproduction='PATCH /users/me with body {"role":"admin"}',
                    expected="role unchanged; PATCH only accepts {bio, age}.",
                    actual=f"role is now {new_role!r}",
                    suggested_fix="Define a strict UserUpdate Pydantic model that only includes editable fields.",
                )
            # email change side-effect
            new_email = (mer.body or {}).get("email")
            if new_email == "hacker@example.com":
                self.add(
                    category="authorization",
                    severity="high",
                    endpoint="/users/me",
                    method="PATCH",
                    title="Mass assignment: PATCH /users/me allows email change",
                    description=(
                        "PATCH /users/me only documents bio/age as editable; the API "
                        "allowed the email field to be overwritten as well."
                    ),
                    request=evidence_request(r),
                    response=evidence_response(mer),
                    reproduction='PATCH /users/me with body {"email":"x@y.z"}',
                    expected="email unchanged",
                    actual=f"email is now {new_email!r}",
                    spec_reference="paths./users/me.patch (description: bio, age)",
                    suggested_fix="Restrict editable fields to {bio, age} via a typed Pydantic model.",
                )

        # Self-follow: a user follows themselves
        if u.user_id is not None:
            r = self.client.request("POST", f"/users/{u.user_id}/follow", token=u.token)
            if r.status in (200, 201):
                self.add(
                    category="business_logic",
                    severity="medium",
                    endpoint="/users/{user_id}/follow",
                    method="POST",
                    title="A user can follow themselves",
                    description="POST /users/<own_id>/follow succeeds; this is a logic flaw — a user cannot meaningfully follow themselves.",
                    request=evidence_request(r),
                    response=evidence_response(r),
                    reproduction='POST /users/<own_id>/follow',
                    expected="400 Bad Request — cannot follow self.",
                    actual=f"{r.status}",
                    suggested_fix="Reject follow when target_id == requester_id.",
                )

        # Like the same post twice
        if post_id2:
            r1 = self.client.request("POST", f"/posts/{post_id2}/like", token=u.token)
            r2 = self.client.request("POST", f"/posts/{post_id2}/like", token=u.token)
            if r1.status in (200, 201) and r2.status in (200, 201):
                # Check whether like_count visibly doubled.
                rg = self.client.request("GET", f"/posts/{post_id2}")
                like_count = None
                if isinstance(rg.body, dict):
                    for k in ("like_count", "likes", "likes_count"):
                        if k in rg.body and isinstance(rg.body[k], int):
                            like_count = rg.body[k]
                            break
                if like_count is not None and like_count > 1:
                    self.add(
                        category="business_logic",
                        severity="medium",
                        endpoint="/posts/{post_id}/like",
                        method="POST",
                        title="Liking the same post twice increments like count",
                        description=f"After liking the same post twice as a single user, like_count={like_count} (>1).",
                        request=evidence_request(r2),
                        response=evidence_response(rg),
                        reproduction='POST /posts/<id>/like twice with the same user.',
                        expected="Idempotent: each user contributes at most 1 like.",
                        actual=f"like count={like_count}",
                        suggested_fix="Make the like operation a uniqueness-constrained insert keyed by (user_id, post_id).",
                    )

        # Unfollow a user that is not followed
        if v.user_id is not None:
            r = self.client.request("DELETE", f"/users/{v.user_id}/follow", token=u.token)
            if r.status == 200:
                # Many APIs return 200 here, only flag if not 404. Soft signal.
                pass

        # Comment on non-existent post
        r = self.client.request(
            "POST", "/posts/999999999/comments",
            token=u.token,
            json_body={"body": "ghost"},
        )
        if r.status in (200, 201):
            self.add(
                category="business_logic",
                severity="high",
                endpoint="/posts/{post_id}/comments",
                method="POST",
                title="Can comment on a non-existent post",
                description="Posting a comment to /posts/999999999/comments succeeds despite the post not existing.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='POST /posts/999999999/comments with valid body.',
                expected="404 Not Found",
                actual=f"{r.status}",
                suggested_fix="Verify the parent post exists before creating the comment.",
            )

        # Like a non-existent post
        r = self.client.request("POST", "/posts/999999999/like", token=u.token)
        if r.status in (200, 201):
            self.add(
                category="business_logic",
                severity="medium",
                endpoint="/posts/{post_id}/like",
                method="POST",
                title="Can like a non-existent post",
                description="POST /posts/999999999/like returned a success status although the post does not exist.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='POST /posts/999999999/like',
                expected="404 Not Found",
                actual=f"{r.status}",
            )

        # Follow a non-existent user
        r = self.client.request("POST", "/users/999999999/follow", token=u.token)
        if r.status in (200, 201):
            self.add(
                category="business_logic",
                severity="medium",
                endpoint="/users/{user_id}/follow",
                method="POST",
                title="Can follow a non-existent user",
                description="Follow request to a fictional user id succeeds.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='POST /users/999999999/follow',
                expected="404 Not Found",
                actual=f"{r.status}",
            )

    # ---- input validation ----
    def probe_input_validation(self) -> None:
        u = self.alice

        # Empty body for create-post
        r = self.client.request("POST", "/posts", token=u.token, json_body={})
        if r.status in (200, 201):
            self.add(
                category="input_validation",
                severity="high",
                endpoint="/posts",
                method="POST",
                title="POST /posts accepts an empty body",
                description="An empty JSON object is accepted as a valid post body. This is likely missing a required-field check.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl -X POST $BASE/posts -d \'{}\' -H "Authorization: Bearer $TOKEN"',
                expected="422 Unprocessable Entity",
                actual=f"{r.status} created post: {r.body!r}",
                suggested_fix="Define a Pydantic model with body: str (min_length=1).",
            )

        # Wrong type
        r = self.client.request("POST", "/posts", token=u.token, json_body={"body": 12345})
        if r.status in (200, 201):
            stored_body = (r.body or {}).get("body") if isinstance(r.body, dict) else None
            self.add(
                category="input_validation",
                severity="medium",
                endpoint="/posts",
                method="POST",
                title="POST /posts accepts a non-string `body`",
                description=(
                    "Sending `body=12345` (integer) is accepted and stored as the "
                    f"integer {stored_body!r}. Posts are documented as string-bodied "
                    "content; the API does not validate the type and the value is "
                    "round-tripped as an integer in the response."
                ),
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl -X POST $BASE/posts -d \'{"body":12345}\' -H "Authorization: Bearer $TOKEN"',
                expected="422 Unprocessable Entity",
                actual=f"{r.status} stored body type={type(stored_body).__name__}",
            )

        # Comment max length 500 — try 5000
        if hasattr(self, "alice_post_id") and self.alice_post_id:
            big = "x" * 5000
            r = self.client.request(
                "POST", f"/posts/{self.alice_post_id}/comments",
                token=u.token, json_body={"body": big},
            )
            if r.status in (200, 201):
                self.add(
                    category="input_validation",
                    severity="medium",
                    endpoint="/posts/{post_id}/comments",
                    method="POST",
                    title="Comment body exceeds documented max length (500) without rejection",
                    description="CommentCreate.body has maxLength=500 in the spec. A 5000-character body is accepted.",
                    request=evidence_request(r),
                    response=evidence_response(r),
                    reproduction='POST /posts/<id>/comments with body of length 5000.',
                    expected="422 Validation Error",
                    actual=f"{r.status}",
                    spec_reference="components.schemas.CommentCreate.body.maxLength",
                )

            # Empty comment body — minLength=1
            r = self.client.request(
                "POST", f"/posts/{self.alice_post_id}/comments",
                token=u.token, json_body={"body": ""},
            )
            if r.status in (200, 201):
                self.add(
                    category="input_validation",
                    severity="medium",
                    endpoint="/posts/{post_id}/comments",
                    method="POST",
                    title="Empty comment body accepted (minLength=1 violated)",
                    description="The CommentCreate.body field has minLength=1; the API accepts empty strings.",
                    request=evidence_request(r),
                    response=evidence_response(r),
                    reproduction='POST /posts/<id>/comments with body=""',
                    expected="422 Validation Error",
                    actual=f"{r.status}",
                    spec_reference="components.schemas.CommentCreate.body.minLength",
                )

        # Negative post_id (path is integer per spec; FastAPI accepts negative ints)
        r = self.client.request("GET", "/posts/-1")
        if r.status == 200:
            self.add(
                category="input_validation",
                severity="low",
                endpoint="/posts/{post_id}",
                method="GET",
                title="Negative post_id accepted",
                description="GET /posts/-1 returns 200 even though no post with id<=0 should exist.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl $BASE/posts/-1',
                expected="404 Not Found",
                actual=f"{r.status}",
            )

        # /posts?limit=-1 — should be 422; observed 500 in practice
        r = self.client.request("GET", "/posts", params={"limit": -1})
        if r.status >= 500:
            self.add(
                category="error_handling",
                severity="high",
                endpoint="/posts",
                method="GET",
                title="Negative `limit` query parameter triggers a 500",
                description=(
                    "GET /posts?limit=-1 returns a 500 Internal Server Error rather "
                    "than a validation error. Out-of-range query parameters should "
                    "be rejected at the validation layer with 422."
                ),
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl -i "$BASE/posts?limit=-1"',
                expected="422 Unprocessable Entity",
                actual=f"{r.status} {r.raw_text[:120]}",
                suggested_fix="Apply Query(..., ge=0) on the limit parameter, and similarly bound offset.",
            )
        elif r.status == 200:
            self.add(
                category="input_validation",
                severity="low",
                endpoint="/posts",
                method="GET",
                title="Negative limit accepted on /posts",
                description="A negative limit is accepted on the public feed; pagination params should be validated >=0.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl $BASE/posts?limit=-1',
                expected="422 Validation Error",
                actual=f"{r.status}",
            )

        # Age set to negative via PATCH /users/me
        r = self.client.request("PATCH", "/users/me",
                                token=u.token,
                                json_body={"age": -42})
        if r.status in (200, 201):
            mer = self.client.request("GET", "/users/me", token=u.token)
            if isinstance(mer.body, dict) and mer.body.get("age") == -42:
                self.add(
                    category="input_validation",
                    severity="medium",
                    endpoint="/users/me",
                    method="PATCH",
                    title="Negative age accepted on PATCH /users/me",
                    description="Setting age to -42 is accepted and persisted; age should be >=0.",
                    request=evidence_request(r),
                    response=evidence_response(mer),
                    reproduction='PATCH /users/me with {"age":-42}',
                    expected="422 Validation Error",
                    actual="age stored as -42",
                    suggested_fix="Add a Field(ge=0) constraint on UserUpdate.age.",
                )

        # Wrong content type on register
        r = self.client.request(
            "POST", "/auth/register",
            raw_body=b"username=foo&password=bar",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if r.status == 500:
            self.add(
                category="error_handling",
                severity="medium",
                endpoint="/auth/register",
                method="POST",
                title="Form-encoded body to /auth/register returns 500",
                description="Sending a form-encoded body returns a 500 — the API should respond 415 Unsupported Media Type or 422.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl -X POST $BASE/auth/register --data-urlencode username=foo --data-urlencode password=bar',
                expected="415 / 422",
                actual="500 Internal Server Error",
            )

    # ---- error handling ----
    def probe_error_handling(self) -> None:
        # Send invalid JSON to /auth/login
        r = self.client.request(
            "POST", "/auth/login",
            raw_body=b"{not-json",
            headers={"Content-Type": "application/json"},
        )
        if r.status >= 500:
            self.add(
                category="error_handling",
                severity="high",
                endpoint="/auth/login",
                method="POST",
                title="Malformed JSON triggers a 5xx",
                description="Garbage JSON in the request body should be a 400/422, not a 500.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl -X POST $BASE/auth/login -H "Content-Type: application/json" --data-binary "{not-json"',
                expected="400 / 422",
                actual=f"{r.status}",
            )
        body_text = (r.raw_text or "")
        if any(t in body_text for t in ('Traceback', '"line":', "File \"/", "/usr/lib/python")):
            self.add(
                category="error_handling",
                severity="high",
                endpoint="/auth/login",
                method="POST",
                title="Stack trace leaked on bad input",
                description="Server response contains traceback / source path information.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='POST /auth/login with malformed JSON',
                expected="Generic 4xx error.",
                actual="Traceback present in body",
            )

        # Compare error response shapes across endpoints
        e1 = self.client.request("POST", "/auth/login",
                                 json_body={"username": "x"})
        e2 = self.client.request("POST", "/auth/register", json_body={})
        e3 = self.client.request("GET", "/posts/notanint")
        shapes = []
        for e in (e1, e2, e3):
            if isinstance(e.body, dict):
                shapes.append(set(e.body.keys()))
            else:
                shapes.append(set())
        if len(set(map(frozenset, shapes))) > 1:
            self.add(
                category="error_handling",
                severity="low",
                endpoint="/auth/login",
                method="POST",
                title="Inconsistent error response shapes",
                description=(
                    "Different endpoints return different JSON shapes for client "
                    "errors: "
                    f"login(missing pw)={list(shapes[0])}, "
                    f"register(empty)={list(shapes[1])}, "
                    f"get-post(non-int)={list(shapes[2])}."
                ),
                request=evidence_request(e2),
                response=evidence_response(e2),
                reproduction='Compare error bodies of /auth/login (missing pw), /auth/register (empty), /posts/notanint',
                expected="A consistent error envelope (e.g., {detail: ...}).",
                actual="Multiple distinct shapes observed.",
            )

    # ---- rate limiting ----
    def probe_rate_limiting(self) -> None:
        # Fire a short burst of failed logins concurrently and observe.
        bad = {"username": self.alice.username, "password": "wrong"}
        sample: Optional[Resp] = None

        def hit(_):
            return self.client.request("POST", "/auth/login", json_body=bad)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            results = list(ex.map(hit, range(20)))
        statuses = [r.status for r in results]
        # If no 429 anywhere within a 20-request burst on a sensitive endpoint,
        # report missing rate limiting as low/medium.
        if all(s != 429 for s in statuses):
            sample = results[-1]
            self.add(
                category="rate_limiting",
                severity="medium",
                endpoint="/auth/login",
                method="POST",
                title="No rate limiting observed on /auth/login",
                description=(
                    "20 failed login attempts in a tight burst all received non-429 "
                    "responses. There is no apparent rate limit on the login endpoint, "
                    "which enables brute-force credential attacks."
                ),
                request=evidence_request(sample),
                response=evidence_response(sample),
                reproduction='Fire 20 concurrent POST /auth/login attempts with a wrong password.',
                expected="At least some responses with 429 Too Many Requests after a sustained burst.",
                actual=f"Status codes: {statuses}",
                confidence="medium",
                suggested_fix="Add per-IP and per-username rate limiting on /auth/login.",
            )

    # ---- performance ----
    def probe_performance(self) -> None:
        # Login latency — many real APIs aim for <500ms even with bcrypt
        latencies = []
        for _ in range(3):
            r = self.client.request(
                "POST", "/auth/login",
                json_body={"username": self.alice.username, "password": self.alice.password},
            )
            if r.status == 200:
                latencies.append(r.elapsed_ms)
        if latencies and (sum(latencies) / len(latencies)) > 1000:
            avg = sum(latencies) / len(latencies)
            self.add(
                category="performance",
                severity="low",
                endpoint="/auth/login",
                method="POST",
                title=f"Login is slow: avg {avg:.0f} ms over {len(latencies)} samples",
                description=(
                    "Successful login takes longer than 1 second on average. While "
                    "bcrypt is intentionally slow, sub-second logins are typical with "
                    "well-tuned cost factors. Slow logins also amplify any rate-limit "
                    "absence into a denial-of-service vector."
                ),
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='Time three POST /auth/login requests with valid credentials.',
                expected="< 500 ms p50",
                actual=f"avg ~{avg:.0f} ms",
                confidence="medium",
            )

        # Big offset and big limit
        r = self.client.request("GET", "/posts", params={"limit": 100000})
        self.mark_tested("GET", "/posts")
        if r.status == 200 and isinstance(r.body, list) and len(r.body) > 1000:
            self.add(
                category="performance",
                severity="medium",
                endpoint="/posts",
                method="GET",
                title="Unbounded limit on /posts (no max page size)",
                description=(
                    "limit=100000 returns "
                    f"{len(r.body)} posts in a single response. The API should "
                    "cap the maximum page size to prevent unbounded payloads."
                ),
                request=evidence_request(r),
                response={"status": r.status, "headers": _sanitize_headers(r.headers),
                          "body_length_items": len(r.body),
                          "elapsed_ms": round(r.elapsed_ms, 1)},
                reproduction='curl $BASE/posts?limit=100000',
                expected="Server enforces a sane maximum (e.g., limit<=100).",
                actual=f"limit=100000 returned {len(r.body)} items",
                suggested_fix="Clamp limit to a configured ceiling (e.g., min(limit, 100)).",
            )
        if r.elapsed_ms > 5000:
            self.add(
                category="performance",
                severity="low",
                endpoint="/posts",
                method="GET",
                title="Slow response on /posts with large limit",
                description=f"GET /posts?limit=100000 took {r.elapsed_ms:.0f} ms.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='time curl $BASE/posts?limit=100000',
                expected="<2 seconds",
                actual=f"{r.elapsed_ms:.0f} ms",
                confidence="medium",
            )

        # No caching headers on a public read-only resource
        r2 = self.client.request("GET", "/posts")
        h = {k.lower(): v for k, v in r2.headers.items()}
        if not any(k in h for k in ("cache-control", "etag", "last-modified")):
            self.add(
                category="performance",
                severity="low",
                endpoint="/posts",
                method="GET",
                title="No caching/validation headers on /posts",
                description="Public GET endpoints expose no Cache-Control, ETag or Last-Modified, preventing client and proxy caching.",
                request=evidence_request(r2),
                response=evidence_response(r2),
                reproduction='curl -I $BASE/posts',
                expected="Cache-Control or ETag/Last-Modified set on read-only collections.",
                actual="No caching-related headers",
                confidence="medium",
            )

    # ---- HTTP protocol ----
    def probe_http_protocol(self) -> None:
        # OPTIONS preflight
        r = self.client.request(
            "OPTIONS", "/posts",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        self.mark_tested("OPTIONS", "/posts")
        h = {k.lower(): v for k, v in r.headers.items()}
        if h.get("access-control-allow-origin") == "*":
            self.add(
                category="http_protocol",
                severity="medium",
                endpoint="/posts",
                method="OPTIONS",
                title="OPTIONS preflight reflects wildcard ACAO for arbitrary Origin",
                description=(
                    "A preflight from Origin 'https://evil.example' is answered with "
                    "Access-Control-Allow-Origin: *, accepting any cross-origin caller."
                ),
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl -X OPTIONS $BASE/posts -H "Origin: https://evil.example" -H "Access-Control-Request-Method: POST"',
                expected="ACAO restricted to a vetted origin list.",
                actual="ACAO=*",
            )

        # HEAD on /posts
        r = self.client.request("HEAD", "/posts")
        self.mark_tested("HEAD", "/posts")
        if r.status == 405:
            self.add(
                category="http_protocol",
                severity="low",
                endpoint="/posts",
                method="HEAD",
                title="HEAD not supported on /posts",
                description="HEAD on /posts returns 405. RFC 9110 expects HEAD to be supported wherever GET is.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl -I $BASE/posts',
                expected="200 with no body",
                actual="405 Method Not Allowed",
                confidence="medium",
            )

        # Non-JSON Accept header
        r = self.client.request(
            "GET", "/posts",
            headers={"Accept": "application/xml"},
        )
        if r.status == 200 and "application/json" in r.headers.get("Content-Type", "").lower():
            # Server ignored Accept and returned JSON anyway. Note: this is
            # common, only flag if the API documents content negotiation.
            pass

        # PUT on a POST-only endpoint should be 405
        r = self.client.request("PUT", "/posts",
                                token=self.alice.token,
                                json_body={"body": "x"})
        if r.status == 200:
            self.add(
                category="http_protocol",
                severity="low",
                endpoint="/posts",
                method="PUT",
                title="PUT accepted on a POST-only endpoint",
                description="PUT /posts is not declared in the spec but returned 200, suggesting overly permissive method routing.",
                request=evidence_request(r),
                response=evidence_response(r),
                reproduction='curl -X PUT $BASE/posts -d ...',
                expected="405 Method Not Allowed",
                actual="200 OK",
            )

    # ---- documentation drift ----
    def probe_documentation_drift(self) -> None:
        # Spec declares 'authorization' as a normal optional Header parameter,
        # which is documentation drift — the real protection is JWT-Bearer, and
        # this exposes the auth as if it were optional.
        spec_path = self.spec.get("paths", {}).get("/users/me", {}).get("get", {})
        params = spec_path.get("parameters", [])
        for p in params:
            if p.get("name", "").lower() == "authorization" and p.get("required") is False:
                self.add(
                    category="documentation_drift",
                    severity="medium",
                    endpoint="/users/me",
                    method="GET",
                    title="OpenAPI declares 'authorization' as an optional header parameter",
                    description=(
                        "The spec lists 'authorization' as an optional header parameter "
                        "rather than declaring an HTTP-Bearer security scheme. This "
                        "misrepresents the auth requirements: the endpoint does require "
                        "a token in practice."
                    ),
                    request={"method": "GET", "url": f"{self.base_url}/users/me",
                             "headers": {}, "body": None},
                    response={"status": 0, "body": "spec-only finding"},
                    reproduction='Inspect openapi.json paths./users/me.get.parameters',
                    expected="securitySchemes.bearerAuth declared and required on protected paths.",
                    actual='Authorization listed as an optional Header parameter.',
                    spec_reference="paths./users/me.get.parameters",
                    suggested_fix="Define components.securitySchemes.bearerAuth and apply security: [{bearerAuth: []}] on protected operations.",
                )
                break

        # Schema for POST /auth/register / /auth/login does not declare a request body
        for p in ("/auth/register", "/auth/login"):
            op = self.spec.get("paths", {}).get(p, {}).get("post", {})
            if "requestBody" not in op:
                self.add(
                    category="documentation_drift",
                    severity="low",
                    endpoint=p,
                    method="POST",
                    title=f"{p} has no documented requestBody",
                    description=(
                        f"{p} requires username/password/email but the spec declares "
                        "no requestBody — clients cannot generate a typed payload from "
                        "the spec."
                    ),
                    request={"method": "POST", "url": f"{self.base_url}{p}",
                             "headers": {}, "body": None},
                    response={"status": 0, "body": "spec-only finding"},
                    reproduction=f'Inspect openapi.json paths.{p}.post',
                    expected="requestBody with a schema describing username/password/email.",
                    actual="No requestBody declared in spec.",
                    spec_reference=f"paths.{p}.post",
                )

    # ---- consistency ----
    def probe_consistency(self) -> None:
        # Get a post via list and via direct fetch — fields should match.
        listed = self.client.request("GET", "/posts", params={"limit": 5})
        if listed.status == 200 and isinstance(listed.body, list) and listed.body:
            sample = listed.body[0]
            if isinstance(sample, dict) and "id" in sample:
                pid = sample["id"]
                single = self.client.request("GET", f"/posts/{pid}")
                if single.status == 200 and isinstance(single.body, dict):
                    a = set(sample.keys())
                    b = set(single.body.keys())
                    if a != b:
                        self.add(
                            category="consistency",
                            severity="medium",
                            endpoint="/posts/{post_id}",
                            method="GET",
                            title="Post shape differs between list and detail endpoints",
                            description=(
                                "GET /posts (list) and GET /posts/{id} (detail) return "
                                f"different sets of fields — list keys={sorted(a)}, "
                                f"detail keys={sorted(b)}. Clients are forced to "
                                "branch on which endpoint they used."
                            ),
                            request=evidence_request(single),
                            response=evidence_response(single),
                            reproduction='Compare keys of GET /posts[0] vs GET /posts/<id>',
                            expected="Same canonical post shape from both endpoints.",
                            actual=f"list-only={sorted(a-b)}, detail-only={sorted(b-a)}",
                            confidence="high",
                        )

                    # author vs authorName naming inconsistency
                    list_has = [k for k in ("author", "authorName", "author_name") if k in sample]
                    det_has = [k for k in ("author", "authorName", "author_name") if k in single.body]
                    if list_has and det_has and set(list_has) != set(det_has):
                        self.add(
                            category="consistency",
                            severity="medium",
                            endpoint="/posts",
                            method="GET",
                            title="Author display field is named differently in list vs detail",
                            description=(
                                f"GET /posts uses {list_has} but GET /posts/{{id}} "
                                f"uses {det_has}. The same logical field has two "
                                "different names depending on the endpoint."
                            ),
                            request=evidence_request(listed),
                            response=evidence_response(single),
                            reproduction='Compare /posts[0] and /posts/<id>; note author key naming.',
                            expected="Consistent field name (e.g. 'author_username') everywhere.",
                            actual=f"list={list_has}, detail={det_has}",
                            suggested_fix="Pick one canonical name and add a deprecated alias if needed.",
                        )

                    # like_count: same field, different types in list vs detail
                    if "like_count" in sample and "like_count" in single.body:
                        if type(sample["like_count"]) is not type(single.body["like_count"]):
                            self.add(
                                category="consistency",
                                severity="high",
                                endpoint="/posts",
                                method="GET",
                                title="like_count has different types between list and detail",
                                description=(
                                    f"GET /posts returns like_count as "
                                    f"{type(sample['like_count']).__name__} (value={sample['like_count']!r}), "
                                    f"GET /posts/{{id}} returns it as "
                                    f"{type(single.body['like_count']).__name__} (value={single.body['like_count']!r}). "
                                    "Strongly-typed clients will fail on whichever payload they did not expect."
                                ),
                                request=evidence_request(listed),
                                response=evidence_response(single),
                                reproduction='Inspect type(like_count) on /posts vs /posts/<id>',
                                expected="like_count is an integer in both responses.",
                                actual=f"list:{type(sample['like_count']).__name__} detail:{type(single.body['like_count']).__name__}",
                                suggested_fix="Cast like_count to int in the list serializer.",
                            )

        # Schema_contract: list response items contain fields that are not declared anywhere
        # but more importantly, like_count as a string is a contract violation
        if listed.status == 200 and isinstance(listed.body, list) and listed.body:
            sample = listed.body[0]
            if isinstance(sample, dict) and isinstance(sample.get("like_count"), str):
                self.add(
                    category="schema_contract",
                    severity="high",
                    endpoint="/posts",
                    method="GET",
                    title="GET /posts returns like_count as a string",
                    description=(
                        "Counters should be numeric. The /posts list serializer "
                        f"emits like_count as a string ({sample['like_count']!r}). "
                        "Numeric-typed clients (TypeScript, Swift, Kotlin) will fail "
                        "to deserialize, and JSON-Schema generators will mistype "
                        "downstream models."
                    ),
                    request=evidence_request(listed),
                    response=evidence_response(listed),
                    reproduction='curl $BASE/posts | jq ".[0].like_count | type"',
                    expected='"number"',
                    actual='"string"',
                    suggested_fix="Cast like_count to int in the list serializer (likely a SQL COUNT() returning a varchar).",
                )

    # ---- summary helpers ---- #

    def coverage(self) -> Tuple[int, int]:
        endpoints_total = len({(m, p) for m, p in self.endpoints})
        endpoints_tested = len({k for k in self.tested_endpoint_keys
                                if any(k == f"{m} {p}" for m, p in self.endpoints)})
        return endpoints_tested, endpoints_total


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------


def assemble_report(agent: Agent, base_url: str, spec_version: str,
                    started_at: float) -> Dict[str, Any]:
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    categories: Dict[str, int] = {}
    for f in agent.findings:
        severities[f.severity] = severities.get(f.severity, 0) + 1
        categories[f.category] = categories.get(f.category, 0) + 1
    tested, total = agent.coverage()
    coverage_percent = (tested / total * 100) if total else 0.0
    return {
        "target": {
            "base_url": base_url,
            "tested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "spec_version": spec_version,
            "agent_name": "BackendTestAgent/1.0",
            "duration_seconds": round(time.time() - started_at, 2),
        },
        "summary": {
            "total": len(agent.findings),
            "by_severity": severities,
            "by_category": categories,
            "endpoints_tested": tested,
            "endpoints_total": total,
            "coverage_percent": round(coverage_percent, 1),
        },
        "findings": [f.to_dict() for f in agent.findings],
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Backend Testing Agent")
    p.add_argument("--base-url", default="https://backend-agent-test.onrender.com")
    p.add_argument("--spec", default=os.path.join(os.path.dirname(__file__), "openapi.json"))
    p.add_argument("--output", default=os.path.join(os.path.dirname(__file__), "report.json"))
    p.add_argument("--log",    default=os.path.join(os.path.dirname(__file__), "agent_log.txt"))
    p.add_argument("--credentials", default="alice:alice123,bob:bob123,carol:carol123",
                   help="Comma-separated user:password seed credentials.")
    p.add_argument("--validate", action="store_true",
                   help="Validate the produced report.json against report.schema.json.")
    p.add_argument("--schema", default=os.path.join(os.path.dirname(__file__), "report.schema.json"))
    args = p.parse_args(argv)

    seeded = []
    for tok in args.credentials.split(","):
        if ":" in tok:
            u, pw = tok.split(":", 1)
            seeded.append((u.strip(), pw.strip()))

    spec = load_spec(args.spec)
    spec_version = spec.get("info", {}).get("version", "unknown")

    started = time.time()
    agent = Agent(args.base_url, args.spec, seeded)
    agent.run()
    report = assemble_report(agent, args.base_url, spec_version, started)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    log(f"Wrote report to {args.output} with {len(agent.findings)} findings")

    with open(args.log, "w", encoding="utf-8") as fh:
        fh.write("\n".join(LOG_LINES))
    log(f"Wrote log to {args.log}")

    if args.validate:
        try:
            import jsonschema  # type: ignore
            with open(args.schema, "r", encoding="utf-8") as fh:
                schema = json.load(fh)
            jsonschema.validate(report, schema)
            log("Schema validation: PASS")
        except Exception as e:
            log(f"Schema validation FAILED: {e}")
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
