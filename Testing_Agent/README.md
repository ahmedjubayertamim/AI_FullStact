# Backend Testing Agent — Exam

## Your Task

Build an **agent** that performs **black-box testing** of the live REST API at the
URL provided to you, and produces a single `report.json` file describing the bugs
your agent finds.

You have **3 days** from the time you receive this bundle.

## What You Receive

| File | Purpose |
|---|---|
| `README.md` | This file |
| `openapi.json` | The OpenAPI 3 spec for the API under test |
| `report.schema.json` | JSON Schema your `report.json` must validate against |

**Base URL:** `https://backend-agent-test.onrender.com`

## Test accounts

- `alice` / `alice123`
- `bob` / `bob123`
- `carol` / `carol123`

Login: `POST /auth/login` with `{"username": "...", "password": "..."}` → returns `{"access_token": "..."}`. Use as `Authorization: Bearer <token>`.

## What You Must Build

An autonomous agent (in any language / framework you like) that:

1. Takes as input: a base URL, an OpenAPI spec, and credentials
2. Probes the API to discover bugs
3. Emits a `report.json` file matching `report.schema.json`

Your agent should be **reproducible** — running it again should produce the same
findings (allowing for response-time variance).

## Bug Categories You Should Consider

Your agent should look for issues in any of the following 14 categories. Not all
categories necessarily contain bugs. Each finding in your report MUST use one of
these category strings:

| Category | What to look for |
|---|---|
| `status_code` | Wrong HTTP status code returned |
| `schema_contract` | Response shape/types don't match the OpenAPI spec |
| `endpoint_existence` | Documented endpoint missing, or undocumented endpoint exists |
| `input_validation` | Bad input (wrong type, out of range, missing required) not properly rejected |
| `authentication` | Auth not enforced where it should be, or broken |
| `authorization` | IDOR, privilege escalation, mass assignment |
| `error_handling` | Stack traces leaked, inconsistent error formats, internal errors exposed |
| `headers_cors` | Missing security headers, CORS misconfiguration, info disclosure headers |
| `rate_limiting` | No rate limit, or weak/bypassable rate limit on sensitive endpoints |
| `business_logic` | Invalid state transitions, logic flaws (e.g., follow-yourself, double-spend) |
| `consistency` | Same field named differently across endpoints, response shape varies |
| `performance` | Slow responses, no caching, oversize payloads |
| `documentation_drift` | Spec says X, API does Y |
| `http_protocol` | OPTIONS/HEAD/Accept-header issues |

## Deliverable

A single file:

```
report.json
```

It must:

- Validate against `report.schema.json`
- Be UTF-8 JSON
- Contain at least 1 finding (if your agent finds none, you're not testing hard enough)

You must also include:

- The source code of your agent (required)

You may optionally include:

- `agent_log.txt` — a plain-text log of the requests your agent made

## Submission

Push **both** `report.json` **and your agent's source code** to a **private** GitHub repo and add the following collaborators:

- `dibbo@sharif.com`
- `farzana@sharif.com`

Then share the repo link. Submission is due **3 days after the bundle is delivered**.

## Notes

- The API resets its state on each deploy. If you need a clean slate, just keep testing — your run is your responsibility.
- `DELETE` operations and `PATCH` operations CAN modify state on the live target. Use the seeded test accounts.
- Be polite — don't run sustained 1000-rps load tests; you can demonstrate rate-limit issues with a brief burst.

## Shared infrastructure

The API is shared across multiple examinees. Use unique usernames (UUID suffix) when registering, and discover state via GET requests rather than hardcoding IDs.

Good luck.
