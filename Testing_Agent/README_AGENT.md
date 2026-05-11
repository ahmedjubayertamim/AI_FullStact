# Backend Testing Agent

Black-box tester for the **Mini Social API**. The agent takes a base URL, an
OpenAPI spec, and seed credentials, then probes the live API for bugs across
all 14 exam categories and emits a `report.json` that validates against
`report.schema.json`.

## Quick start

```bash
pip install -r requirements.txt
python3 agent.py \
  --base-url https://backend-agent-test.onrender.com \
  --spec     openapi.json \
  --output   report.json \
  --log      agent_log.txt \
  --validate
```

The `--validate` flag re-validates the produced `report.json` against
`report.schema.json` before exiting.

## Inputs

| Flag | Default | Meaning |
|---|---|---|
| `--base-url` | `https://backend-agent-test.onrender.com` | API root |
| `--spec` | `openapi.json` | OpenAPI 3 spec for the API |
| `--credentials` | `alice:alice123,bob:bob123,carol:carol123` | Seeded test users |
| `--output` | `report.json` | Where to write the final report |
| `--log` | `agent_log.txt` | Plain-text request/response log |
| `--schema` | `report.schema.json` | JSON Schema used by `--validate` |

The agent tries the seed credentials first; if any account fails to log in
(because the shared infrastructure has been mutated by other examinees) it
falls back to registering a UUID-suffixed account so a clean run is always
possible.

## How it works

1. **Bootstrap** — login or register-and-login three test users (Alice, Bob,
   Carol). Each user's `id` is discovered by GET /users/me.
2. **Probe phases** — twelve probe groups, each emitting `Finding` objects:
   - `probe_headers_cors`     → missing security headers, CORS misconfig
   - `probe_endpoint_existence` → undocumented endpoints (`/admin`, `/.env`, …)
   - `probe_status_and_schema` → 201 vs 200, response shape vs OpenAPI
   - `probe_authentication`   → unauth access, bad bearer, logout invalidation,
                                 username enumeration
   - `probe_authorization_and_logic` → IDOR on PATCH/DELETE posts, mass
                                 assignment for role/email, follow-self,
                                 like-twice, ghost-post operations
   - `probe_input_validation` → empty/oversize/wrong-type payloads, negative
                                 ages, negative pagination
   - `probe_error_handling`   → malformed JSON 5xx, form-encoded body,
                                 inconsistent error envelopes
   - `probe_rate_limiting`    → bursted failed-login attempts
   - `probe_performance`      → unbounded `limit`, login latency, caching
                                 headers
   - `probe_http_protocol`    → OPTIONS preflight reflection, HEAD support,
                                 PUT on POST-only routes
   - `probe_documentation_drift` → spec disagreements (security scheme,
                                 missing requestBody, framework defaults
                                 like `/docs`, `/redoc`)
   - `probe_consistency`      → list vs detail field-set drift, type drift
                                 (e.g. `like_count` string vs int), naming
                                 inconsistencies (`author` vs `authorName`)
3. **Report assembly** — counts findings by severity and category, computes
   endpoint coverage, writes `report.json`.

Every HTTP request goes through one helper that captures the request,
response, latency, and headers. Each `Finding` references those bytes verbatim
in its `evidence` block, so the report is self-contained.

## Output

`report.json` matches the supplied schema and includes:

- `target` — base URL, ISO-8601 timestamp, spec version, duration
- `summary` — totals by severity and category, endpoint coverage
- `findings[]` — id, category, severity, endpoint, method, title,
  description, evidence (request + response), reproduction, expected,
  actual, optional `spec_reference` and `suggested_fix`

`agent_log.txt` is a chronological transcript of every request the agent
issued (one line per request). Authorization headers are redacted.

## Reproducibility

The run is deterministic modulo response-time variance and shared-state
effects on the live target. All endpoint discovery uses GET requests; no IDs
are hard-coded. The fallback-registration path uses UUID suffixes so two runs
do not collide.

## Reliability notes

- The rate-limiting probe is a *short* burst (20 concurrent requests) — well
  inside the README's "be polite" guideline.
- Mutating probes (PATCH /users/me with `role: admin`, IDOR DELETE on Alice's
  post, etc.) only run against agent-owned accounts created during bootstrap.
- The schema validator (`jsonschema`) is invoked when `--validate` is passed;
  the run exits non-zero if `report.json` does not match `report.schema.json`.
