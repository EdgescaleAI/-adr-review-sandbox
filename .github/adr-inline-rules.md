# Inline ADRs for the sandbox test

This sandbox does not call the EdgescaleAI Engine API. Instead, the
workflow feeds these five rules into the Claude prompt directly so
validations can run without AUTH0 credentials or the engine being
reachable.

Keep this list short. The goal is to exercise the workflow's plumbing,
not to cover every real ADR.

## Rules

### adr-0001: no plaintext secrets in committed files
Any token, password, API key, or client secret committed as a literal
string value (not a placeholder, not a secret-manager reference) is a
violation. Allowed: placeholders like `your-xxx-here`, empty values,
comments explaining the field.

### adr-0002: HTTPS only (no `http://` for remote calls)
Any outbound HTTP call must use `https://`. `http://localhost` and
`http://127.0.0.1` are allowed. Comments / docstrings / example URLs
inside explicit "example" blocks are allowed.

### adr-0003: no hardcoded credentials or tokens in source
Like adr-0001 but specifically about variables named `*_TOKEN`,
`*_KEY`, `*_PASSWORD`, `*_SECRET`, `ACCESS_KEY`, `AWS_*_ACCESS`, or
similar patterns. Any assignment of such a variable to a non-empty,
non-placeholder literal is a violation.

### adr-0004: direct state-changing calls without validation
Calls that mutate external state (HTTP POST/PUT/DELETE, `curl -X POST`
to an API, `kubectl apply` of a manifest containing secrets) that
lack preceding validation/guard logic (try/catch, error handling,
sanity-check `if` blocks). Pure manifests are fine — this targets
scripts that make mutating calls.

### adr-0005: append-only logs, no truncating writes
Shell redirects that overwrite audit/log files with `>` are violations
if the path names `log`, `audit`, or `history`. Use `>>` (append) or
timestamped per-run files instead.
