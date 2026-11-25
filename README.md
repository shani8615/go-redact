# go-redact

[![ci](https://github.com/shani8615/go-redact/actions/workflows/ci.yml/badge.svg)](https://github.com/shani8615/go-redact/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/shani8615/go-redact.svg)](https://pkg.go.dev/github.com/shani8615/go-redact)

**Keep secrets and personal data out of your logs.** A `log/slog` handler that cleans every record before it's written. It has no dependencies outside the standard library.

```bash
go get github.com/shani8615/go-redact
```

```go
logger := slog.New(redact.NewHandler(slog.NewJSONHandler(os.Stdout, nil), nil))

logger.Error("call failed for jane@example.com",
    "api_key", key,                                   // → "[REDACTED]"
    "dsn", "postgres://app:hunter2@db:5432/orders",   // → "postgres://[REDACTED]@db:5432/orders"
    "err", err,                                       // tokens inside error text are scrubbed
    "max_tokens", 512,                                // left alone: it's a count, not a secret
)
// {"msg":"call failed for j***@example.com", "api_key":"[REDACTED]", ...}
```

## What gets redacted

**1. Sensitive keys, at any depth.** Matching ignores case and `_`/`-`/`.`, so `password`, `DB_PASSWORD`, `X-Api-Key`, `githubToken`, `Authorization`, `set-cookie` and `client_secret` all match, inside groups and maps too. Add your own keys with `Options.Keys`.

**2. Secrets in free text.** Log messages, string values and error messages are scanned for:

| Pattern | Example output |
|---|---|
| JWT | `[REDACTED:jwt]` |
| `Bearer` / `Basic` credentials | `Bearer [REDACTED]` |
| Credentials in URLs / DSNs | `postgres://[REDACTED]@db/app` |
| AWS access keys, GitHub tokens, `sk-…` API keys (OpenAI, Anthropic), Slack, Google, Stripe | `[REDACTED:github_token]` |
| PEM private keys | `[REDACTED:private_key]` |
| Card numbers (**Luhn-checked**, so order IDs survive) | `****1111` |
| Email addresses (turn off with `KeepEmails`) | `j***@example.com` |

**3. Struct field tags,** for anything logged with `slog.Any`:

```go
type User struct {
    ID       int    `json:"id"`
    Email    string `json:"email"    redact:"email"`  // j***@example.com
    Phone    string `json:"phone"    redact:"last4"`  // ****4567
    Session  string `json:"session"  redact:"secret"` // [REDACTED]
    Customer string `json:"customer" redact:"hash"`   // hmac:3f2a9c… (stable, for correlating logs)
    Internal string `json:"internal" redact:"-"`      // dropped
}
logger.Info("login", "user", u)
```

Partial modes (`email`, `last4`) on non-string fields fail closed to `[REDACTED]`. `hash` uses HMAC-SHA256 with `Options.HashKey`. If you don't set one, a random key is created per process, so hashes can't be reversed with a dictionary.

## Without slog

```go
r := redact.New(redact.Options{})
safe := r.String(untrustedText)   // e.g. before storing an LLM prompt or an error in an audit table
```

## Custom rules

```go
r := redact.New(redact.Options{
    Keys: []string{"tenant_secret"},
    Patterns: []redact.Pattern{{
        Name: "internal_id",
        Re:   regexp.MustCompile(`\bEMP-\d{6}\b`),
    }},
})
logger := slog.New(redact.NewHandler(base, r))
```

## Notes

- Redaction is defense in depth. It catches mistakes, but it is no excuse to log secrets on purpose.
- Patterns run on every string value. In very hot logging paths, log fewer free-text fields instead of turning rules off.
- Cyclic or very deep structures are cut off at `MaxDepth` (default 8) with `[TRUNCATED]`.

## License

MIT
