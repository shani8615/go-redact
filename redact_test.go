package redact

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// Fake credentials are assembled at runtime so secret scanners don't flag
// this file. None of them are real.
var (
	fakeAWS    = "AKIA" + "ABCDEFGHIJKLMNOP"
	fakeGitHub = "ghp" + "_" + strings.Repeat("a1B2", 9)
	fakeOpenAI = "sk-" + "proj-" + strings.Repeat("x9Y8", 6)
	fakeJWT    = "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiIxMjMifQ" + "." + "c2lnbmF0dXJlLXZhbHVl"
	fakeSlack  = "xox" + "b-" + "123456789012-abcdefghij"
	testCard   = "4111 1111 1111 1111" // Visa test number, passes Luhn
	notCard    = "4111 1111 1111 1112" // fails Luhn
)

func logTo(r *Redactor) (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(NewHandler(slog.NewJSONHandler(&buf, nil), r)), &buf
}

func TestSensitiveKeys(t *testing.T) {
	r := New(Options{Keys: []string{"x-internal-ref"}})
	for _, k := range []string{"password", "DB_PASSWORD", "apiKey", "X-Api-Key", "github_token", "Authorization",
		"set-cookie", "client_secret", "ssn", "pin", "X-Internal-Ref"} {
		if !r.SensitiveKey(k) {
			t.Errorf("%q should be sensitive", k)
		}
	}
	for _, k := range []string{"user_id", "author", "max_tokens", "prompt_tokens", "token_count", "status", "spinner"} {
		if r.SensitiveKey(k) {
			t.Errorf("%q should not be sensitive", k)
		}
	}
}

func TestStringPatterns(t *testing.T) {
	r := New(Options{})
	cases := []struct{ in, mustNotContain, mustContain string }{
		{"aws key " + fakeAWS, fakeAWS, "[REDACTED:aws_access_key]"},
		{"token=" + fakeGitHub, fakeGitHub, "[REDACTED:github_token]"},
		{"using " + fakeOpenAI + " now", fakeOpenAI, "[REDACTED:api_key]"},
		{"jwt " + fakeJWT, fakeJWT, "[REDACTED:jwt]"},
		{"slack " + fakeSlack, fakeSlack, "[REDACTED:slack_token]"},
		{"Authorization: Bearer abcdefgh12345678", "abcdefgh12345678", "Bearer [REDACTED]"},
		{"postgres://app:hunter2@db:5432/x", "hunter2", "postgres://[REDACTED]@db:5432/x"},
		{"card " + testCard + " ok", "4111 1111 1111 1111", "****1111"},
		{"mail jane.doe@example.com", "jane.doe@", "j***@example.com"},
		{"-----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY-----", "MIIabc", "[REDACTED:private_key]"},
	}
	for _, c := range cases {
		got := r.String(c.in)
		if strings.Contains(got, c.mustNotContain) || !strings.Contains(got, c.mustContain) {
			t.Errorf("String(%.30q) = %q", c.in, got)
		}
	}
	// No false positives on ordinary values.
	for _, s := range []string{"order 1234567890123 shipped", "card " + notCard, "2026-11-25T10:00:00Z", "skip-this-step"} {
		if got := r.String(s); got != s {
			t.Errorf("false positive: %q -> %q", s, got)
		}
	}
	if got := New(Options{KeepEmails: true}).String("a@b.io"); got != "a@b.io" {
		t.Errorf("KeepEmails: %q", got)
	}
}

type User struct {
	ID       int     `json:"id"`
	Email    string  `json:"email" redact:"email"`
	Phone    string  `json:"phone" redact:"last4"`
	Password string  `json:"password"` // caught by key name
	APIKey   string  `json:"-"`
	Session  string  `json:"session" redact:"secret"`
	Customer string  `json:"customer" redact:"hash"`
	Internal string  `json:"internal" redact:"-"`
	Note     string  `json:"note"`
	Manager  *User   `json:"manager,omitempty"`
	Balance  float64 `json:"balance" redact:"last4"` // non-string partial mode: fail closed
}

func TestStructTagsThroughHandler(t *testing.T) {
	log, buf := logTo(New(Options{HashKey: []byte("k")}))
	u := User{ID: 7, Email: "jane@example.com", Phone: "+92 300 1234567", Password: "hunter2", APIKey: "nope",
		Session: "s3ss10n", Customer: "cust-42", Internal: "drop me", Note: "key " + fakeAWS, Balance: 99.5,
		Manager: &User{ID: 1, Email: "boss@example.com", Password: "boss-pw"}}
	log.Info("login", "user", u)
	out := buf.String()

	for _, leaked := range []string{"jane@example.com", "1234567\"", "hunter2", "nope", "s3ss10n", "cust-42",
		"drop me", fakeAWS, "boss-pw", "boss@example.com", "99.5"} {
		if strings.Contains(out, leaked) {
			t.Errorf("leaked %q in %s", leaked, out)
		}
	}
	for _, want := range []string{`"id":7`, `"email":"j***@example.com"`, `"phone":"****4567"`, `"password":"[REDACTED]"`,
		`"session":"[REDACTED]"`, `"customer":"hmac:`, `"manager":{"id":1`, `"balance":"[REDACTED]"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
}

func TestHashIsStableAndKeyed(t *testing.T) {
	a := New(Options{HashKey: []byte("k1")})
	b := New(Options{HashKey: []byte("k2")})
	first, second := a.Apply(ModeHash, "x"), a.Apply(ModeHash, "x")
	if first != second || first == b.Apply(ModeHash, "x") {
		t.Fatal("hash must be stable per key and differ across keys")
	}
}

func TestHandlerCoversMessageGroupsWithAttrsAndErrors(t *testing.T) {
	log, buf := logTo(nil)
	log = log.With("api_key", "abc123", slog.Group("db", "dsn", "mysql://root:toor@db/app")).WithGroup("req")
	log.Error("call failed for jane@example.com",
		"err", errors.New("upstream said: invalid "+fakeOpenAI),
		slog.Group("headers", "Authorization", "Bearer abcdefgh12345678", "Accept", "json"),
		"credentials", map[string]any{"user": "u", "pass": "p"},
		"max_tokens", 512,
	)
	out := buf.String()
	for _, leaked := range []string{"abc123", "toor", "jane@", fakeOpenAI, "abcdefgh12345678", `"pass":"p"`} {
		if strings.Contains(out, leaked) {
			t.Errorf("leaked %q in %s", leaked, out)
		}
	}
	for _, want := range []string{`"api_key":"[REDACTED]"`, `"Accept":"json"`, `"credentials":"[REDACTED]"`, `"max_tokens":512`, `"msg":"call failed for j***@example.com"`} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in %s", want, out)
		}
	}
}

func TestDepthLimit(t *testing.T) {
	type N struct {
		Next *N `json:"next"`
	}
	n := &N{}
	n.Next = n // cycle
	log, buf := logTo(New(Options{MaxDepth: 3}))
	log.Info("cycle", "n", n) // must terminate
	if !strings.Contains(buf.String(), "[TRUNCATED]") {
		t.Fatalf("out=%s", buf.String())
	}
}

func TestEnabledDelegates(t *testing.T) {
	h := NewHandler(slog.NewTextHandler(&bytes.Buffer{}, &slog.HandlerOptions{Level: slog.LevelWarn}), nil)
	if h.Enabled(context.Background(), slog.LevelInfo) || !h.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("Enabled must follow the wrapped handler")
	}
}
