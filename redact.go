// Package redact keeps secrets and personal data out of your logs.
//
// Wrap any slog.Handler with NewHandler and every record is cleaned before it
// is written:
//
//   - attributes with sensitive keys (password, token, api_key, authorization,
//     cookie, ...) are masked, at any nesting depth;
//   - strings are scanned for secrets — JWTs, bearer tokens, cloud and SaaS
//     API keys, private keys, credentials in URLs — and for card numbers
//     (Luhn-checked) and email addresses;
//   - structs logged with slog.Any honour `redact:"..."` field tags.
//
// The same rules are available without slog through Redactor.String and
// Redactor.Value.
package redact

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"reflect"
	"regexp"
	"strings"
	"time"
)

// Mode is a field-level redaction mode set with the `redact` struct tag.
type Mode string

const (
	ModeNone   Mode = ""       // log normally (strings are still scanned)
	ModeSecret Mode = "secret" // replace with the mask
	ModeEmail  Mode = "email"  // j***@example.com
	ModeLast4  Mode = "last4"  // ****1234
	ModeHash   Mode = "hash"   // hmac:3f2a9c... stable for correlation, not reversible
	ModeOmit   Mode = "-"      // drop the field
)

// Pattern finds sensitive substrings in free text.
type Pattern struct {
	Name    string
	Re      *regexp.Regexp
	Replace func(match string) string // nil: replace with "[REDACTED:<Name>]"
	// Valid filters matches, e.g. a Luhn check for card numbers. nil accepts all.
	Valid func(match string) bool
}

// Options configures a Redactor. The zero value is a good default.
type Options struct {
	Mask           string    // default "[REDACTED]"
	Keys           []string  // extra sensitive attribute keys (matched case- and separator-insensitively)
	Patterns       []Pattern // extra patterns, applied after the built-in ones
	NoDefaultKeys  bool      // don't use the built-in key list
	NoDefaultRules bool      // don't use the built-in patterns
	KeepEmails     bool      // don't mask email addresses found in text
	HashKey        []byte    // HMAC key for ModeHash; random per process if empty
	MaxDepth       int       // nesting limit for structs/groups; default 8
}

// Redactor applies redaction rules. It is safe for concurrent use.
type Redactor struct {
	mask      string
	exactKeys map[string]bool
	subKeys   []string
	patterns  []Pattern
	hashKey   []byte
	maxDepth  int
}

// Keys that mark a value as sensitive when they appear anywhere in an
// attribute key ("db_password", "X-Api-Key", "githubToken").
var defaultSubstringKeys = []string{
	"password", "passwd", "secret", "token", "apikey", "privatekey",
	"authorization", "cookie", "credential", "sessionid", "signature",
}

// Keys that must match exactly (too short to match as substrings).
var defaultExactKeys = []string{"pwd", "pass", "auth", "ssn", "cvv", "cvc", "pin", "otp", "cardnumber", "creditcard", "iban"}

// New returns a Redactor.
func New(o Options) *Redactor {
	r := &Redactor{mask: o.Mask, exactKeys: map[string]bool{}, hashKey: o.HashKey, maxDepth: o.MaxDepth}
	if r.mask == "" {
		r.mask = "[REDACTED]"
	}
	if r.maxDepth <= 0 {
		r.maxDepth = 8
	}
	if len(r.hashKey) == 0 {
		r.hashKey = make([]byte, 32)
		_, _ = rand.Read(r.hashKey)
	}
	if !o.NoDefaultKeys {
		r.subKeys = append(r.subKeys, defaultSubstringKeys...)
		for _, k := range defaultExactKeys {
			r.exactKeys[k] = true
		}
	}
	for _, k := range o.Keys {
		r.exactKeys[normKey(k)] = true
	}
	if !o.NoDefaultRules {
		r.patterns = append(r.patterns, defaultPatterns()...)
		if !o.KeepEmails {
			r.patterns = append(r.patterns, emailPattern)
		}
	}
	r.patterns = append(r.patterns, o.Patterns...)
	return r
}

func normKey(k string) string {
	k = strings.ToLower(k)
	return strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(k)
}

// SensitiveKey reports whether an attribute key names a secret.
func (r *Redactor) SensitiveKey(key string) bool {
	n := normKey(key)
	if r.exactKeys[n] {
		return true
	}
	// Token *counts* (max_tokens, prompt_tokens, token_count) are not secrets.
	if strings.HasSuffix(n, "tokens") || strings.HasSuffix(n, "tokencount") {
		return false
	}
	for _, s := range r.subKeys {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

// String scrubs secrets and PII from free text.
func (r *Redactor) String(s string) string {
	for _, p := range r.patterns {
		if !p.Re.MatchString(s) {
			continue
		}
		s = p.Re.ReplaceAllStringFunc(s, func(m string) string {
			if p.Valid != nil && !p.Valid(m) {
				return m
			}
			if p.Replace != nil {
				return p.Replace(m)
			}
			return "[REDACTED:" + p.Name + "]"
		})
	}
	return s
}

// Apply applies a field Mode to a string value.
func (r *Redactor) Apply(mode Mode, s string) string {
	switch mode {
	case ModeSecret:
		return r.mask
	case ModeEmail:
		return maskEmail(s)
	case ModeLast4:
		return last4(s)
	case ModeHash:
		m := hmac.New(sha256.New, r.hashKey)
		m.Write([]byte(s))
		return "hmac:" + hex.EncodeToString(m.Sum(nil))[:16]
	default:
		return r.String(s)
	}
}

// Attr returns a redacted copy of a.
func (r *Redactor) Attr(a slog.Attr) slog.Attr {
	return r.attr(a, 0)
}

func (r *Redactor) attr(a slog.Attr, depth int) slog.Attr {
	if a.Key != "" && r.SensitiveKey(a.Key) {
		// Mask the whole value, including groups such as "credentials".
		return slog.String(a.Key, r.mask)
	}
	a.Value = r.value(a.Value, depth)
	return a
}

// Value returns a redacted copy of v.
func (r *Redactor) Value(v slog.Value) slog.Value { return r.value(v, 0) }

func (r *Redactor) value(v slog.Value, depth int) slog.Value {
	v = v.Resolve()
	if depth > r.maxDepth {
		return slog.StringValue("[TRUNCATED]")
	}
	switch v.Kind() {
	case slog.KindString:
		return slog.StringValue(r.String(v.String()))
	case slog.KindGroup:
		attrs := v.Group()
		out := make([]slog.Attr, len(attrs))
		for i, a := range attrs {
			out[i] = r.attr(a, depth+1)
		}
		return slog.GroupValue(out...)
	case slog.KindAny:
		return r.anyValue(v.Any(), depth)
	default:
		return v
	}
}

var timeType = reflect.TypeFor[time.Time]()

func (r *Redactor) anyValue(x any, depth int) slog.Value {
	switch t := x.(type) {
	case nil:
		return slog.AnyValue(nil)
	case error:
		return slog.StringValue(r.String(t.Error()))
	case []byte:
		return slog.StringValue(r.String(string(t)))
	case []string:
		out := make([]string, len(t))
		for i, s := range t {
			out[i] = r.String(s)
		}
		return slog.AnyValue(out)
	}
	rv := reflect.ValueOf(x)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return slog.AnyValue(nil)
		}
		rv = rv.Elem()
	}
	switch {
	case rv.Kind() == reflect.Struct && rv.Type() != timeType:
		return slog.GroupValue(r.structAttrs(rv, depth)...)
	case rv.Kind() == reflect.Map && rv.Type().Key().Kind() == reflect.String:
		attrs := make([]slog.Attr, 0, rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			attrs = append(attrs, r.attr(slog.Any(iter.Key().String(), iter.Value().Interface()), depth+1))
		}
		return slog.GroupValue(attrs...)
	case rv.Kind() == reflect.String:
		return slog.StringValue(r.String(rv.String()))
	}
	return slog.AnyValue(x)
}

func (r *Redactor) structAttrs(rv reflect.Value, depth int) []slog.Attr {
	t := rv.Type()
	attrs := make([]slog.Attr, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := f.Name
		if tag := f.Tag.Get("json"); tag != "" {
			n, _, _ := strings.Cut(tag, ",")
			if n == "-" {
				continue
			}
			if n != "" {
				name = n
			}
		}
		mode := Mode(f.Tag.Get("redact"))
		fv := rv.Field(i)
		switch mode {
		case ModeOmit:
			continue
		case ModeNone:
			attrs = append(attrs, r.attr(slog.Any(name, fv.Interface()), depth+1))
		default:
			s := ""
			if fv.Kind() == reflect.String {
				s = fv.String()
			} else if fv.Kind() == reflect.Pointer && !fv.IsNil() && fv.Elem().Kind() == reflect.String {
				s = fv.Elem().String()
			} else if mode != ModeSecret {
				mode = ModeSecret // non-string with a partial mode: fail closed
			}
			attrs = append(attrs, slog.String(name, r.Apply(mode, s)))
		}
	}
	return attrs
}

// ---- slog.Handler ----

// Handler redacts records before passing them to the wrapped handler.
type Handler struct {
	next slog.Handler
	r    *Redactor
}

// NewHandler wraps next. A nil r uses New(Options{}).
func NewHandler(next slog.Handler, r *Redactor) *Handler {
	if r == nil {
		r = New(Options{})
	}
	return &Handler{next: next, r: r}
}

func (h *Handler) Enabled(ctx context.Context, l slog.Level) bool { return h.next.Enabled(ctx, l) }

func (h *Handler) Handle(ctx context.Context, rec slog.Record) error {
	out := slog.NewRecord(rec.Time, rec.Level, h.r.String(rec.Message), rec.PC)
	rec.Attrs(func(a slog.Attr) bool {
		out.AddAttrs(h.r.Attr(a))
		return true
	})
	return h.next.Handle(ctx, out)
}

func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	red := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		red[i] = h.r.Attr(a)
	}
	return &Handler{next: h.next.WithAttrs(red), r: h.r}
}

func (h *Handler) WithGroup(name string) slog.Handler {
	return &Handler{next: h.next.WithGroup(name), r: h.r}
}
