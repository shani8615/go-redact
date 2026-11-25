package redact

import (
	"regexp"
	"strings"
)

func defaultPatterns() []Pattern {
	return []Pattern{
		{
			Name: "private_key",
			Re:   regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
		},
		{
			Name: "jwt",
			Re:   regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`),
		},
		{
			Name: "bearer",
			Re:   regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`),
			Replace: func(m string) string {
				scheme, _, _ := strings.Cut(m, " ")
				return scheme + " [REDACTED]"
			},
		},
		{
			Name: "url_credentials",
			Re:   regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@`),
			Replace: func(m string) string {
				i := strings.Index(m, "://")
				return m[:i+3] + "[REDACTED]@"
			},
		},
		{Name: "aws_access_key", Re: regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)},
		{Name: "github_token", Re: regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b`)},
		{Name: "api_key", Re: regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}`)},
		{Name: "slack_token", Re: regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`)},
		{Name: "google_api_key", Re: regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
		{Name: "stripe_key", Re: regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{16,}\b`)},
		{
			Name:    "card_number",
			Re:      regexp.MustCompile(`\b(?:\d[ -]?){12,18}\d\b`),
			Valid:   luhn,
			Replace: last4,
		},
	}
}

var emailPattern = Pattern{
	Name:    "email",
	Re:      regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`),
	Replace: maskEmail,
}

// luhn validates card numbers so order IDs and timestamps aren't masked.
func luhn(s string) bool {
	sum, n, double := 0, 0, false
	for i := len(s) - 1; i >= 0; i-- {
		c := s[i]
		if c == ' ' || c == '-' {
			continue
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
		n++
	}
	return n >= 13 && n <= 19 && sum%10 == 0
}

// maskEmail keeps the first character and the domain: j***@example.com.
func maskEmail(s string) string {
	local, domain, ok := strings.Cut(s, "@")
	if !ok || local == "" {
		return "[REDACTED:email]"
	}
	return local[:1] + "***@" + domain
}

// last4 keeps the last four digits/characters: ****1234.
func last4(s string) string {
	var digits []rune
	for _, r := range s {
		if r != ' ' && r != '-' {
			digits = append(digits, r)
		}
	}
	if len(digits) <= 4 {
		return "****"
	}
	return "****" + string(digits[len(digits)-4:])
}
