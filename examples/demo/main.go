// Command demo logs the same (fake) sensitive data twice: once with a plain
// slog JSON handler and once through go-redact.
//
//	go run ./examples/demo
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/shani8615/go-redact"
)

type User struct {
	ID       int    `json:"id"`
	Email    string `json:"email" redact:"email"`
	Phone    string `json:"phone" redact:"last4"`
	Password string `json:"password"`
}

func main() {
	// Fake values, assembled at runtime so secret scanners don't flag this file.
	apiKey := "sk-" + "proj-" + strings.Repeat("Xy9", 8)
	jwt := "eyJ" + "hbGciOiJIUzI1NiJ9.eyJzdWIiOiI0MiJ9.c2lnbmF0dXJl"
	user := User{ID: 42, Email: "jane.doe@example.com", Phone: "+92 300 1234567", Password: "hunter2"}
	dsn := "postgres://app:s3cr3t@db:5432/orders"
	err := errors.New("upstream 401: invalid key " + apiKey)

	emit := func(title string, h slog.Handler) {
		fmt.Println(title)
		log := slog.New(h)
		log.Info("login", "user", user, "token", jwt)
		log.Error("call failed", "dsn", dsn, "err", err, "card", "4111 1111 1111 1111", "max_tokens", 512)
		fmt.Println()
	}
	noTime := &slog.HandlerOptions{ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
		if a.Key == slog.TimeKey {
			return slog.Attr{}
		}
		return a
	}}

	emit("\033[1m\033[31m✗ plain slog.JSONHandler\033[0m", slog.NewJSONHandler(os.Stdout, noTime))
	emit("\033[1m\033[32m✓ redact.NewHandler(slog.JSONHandler)\033[0m", redact.NewHandler(slog.NewJSONHandler(os.Stdout, noTime), nil))
}
