// Command example shows the basics of the Casdoor Go SDK: configuration
// from the environment, health, an authenticated ping and error handling.
//
//	GROW_CASDOOR_URL=http://127.0.0.1:8000 GROW_CASDOOR_TOKEN=... go run .
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	casdoor "github.com/grow-codes-packages/casdoor/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := casdoor.ConfigFromEnv()
	if err != nil {
		return err // CONFIG error naming the variable, never its value
	}
	cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	cfg.Hooks = &casdoor.Hooks{
		OnError: func(info casdoor.ErrorInfo) {
			if info.WillRetry {
				fmt.Fprintf(os.Stderr, "retrying %s %s (attempt %d)\n", info.Method, info.URL, info.Attempt)
			}
		},
	}
	fmt.Println("config:", cfg) // credentials print as [REDACTED]

	client, err := casdoor.NewClient(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	health, err := client.Health(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("health: healthy=%t status=%s\n", health.Healthy, health.Status)

	latency, err := client.Ping(ctx)
	switch {
	case errors.Is(err, casdoor.ErrAuthentication):
		return fmt.Errorf("check GROW_CASDOOR_TOKEN: %w", err)
	case err != nil:
		return err
	}
	fmt.Println("ping:", latency)

	version, err := client.ServerVersion(ctx)
	switch {
	case errors.Is(err, casdoor.ErrUnsupported):
		fmt.Println("server version: not exposed")
	case err != nil:
		return err
	default:
		fmt.Println("server version:", version)
	}
	return nil
}
