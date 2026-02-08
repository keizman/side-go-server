package config

import (
	"fmt"
	"strings"
	"testing"
)

func applyValidRequiredEnv(t *testing.T) {
	t.Helper()

	t.Setenv("SERVER_SECRET", strings.Repeat("s", 32))
	t.Setenv("CLIENT_SALT_SECRET", "client-salt")
	t.Setenv("REDIS_CONN_STRING", "redis://default:123456@127.0.0.1:6379/1")
	t.Setenv("INIT_ALLOWED_EXTENSION_IDS", "ext-1, ext-2")
}

func TestLoad(t *testing.T) {
	t.Run("Given SERVER_SECRET is missing When loading config Then panic is raised", func(t *testing.T) {
		t.Setenv("SERVER_SECRET", "")
		t.Setenv("CLIENT_SALT_SECRET", "client-salt")
		t.Setenv("REDIS_CONN_STRING", "redis://default:123456@127.0.0.1:6379/1")
		t.Setenv("INIT_ALLOWED_EXTENSION_IDS", "ext-1")

		defer func() {
			r := recover()
			if r == nil {
				t.Fatalf("expected panic for missing SERVER_SECRET")
			}
			if !strings.Contains(fmt.Sprint(r), "SERVER_SECRET") {
				t.Fatalf("unexpected panic message: %v", r)
			}
		}()

		_ = Load()
	})

	t.Run("Given valid environment values When loading config Then parsed config is available", func(t *testing.T) {
		applyValidRequiredEnv(t)
		t.Setenv("APP_NAME", "bdd-app")
		t.Setenv("SERVICE_MODE", "BUSINESS")
		t.Setenv("PORT", "19090")
		t.Setenv("TOKEN_TTL_SECONDS", "120")
		t.Setenv("TIMESTAMP_TOLERANCE_SECONDS", "30")
		t.Setenv("NONCE_TTL_SECONDS", "40")
		t.Setenv("LIMIT_GUEST_RPM", "15")
		t.Setenv("LIMIT_USER_RPM", "25")
		t.Setenv("INIT_ALLOWED_EXTENSION_IDS", "ext-a, ext-b ,ext-c")

		if err := Load(); err != nil {
			t.Fatalf("expected successful Load, got %v", err)
		}

		if Cfg.AppName != "bdd-app" || Cfg.ServiceMode != "BUSINESS" || Cfg.Port != "19090" {
			t.Fatalf("unexpected basic config: %+v", Cfg)
		}
		if len(Cfg.AllowedExtensionIDs) != 3 {
			t.Fatalf("expected 3 extension IDs, got %v", Cfg.AllowedExtensionIDs)
		}
		if Cfg.AllowedExtensionIDs[1] != "ext-b" {
			t.Fatalf("expected trimmed extension id ext-b, got %q", Cfg.AllowedExtensionIDs[1])
		}
		if Cfg.TokenTTL.Seconds() != 120 || Cfg.TimestampTolerance.Seconds() != 30 || Cfg.NonceTTL.Seconds() != 40 {
			t.Fatalf("unexpected TTL values: token=%v tolerance=%v nonce=%v", Cfg.TokenTTL, Cfg.TimestampTolerance, Cfg.NonceTTL)
		}
	})

	t.Run("Given server secret is too short When loading config Then validation fails", func(t *testing.T) {
		applyValidRequiredEnv(t)
		t.Setenv("SERVER_SECRET", "short-secret")

		err := Load()
		if err == nil {
			t.Fatalf("expected validation error for short server secret")
		}
		if !strings.Contains(err.Error(), "at least 32 bytes") {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("Given extension whitelist is empty When loading config Then validation fails", func(t *testing.T) {
		applyValidRequiredEnv(t)
		t.Setenv("INIT_ALLOWED_EXTENSION_IDS", "")

		err := Load()
		if err == nil {
			t.Fatalf("expected validation error for empty whitelist")
		}
		if !strings.Contains(err.Error(), "INIT_ALLOWED_EXTENSION_IDS") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}
