package database

import (
	"os"
	"strings"
	"testing"
	"time"
)

func testDatabaseURL() string {
	if v := strings.TrimSpace(os.Getenv("SIDE_GO_SERVER_TEST_DATABASE_URL")); v != "" {
		return ensureDisableSSL(v)
	}
	if v := strings.TrimSpace(os.Getenv("DATABASE_URL")); v != "" {
		return ensureDisableSSL(v)
	}
	return ""
}

func ensureDisableSSL(url string) string {
	if url == "" || strings.Contains(url, "sslmode=") {
		return url
	}
	if strings.Contains(url, "?") {
		return url + "&sslmode=disable"
	}
	return url + "?sslmode=disable"
}

func TestInitDB(t *testing.T) {
	t.Run("Given unreachable postgres endpoint When InitDB called Then returns error", func(t *testing.T) {
		err := InitDB("postgresql://postgres:postgres@127.0.0.1:1/postgres?connect_timeout=1&sslmode=disable", 1, 1, time.Second)
		if err == nil {
			t.Fatalf("expected InitDB to fail for unreachable endpoint")
		}
	})

	t.Run("Given reachable postgres endpoint When InitDB called Then connection is established", func(t *testing.T) {
		dbURL := testDatabaseURL()
		if dbURL == "" {
			t.Skip("integration db url not provided")
		}

		if err := InitDB(dbURL, 5, 5, time.Minute); err != nil {
			t.Skipf("integration db unavailable: %v", err)
		}
		t.Cleanup(func() {
			_ = Close()
		})

		if DB == nil {
			t.Fatalf("expected global DB to be initialized")
		}
		if err := DB.Ping(); err != nil {
			t.Fatalf("expected ping to succeed, got %v", err)
		}
	})
}

func TestClose(t *testing.T) {
	t.Run("Given nil DB When Close called Then no error", func(t *testing.T) {
		DB = nil
		if err := Close(); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})
}
