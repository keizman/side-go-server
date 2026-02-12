package repository

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yourname/side-go-server/internal/database"
	"github.com/yourname/side-go-server/models"
)

func integrationDatabaseURL() string {
	if v := strings.TrimSpace(os.Getenv("SIDE_GO_SERVER_TEST_DATABASE_URL")); v != "" {
		return normalizePostgresURL(v)
	}
	return normalizePostgresURL(strings.TrimSpace(os.Getenv("DATABASE_URL")))
}

func normalizePostgresURL(raw string) string {
	if raw == "" || strings.Contains(raw, "sslmode=") {
		return raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		if strings.Contains(raw, "?") {
			return raw + "&sslmode=disable"
		}
		return raw + "?sslmode=disable"
	}

	query := parsed.Query()
	query.Set("sslmode", "disable")
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func setupRepositoryIntegrationDB(t *testing.T) {
	t.Helper()

	dbURL := integrationDatabaseURL()
	if dbURL == "" {
		t.Skip("integration db url not provided; set SIDE_GO_SERVER_TEST_DATABASE_URL or DATABASE_URL")
	}

	if err := database.InitDB(dbURL, 5, 5, time.Minute); err != nil {
		t.Skipf("integration db unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = database.Close()
	})

	if err := ensureUsersSchema(); err != nil {
		t.Fatalf("failed to ensure users schema: %v", err)
	}
}

func ensureUsersSchema() error {
	schemaPath := filepath.Join("..", "all.sql")
	schemaBytes, err := os.ReadFile(schemaPath)
	if err == nil {
		if _, execErr := database.DB.Exec(string(schemaBytes)); execErr == nil {
			return nil
		}
	}

	fallback := `
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    display_name VARCHAR(100),
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    tier SMALLINT NOT NULL DEFAULT 2,
    status VARCHAR(20) NOT NULL DEFAULT 'active',
    register_ip INET,
    request_count BIGINT NOT NULL DEFAULT 0,
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip INET,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    email_verified_at TIMESTAMP WITH TIME ZONE,
    deleted_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT chk_users_tier_1_2_3 CHECK (tier IN (1, 2, 3))
);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_tier ON users(tier);
`
	_, err = database.DB.Exec(fallback)
	return err
}

func cleanupUsersByPrefix(t *testing.T, prefix string) {
	t.Helper()
	_, err := database.DB.Exec(`DELETE FROM users WHERE username LIKE $1 OR email LIKE $2`, prefix+"%", prefix+"%")
	if err != nil {
		t.Fatalf("cleanup failed: %v", err)
	}
}

func newTestUser(prefix string) *models.User {
	return &models.User{
		Username:      prefix + "_user",
		Email:         prefix + "@example.com",
		DisplayName:   sql.NullString{String: "BDD User", Valid: true},
		Role:          "user",
		Tier:          2,
		Status:        "active",
		RegisterIP:    sql.NullString{String: "127.0.0.1", Valid: true},
		RequestCount:  0,
		EmailVerified: false,
	}
}

func TestUserRepositoryIntegration(t *testing.T) {
	setupRepositoryIntegrationDB(t)
	repo := NewUserRepository()

	t.Run("Given a new user When CreateUser and lookup APIs are used Then user can be retrieved and password is verifiable", func(t *testing.T) {
		prefix := fmt.Sprintf("bdd_repo_lookup_%d", time.Now().UnixNano())
		cleanupUsersByPrefix(t, prefix)
		t.Cleanup(func() { cleanupUsersByPrefix(t, prefix) })

		user := newTestUser(prefix)
		if err := repo.CreateUser(user, "Passw0rd!"); err != nil {
			t.Fatalf("create user failed: %v", err)
		}
		if user.ID <= 0 {
			t.Fatalf("expected user id > 0, got %d", user.ID)
		}

		byName, err := repo.GetUserByUsername(user.Username)
		if err != nil {
			t.Fatalf("GetUserByUsername failed: %v", err)
		}
		if byName.Email != user.Email {
			t.Fatalf("expected email %s, got %s", user.Email, byName.Email)
		}

		byEmail, err := repo.GetUserByEmail(user.Email)
		if err != nil {
			t.Fatalf("GetUserByEmail failed: %v", err)
		}
		if byEmail.Username != user.Username {
			t.Fatalf("expected username %s, got %s", user.Username, byEmail.Username)
		}

		byEither, err := repo.GetUserByUsernameOrEmail(user.Email)
		if err != nil {
			t.Fatalf("GetUserByUsernameOrEmail failed: %v", err)
		}
		if err := repo.VerifyPassword(byEither.PasswordHash, "Passw0rd!"); err != nil {
			t.Fatalf("VerifyPassword expected success, got %v", err)
		}
		if err := repo.VerifyPassword(byEither.PasswordHash, "wrong-password"); err == nil {
			t.Fatalf("VerifyPassword expected error for wrong password")
		}
	})

	t.Run("Given existing user When usage stats are updated Then last login and request count are persisted", func(t *testing.T) {
		prefix := fmt.Sprintf("bdd_repo_usage_%d", time.Now().UnixNano())
		cleanupUsersByPrefix(t, prefix)
		t.Cleanup(func() { cleanupUsersByPrefix(t, prefix) })

		user := newTestUser(prefix)
		if err := repo.CreateUser(user, "Passw0rd!"); err != nil {
			t.Fatalf("create user failed: %v", err)
		}

		if err := repo.UpdateLastLogin(user.ID, "127.0.0.2"); err != nil {
			t.Fatalf("UpdateLastLogin failed: %v", err)
		}
		if err := repo.IncrementRequestCount(user.ID); err != nil {
			t.Fatalf("IncrementRequestCount #1 failed: %v", err)
		}
		if err := repo.IncrementRequestCount(user.ID); err != nil {
			t.Fatalf("IncrementRequestCount #2 failed: %v", err)
		}

		var count int64
		var lastLoginAt sql.NullTime
		var lastLoginIP sql.NullString
		err := database.DB.QueryRow(`SELECT request_count, last_login_at, last_login_ip FROM users WHERE id = $1`, user.ID).Scan(&count, &lastLoginAt, &lastLoginIP)
		if err != nil {
			t.Fatalf("query updated fields failed: %v", err)
		}

		if count != 2 {
			t.Fatalf("expected request_count=2, got %d", count)
		}
		if !lastLoginAt.Valid {
			t.Fatalf("expected last_login_at to be set")
		}
		if !lastLoginIP.Valid || lastLoginIP.String != "127.0.0.2" {
			t.Fatalf("expected last_login_ip=127.0.0.2, got %+v", lastLoginIP)
		}
	})

	t.Run("Given unique admin identity When CreateDefaultAdmin is called twice Then admin is created once and remains active", func(t *testing.T) {
		prefix := fmt.Sprintf("bdd_repo_admin_%d", time.Now().UnixNano())
		cleanupUsersByPrefix(t, prefix)
		t.Cleanup(func() { cleanupUsersByPrefix(t, prefix) })

		adminUsername := prefix + "_admin"
		adminEmail := prefix + "_admin@example.com"
		adminPassword := "AdminPassw0rd!"

		if err := repo.CreateDefaultAdmin(adminUsername, adminPassword, adminEmail); err != nil {
			t.Fatalf("first CreateDefaultAdmin failed: %v", err)
		}
		if err := repo.CreateDefaultAdmin(adminUsername, adminPassword, adminEmail); err != nil {
			t.Fatalf("second CreateDefaultAdmin failed: %v", err)
		}

		var rowCount int
		var role, status string
		err := database.DB.QueryRow(`SELECT COUNT(*), MIN(role), MIN(status) FROM users WHERE username = $1 AND email = $2`, adminUsername, adminEmail).Scan(&rowCount, &role, &status)
		if err != nil {
			t.Fatalf("query admin row failed: %v", err)
		}
		if rowCount != 1 {
			t.Fatalf("expected exactly 1 admin row, got %d", rowCount)
		}
		if role != "admin" || status != "active" {
			t.Fatalf("unexpected admin role/status: role=%s status=%s", role, status)
		}

		exists, err := repo.UserExists(adminUsername, "unused@example.com")
		if err != nil {
			t.Fatalf("UserExists by username failed: %v", err)
		}
		if !exists {
			t.Fatalf("expected UserExists=true for created admin username")
		}

		exists, err = repo.UserExists("unused-user", adminEmail)
		if err != nil {
			t.Fatalf("UserExists by email failed: %v", err)
		}
		if !exists {
			t.Fatalf("expected UserExists=true for created admin email")
		}
	})

	t.Run("Given unknown identities When lookup methods are called Then not found errors are returned", func(t *testing.T) {
		prefix := fmt.Sprintf("bdd_repo_missing_%d", time.Now().UnixNano())
		cleanupUsersByPrefix(t, prefix)

		if _, err := repo.GetUserByUsername(prefix + "_x"); err == nil {
			t.Fatalf("expected GetUserByUsername to fail for missing user")
		}
		if _, err := repo.GetUserByEmail(prefix + "@example.com"); err == nil {
			t.Fatalf("expected GetUserByEmail to fail for missing user")
		}
		if _, err := repo.GetUserByUsernameOrEmail(prefix + "_x"); err == nil {
			t.Fatalf("expected GetUserByUsernameOrEmail to fail for missing user")
		}
	})
}
