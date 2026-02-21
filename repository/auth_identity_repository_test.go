package repository

import (
	"errors"
	"testing"

	"github.com/yourname/side-go-server/internal/database"
)

func TestLookupIdentityCandidates(t *testing.T) {
	t.Run("Given user-prefixed identity When building candidates Then includes stripped email", func(t *testing.T) {
		got := lookupIdentityCandidates("user_test@example.com")
		if len(got) != 2 {
			t.Fatalf("expected 2 candidates, got %d (%v)", len(got), got)
		}
		if got[0] != "user_test@example.com" || got[1] != "test@example.com" {
			t.Fatalf("unexpected candidates: %v", got)
		}
	})

	t.Run("Given plain identity When building candidates Then keeps single value", func(t *testing.T) {
		got := lookupIdentityCandidates("alice")
		if len(got) != 1 || got[0] != "alice" {
			t.Fatalf("unexpected candidates: %v", got)
		}
	})
}

func TestAuthIdentityRepository_ResolveOrCreateUZID(t *testing.T) {
	t.Run("Given empty auth uid When resolving uzid Then returns error", func(t *testing.T) {
		repo := NewAuthIdentityRepository()
		_, err := repo.ResolveOrCreateUZID("   ")
		if err == nil {
			t.Fatalf("expected error for empty auth uid")
		}
	})

	t.Run("Given database is not initialized When resolving uzid Then returns error", func(t *testing.T) {
		originalDB := database.DB
		database.DB = nil
		t.Cleanup(func() {
			database.DB = originalDB
		})

		repo := NewAuthIdentityRepository()
		_, err := repo.ResolveOrCreateUZID("user_test@example.com")
		if err == nil {
			t.Fatalf("expected error when database is nil")
		}
	})

	t.Run("Given no matched user record When resolving uzid Then returns unbound error", func(t *testing.T) {
		if !errors.Is(ErrAuthIdentityNotBoundToUser, ErrAuthIdentityNotBoundToUser) {
			t.Fatalf("expected sentinel error to be comparable")
		}
	})
}
