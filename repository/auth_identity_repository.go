package repository

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/yourname/side-go-server/internal/database"
)

type AuthIdentityRepository struct{}

var ErrAuthIdentityNotBoundToUser = errors.New("auth identity is not bound to a user record")

func NewAuthIdentityRepository() *AuthIdentityRepository {
	return &AuthIdentityRepository{}
}

func (r *AuthIdentityRepository) ResolveOrCreateUZID(authUID string) (string, error) {
	normalized := strings.TrimSpace(authUID)
	if normalized == "" {
		return "", fmt.Errorf("auth uid is required")
	}
	if database.DB == nil {
		return "", fmt.Errorf("database is not initialized")
	}

	candidates := lookupIdentityCandidates(normalized)
	for _, candidate := range candidates {
		uzid, err := findUserUZID(candidate)
		if err == nil {
			return uzid, nil
		}
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		return "", err
	}

	return "", ErrAuthIdentityNotBoundToUser
}

func findUserUZID(identity string) (string, error) {
	query := `
		SELECT uzid
		FROM users
		WHERE deleted_at IS NULL
		  AND (uzid = $1 OR username = $1 OR email = $1)
		LIMIT 1
	`
	var uzid string
	err := database.DB.QueryRow(query, identity).Scan(&uzid)
	if err != nil {
		return "", err
	}
	uzid = strings.TrimSpace(uzid)
	if uzid == "" {
		return "", fmt.Errorf("empty uzid found for identity=%q", identity)
	}
	return uzid, nil
}

func lookupIdentityCandidates(authUID string) []string {
	seen := map[string]struct{}{}
	candidates := make([]string, 0, 2)

	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		candidates = append(candidates, value)
	}

	add(authUID)
	if strings.HasPrefix(authUID, "user_") {
		add(strings.TrimPrefix(authUID, "user_"))
	}

	return candidates
}
