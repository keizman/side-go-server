package repository

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/yourname/side-go-server/internal/database"
)

type AuthIdentityRepository struct{}

func NewAuthIdentityRepository() *AuthIdentityRepository {
	return &AuthIdentityRepository{}
}

func (r *AuthIdentityRepository) ResolveOrCreateUZID(authUID string) (string, error) {
	identityHash := hashIdentity(authUID)
	if identityHash == "" {
		return "", fmt.Errorf("auth uid is required")
	}

	candidateUZID := uuid.NewString()
	query := `
		INSERT INTO auth_identity_uzid (identity_hash, uzid)
		VALUES ($1, $2)
		ON CONFLICT (identity_hash)
		DO UPDATE SET updated_at = CURRENT_TIMESTAMP
		RETURNING uzid
	`
	var uzid string
	if err := database.DB.QueryRow(query, identityHash, candidateUZID).Scan(&uzid); err != nil {
		return "", fmt.Errorf("failed to resolve auth identity uzid: %w", err)
	}
	return uzid, nil
}

func hashIdentity(identity string) string {
	trimmed := strings.TrimSpace(identity)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:])
}
