package repository

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yourname/side-go-server/internal/database"
)

var ErrUserConfNotFound = errors.New("user conf not found")

type UserConfRepository struct{}

func NewUserConfRepository() *UserConfRepository {
	return &UserConfRepository{}
}

func (r *UserConfRepository) Get(uzid, key string) (json.RawMessage, time.Time, error) {
	query := `
		SELECT conf_value, updated_at
		FROM user_conf
		WHERE uzid = $1 AND conf_key = $2
	`
	var raw []byte
	var updatedAt time.Time
	err := database.DB.QueryRow(query, uzid, key).Scan(&raw, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, time.Time{}, ErrUserConfNotFound
	}
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to get user conf: %w", err)
	}
	return json.RawMessage(raw), updatedAt, nil
}

func (r *UserConfRepository) Upsert(uzid, key string, value json.RawMessage) (json.RawMessage, time.Time, error) {
	query := `
		INSERT INTO user_conf (uzid, conf_key, conf_value)
		VALUES ($1, $2, $3::jsonb)
		ON CONFLICT (uzid, conf_key)
		DO UPDATE SET conf_value = EXCLUDED.conf_value, updated_at = CURRENT_TIMESTAMP
		RETURNING conf_value, updated_at
	`
	var raw []byte
	var updatedAt time.Time
	err := database.DB.QueryRow(query, uzid, key, []byte(value)).Scan(&raw, &updatedAt)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to upsert user conf: %w", err)
	}
	return json.RawMessage(raw), updatedAt, nil
}
