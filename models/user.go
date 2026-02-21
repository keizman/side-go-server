package models

import (
	"database/sql"
	"time"
)

type User struct {
	ID              int            `json:"id"`
	UZID            string         `json:"uzid"`
	Username        string         `json:"username"`
	Email           string         `json:"email"`
	PasswordHash    string         `json:"-"`
	DisplayName     sql.NullString `json:"display_name,omitempty"`
	Status          string         `json:"status"`
	Role            string         `json:"role"`
	Tier            int            `json:"tier"`
	RegisterIP      sql.NullString `json:"register_ip,omitempty"`
	RequestCount    int64          `json:"request_count"`
	LastLoginAt     sql.NullTime   `json:"last_login_at,omitempty"`
	LastLoginIP     sql.NullString `json:"last_login_ip,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	EmailVerified   bool           `json:"email_verified"`
	EmailVerifiedAt sql.NullTime   `json:"email_verified_at,omitempty"`
	DeletedAt       sql.NullTime   `json:"deleted_at,omitempty"`
}

type RegisterRequest struct {
	Username        string `json:"username" binding:"required,min=3,max=50"`
	Password        string `json:"password" binding:"required,min=8,max=100"`
	ConfirmPassword string `json:"confirm_password" binding:"required,eqfield=Password"`
	Email           string `json:"email" binding:"required"`
}

type LoginRequest struct {
	UsernameOrEmail string `json:"username_or_email" binding:"required"`
	Password        string `json:"password" binding:"required"`
}
