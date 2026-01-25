package repository

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/yourname/side-go-server/internal/database"
	"github.com/yourname/side-go-server/models"

	"golang.org/x/crypto/bcrypt"
)

type UserRepository struct{}

func NewUserRepository() *UserRepository {
	return &UserRepository{}
}

func (r *UserRepository) CreateUser(user *models.User, password string) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	query := `
		INSERT INTO users (username, email, password_hash, display_name, role, status, register_ip, request_count, email_verified)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, created_at, updated_at
	`

	err = database.DB.QueryRow(
		query,
		user.Username,
		user.Email,
		string(hashedPassword),
		user.DisplayName,
		user.Role,
		user.Status,
		user.RegisterIP,
		user.RequestCount,
		user.EmailVerified,
	).Scan(&user.ID, &user.CreatedAt, &user.UpdatedAt)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

func (r *UserRepository) GetUserByUsername(username string) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, username, email, password_hash, display_name, role, status, 
		       register_ip, request_count, last_login_at, last_login_ip,
		       created_at, updated_at, email_verified, email_verified_at, deleted_at
		FROM users
		WHERE username = $1 AND deleted_at IS NULL
	`

	err := database.DB.QueryRow(query, username).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.DisplayName,
		&user.Role,
		&user.Status,
		&user.RegisterIP,
		&user.RequestCount,
		&user.LastLoginAt,
		&user.LastLoginIP,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.EmailVerified,
		&user.EmailVerifiedAt,
		&user.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

func (r *UserRepository) GetUserByEmail(email string) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, username, email, password_hash, display_name, role, status, 
		       register_ip, request_count, last_login_at, last_login_ip,
		       created_at, updated_at, email_verified, email_verified_at, deleted_at
		FROM users
		WHERE email = $1 AND deleted_at IS NULL
	`

	err := database.DB.QueryRow(query, email).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.DisplayName,
		&user.Role,
		&user.Status,
		&user.RegisterIP,
		&user.RequestCount,
		&user.LastLoginAt,
		&user.LastLoginIP,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.EmailVerified,
		&user.EmailVerifiedAt,
		&user.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

func (r *UserRepository) GetUserByUsernameOrEmail(usernameOrEmail string) (*models.User, error) {
	user := &models.User{}
	query := `
		SELECT id, username, email, password_hash, display_name, role, status, 
		       register_ip, request_count, last_login_at, last_login_ip,
		       created_at, updated_at, email_verified, email_verified_at, deleted_at
		FROM users
		WHERE (username = $1 OR email = $1) AND deleted_at IS NULL
	`

	err := database.DB.QueryRow(query, usernameOrEmail).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.PasswordHash,
		&user.DisplayName,
		&user.Role,
		&user.Status,
		&user.RegisterIP,
		&user.RequestCount,
		&user.LastLoginAt,
		&user.LastLoginIP,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.EmailVerified,
		&user.EmailVerifiedAt,
		&user.DeletedAt,
	)

	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

func (r *UserRepository) VerifyPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func (r *UserRepository) UpdateLastLogin(userID int, ip string) error {
	query := `
		UPDATE users
		SET last_login_at = $1, last_login_ip = $2, updated_at = $1
		WHERE id = $3
	`

	_, err := database.DB.Exec(query, time.Now(), ip, userID)
	if err != nil {
		return fmt.Errorf("failed to update last login: %w", err)
	}

	return nil
}

func (r *UserRepository) IncrementRequestCount(userID int) error {
	query := `
		UPDATE users
		SET request_count = request_count + 1
		WHERE id = $1
	`

	_, err := database.DB.Exec(query, userID)
	if err != nil {
		return fmt.Errorf("failed to increment request count: %w", err)
	}

	return nil
}

func (r *UserRepository) UserExists(username, email string) (bool, error) {
	var exists bool
	query := `
		SELECT EXISTS(SELECT 1 FROM users WHERE (username = $1 OR email = $2) AND deleted_at IS NULL)
	`

	err := database.DB.QueryRow(query, username, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if user exists: %w", err)
	}

	return exists, nil
}

func (r *UserRepository) CreateDefaultAdmin(username, password, email string) error {
	exists, err := r.UserExists(username, email)
	if err != nil {
		return err
	}

	if exists {
		return nil
	}

	user := &models.User{
		Username:      username,
		Email:         email,
		DisplayName:   sql.NullString{String: "Administrator", Valid: true},
		Role:          "admin",
		Status:        "active",
		RegisterIP:    sql.NullString{String: "127.0.0.1", Valid: true},
		RequestCount:  0,
		EmailVerified: true,
	}

	return r.CreateUser(user, password)
}
