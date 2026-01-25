package api

import (
	"database/sql"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/yourname/side-go-server/models"
	"github.com/yourname/side-go-server/repository"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

type AuthHandlers struct {
	userRepo *repository.UserRepository
}

func NewAuthHandlers(userRepo *repository.UserRepository) *AuthHandlers {
	return &AuthHandlers{
		userRepo: userRepo,
	}
}

func (h *AuthHandlers) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	if !emailRegex.MatchString(req.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)

	existingUser, err := h.userRepo.GetUserByUsername(req.Username)
	if err == nil && existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}

	existingUser, err = h.userRepo.GetUserByEmail(req.Email)
	if err == nil && existingUser != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		return
	}

	clientIP := c.ClientIP()

	user := &models.User{
		Username:     req.Username,
		Email:        req.Email,
		DisplayName:  sql.NullString{String: req.Username, Valid: true},
		Role:         "user",
		Status:       "active",
		RegisterIP:   sql.NullString{String: clientIP, Valid: true},
		RequestCount: 0,
	}

	if err := h.userRepo.CreateUser(user, req.Password); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user_id": user.ID,
	})
}
