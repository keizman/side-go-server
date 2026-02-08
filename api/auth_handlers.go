package api

import (
	"database/sql"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/yourname/side-go-server/models"
	"github.com/yourname/side-go-server/repository"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

type AuthHandlers struct {
	userRepo authUserRepository
}

type authUserRepository interface {
	GetUserByUsername(username string) (*models.User, error)
	GetUserByEmail(email string) (*models.User, error)
	CreateUser(user *models.User, password string) error
}

func NewAuthHandlers(userRepo *repository.UserRepository) *AuthHandlers {
	return &AuthHandlers{
		userRepo: userRepo,
	}
}

func (h *AuthHandlers) Register(c *gin.Context) {
	var req models.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("WARN register rejected: reason=invalid_request ip=%s err=%v", c.ClientIP(), err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}

	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.TrimSpace(req.Email)

	if !emailRegex.MatchString(req.Email) {
		log.Printf("WARN register rejected: reason=invalid_email ip=%s username=%q email=%q", c.ClientIP(), req.Username, req.Email)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	existingUser, err := h.userRepo.GetUserByUsername(req.Username)
	if err == nil && existingUser != nil {
		log.Printf("WARN register rejected: reason=username_exists ip=%s username=%q email=%q", c.ClientIP(), req.Username, req.Email)
		c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
		return
	}
	if err != nil {
		log.Printf("WARN register username lookup failed (will continue): ip=%s username=%q err=%v", c.ClientIP(), req.Username, err)
	}

	existingUser, err = h.userRepo.GetUserByEmail(req.Email)
	if err == nil && existingUser != nil {
		log.Printf("WARN register rejected: reason=email_exists ip=%s username=%q email=%q", c.ClientIP(), req.Username, req.Email)
		c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		return
	}
	if err != nil {
		log.Printf("WARN register email lookup failed (will continue): ip=%s email=%q err=%v", c.ClientIP(), req.Email, err)
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
		log.Printf("ERROR register create user failed: ip=%s username=%q email=%q err=%v", clientIP, req.Username, req.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	log.Printf("INFO register success: ip=%s user_id=%d username=%q email=%q", clientIP, user.ID, user.Username, user.Email)

	c.JSON(http.StatusCreated, gin.H{
		"message": "User registered successfully",
		"user_id": user.ID,
	})
}
