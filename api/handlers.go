package api

import (
	"fmt"

	"github.com/gin-gonic/gin"
	redisClient "github.com/yourname/side-go-server/internal/redis"
)

type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

type LoginResponse struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Action string `json:"action"`
}

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request body"})
		return
	}

	tempID := c.GetHeader("x-temp-id")

	userID := "user_" + req.Email
	email := req.Email

	guestTokenKey := fmt.Sprintf("token:%s:%s", tempID, tempID)
	redisClient.Client.Del(redisClient.Ctx, guestTokenKey)

	c.JSON(200, LoginResponse{
		UserID: userID,
		Email:  email,
		Action: "refresh_token",
	})
}

func Logout(c *gin.Context) {
	uid := c.GetString("verified_uid")
	deviceID := c.GetString("verified_device_id")

	if uid == "" || deviceID == "" {
		c.JSON(400, gin.H{"error": "Not authenticated"})
		return
	}

	tokenKey := fmt.Sprintf("token:%s:%s", uid, deviceID)
	redisClient.Client.Del(redisClient.Ctx, tokenKey)

	c.JSON(200, gin.H{"message": "Logged out successfully"})
}

func LogoutAllDevices(c *gin.Context) {
	uid := c.GetString("verified_uid")

	if uid == "" {
		c.JSON(400, gin.H{"error": "Not authenticated"})
		return
	}

	pattern := fmt.Sprintf("token:%s:*", uid)
	keys, _ := redisClient.Client.Keys(redisClient.Ctx, pattern).Result()
	if len(keys) > 0 {
		redisClient.Client.Del(redisClient.Ctx, keys...)
	}

	c.JSON(200, gin.H{
		"message":         "Logged out from all devices",
		"devices_cleared": len(keys),
	})
}

func Translate(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "Translation endpoint placeholder",
		"uid":     c.GetString("verified_uid"),
		"role":    c.GetString("verified_role"),
	})
}

func GetProfile(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "Profile endpoint placeholder",
		"uid":     c.GetString("verified_uid"),
		"role":    c.GetString("verified_role"),
	})
}
