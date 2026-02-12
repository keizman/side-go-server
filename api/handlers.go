package api

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	redisClient "github.com/yourname/side-go-server/internal/redis"
)

const defaultUserTier = 2

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
		log.Printf("WARN login rejected: reason=invalid_request ip=%s err=%v", c.ClientIP(), err)
		c.JSON(400, gin.H{"error": "Invalid request body"})
		return
	}

	tempID := c.GetHeader("x-temp-id")

	userID := "user_" + req.Email
	email := req.Email

	guestTokenKey := fmt.Sprintf("token:%s:%s", tempID, tempID)
	if err := redisClient.Client.Del(redisClient.Ctx, guestTokenKey).Err(); err != nil {
		log.Printf("WARN login guest token cleanup failed: ip=%s temp_id=%q key=%q err=%v", c.ClientIP(), tempID, guestTokenKey, err)
	}
	tierKey := fmt.Sprintf("user:tier:%s", userID)
	if err := redisClient.Client.Set(redisClient.Ctx, tierKey, defaultUserTier, 0).Err(); err != nil {
		log.Printf("WARN login user tier cache set failed: ip=%s user_id=%q key=%q tier=%d err=%v", c.ClientIP(), userID, tierKey, defaultUserTier, err)
	}

	log.Printf("INFO login success: ip=%s temp_id=%q email=%q user_id=%q", c.ClientIP(), tempID, email, userID)

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
		log.Printf("WARN logout rejected: reason=not_authenticated ip=%s uid=%q device_id=%q", c.ClientIP(), uid, deviceID)
		c.JSON(400, gin.H{"error": "Not authenticated"})
		return
	}

	tokenKey := fmt.Sprintf("token:%s:%s", uid, deviceID)
	if err := redisClient.Client.Del(redisClient.Ctx, tokenKey).Err(); err != nil {
		log.Printf("WARN logout token cleanup failed: ip=%s uid=%q device_id=%q key=%q err=%v", c.ClientIP(), uid, deviceID, tokenKey, err)
	}
	log.Printf("INFO logout success: ip=%s uid=%q device_id=%q", c.ClientIP(), uid, deviceID)

	c.JSON(200, gin.H{"message": "Logged out successfully"})
}

func LogoutAllDevices(c *gin.Context) {
	uid := c.GetString("verified_uid")

	if uid == "" {
		log.Printf("WARN logout_all rejected: reason=not_authenticated ip=%s", c.ClientIP())
		c.JSON(400, gin.H{"error": "Not authenticated"})
		return
	}

	pattern := fmt.Sprintf("token:%s:*", uid)
	keys, err := redisClient.Client.Keys(redisClient.Ctx, pattern).Result()
	if err != nil {
		log.Printf("ERROR logout_all failed: reason=redis_keys_error ip=%s uid=%q pattern=%q err=%v", c.ClientIP(), uid, pattern, err)
		c.JSON(500, gin.H{"error": "Failed to list user sessions"})
		return
	}
	if len(keys) > 0 {
		if err := redisClient.Client.Del(redisClient.Ctx, keys...).Err(); err != nil {
			log.Printf("ERROR logout_all failed: reason=redis_del_error ip=%s uid=%q keys=%d err=%v", c.ClientIP(), uid, len(keys), err)
			c.JSON(500, gin.H{"error": "Failed to revoke user sessions"})
			return
		}
	}
	log.Printf("INFO logout_all success: ip=%s uid=%q devices_cleared=%d", c.ClientIP(), uid, len(keys))

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
		"tier":    c.GetString("verified_tier"),
	})
}

func GetProfile(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "Profile endpoint placeholder",
		"uid":     c.GetString("verified_uid"),
		"role":    c.GetString("verified_role"),
		"tier":    c.GetString("verified_tier"),
	})
}
