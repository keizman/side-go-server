package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/yourname/side-go-server/config"
	redisClient "github.com/yourname/side-go-server/internal/redis"
)

type TokenPayload struct {
	UID      string `json:"uid"`
	Role     string `json:"role"`
	DeviceID string `json:"device_id"`
	Exp      int64  `json:"exp"`
	Iat      int64  `json:"iat"`
}

type AuthTokenResponse struct {
	Token         string `json:"token"`
	ExpiresIn     int    `json:"expires_in"`
	CheckInterval int    `json:"check_interval"`
}

func AuthToken(c *gin.Context) {
	tempID := c.GetHeader("x-temp-id")
	extensionID := c.GetHeader("x-extension-id")
	timestamp := c.GetHeader("x-timestamp")
	userID := c.GetHeader("x-user-id")
	clientSalt := c.GetHeader("x-init-salt")
	authHeader := c.GetHeader("Authorization")

	if tempID == "" || extensionID == "" || timestamp == "" {
		c.AbortWithStatusJSON(400, gin.H{"error": "Missing required headers"})
		return
	}

	if !isExtensionAllowed(extensionID) {
		c.AbortWithStatusJSON(403, gin.H{"error": "Invalid extension ID"})
		return
	}

	if !isTimestampValid(timestamp, 60) {
		c.AbortWithStatusJSON(401, gin.H{"error": "Timestamp expired"})
		return
	}

	var identity string
	var role string
	oldToken := extractBearerToken(authHeader)

	if oldToken != "" {
		payload, err := decryptToken(oldToken)
		if err != nil {
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token format"})
			return
		}

		redisKey := fmt.Sprintf("token:%s:%s", payload.UID, payload.DeviceID)
		storedToken, err := redisClient.Client.Get(redisClient.Ctx, redisKey).Result()
		if err != nil || storedToken != oldToken {
			c.AbortWithStatusJSON(401, gin.H{"error": "Token revoked or expired"})
			return
		}

		redisClient.Client.Del(redisClient.Ctx, redisKey)

		identity = payload.UID
		role = payload.Role

		if userID != "" && userID != identity {
			identity = userID
			role = "user"
		}

	} else if clientSalt != "" {
		if !verifyInitSalt(extensionID, timestamp, clientSalt) {
			c.AbortWithStatusJSON(403, gin.H{"error": "Invalid init salt"})
			return
		}

		if userID != "" {
			identity = userID
			role = "user"
		} else {
			identity = tempID
			role = "guest"
		}

	} else {
		c.AbortWithStatusJSON(400, gin.H{
			"error": "Missing credentials: provide either Authorization or x-init-salt",
		})
		return
	}

	tokenTTL := int(config.Cfg.TokenTTL.Seconds())
	now := time.Now().Unix()

	newPayload := TokenPayload{
		UID:      identity,
		Role:     role,
		DeviceID: tempID,
		Exp:      now + int64(tokenTTL),
		Iat:      now,
	}

	newToken, err := encryptToken(newPayload)
	if err != nil {
		c.AbortWithStatusJSON(500, gin.H{"error": "Token generation failed"})
		return
	}

	redisKey := fmt.Sprintf("token:%s:%s", identity, tempID)
	err = redisClient.Client.SetEX(redisClient.Ctx, redisKey, newToken, config.Cfg.TokenTTL).Err()
	if err != nil {
		c.AbortWithStatusJSON(500, gin.H{"error": "Token storage failed"})
		return
	}

	c.JSON(200, AuthTokenResponse{
		Token:         newToken,
		ExpiresIn:     tokenTTL,
		CheckInterval: 300,
	})
}

func CheckToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	timestamp := c.GetHeader("x-timestamp")
	nonce := c.GetHeader("x-nonce")
	tempID := c.GetHeader("x-temp-id")

	token := extractBearerToken(authHeader)
	if token == "" {
		c.AbortWithStatus(401)
		return
	}

	if tempID == "" || timestamp == "" || nonce == "" {
		c.AbortWithStatus(400)
		return
	}

	toleranceSeconds := int64(config.Cfg.TimestampTolerance.Seconds())
	if !isTimestampValid(timestamp, toleranceSeconds) {
		c.AbortWithStatus(401)
		return
	}

	payload, err := decryptToken(token)
	if err != nil {
		c.AbortWithStatus(401)
		return
	}

	if time.Now().Unix() > payload.Exp {
		c.AbortWithStatus(401)
		return
	}

	if payload.DeviceID != tempID {
		c.AbortWithStatus(401)
		return
	}

	redisKey := fmt.Sprintf("token:%s:%s", payload.UID, tempID)
	storedToken, err := redisClient.Client.Get(redisClient.Ctx, redisKey).Result()
	if err == redis.Nil {
		c.AbortWithStatus(401)
		return
	} else if err != nil {
		c.AbortWithStatus(500)
		return
	}

	if storedToken != token {
		c.AbortWithStatus(401)
		return
	}

	nonceKey := fmt.Sprintf("nonce:%s:%s", payload.UID, nonce)
	nonceTTL := config.Cfg.NonceTTL

	set, err := redisClient.Client.SetNX(redisClient.Ctx, nonceKey, "1", nonceTTL).Result()
	if err != nil {
		c.AbortWithStatus(500)
		return
	}
	if !set {
		c.AbortWithStatus(401)
		return
	}

	if !checkRateLimit(payload.UID, payload.Role, tempID) {
		c.AbortWithStatus(429)
		return
	}

	c.Header("X-Verified-UID", payload.UID)
	c.Header("X-Verified-Role", payload.Role)
	c.Header("X-Verified-DeviceID", payload.DeviceID)
	c.Status(200)
}

func isExtensionAllowed(extensionID string) bool {
	for _, id := range config.Cfg.AllowedExtensionIDs {
		if id == extensionID {
			return true
		}
	}
	return false
}

func isTimestampValid(timestampStr string, toleranceSeconds int64) bool {
	ts, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	diff := now - ts
	if diff < 0 {
		diff = -diff
	}
	return diff <= toleranceSeconds
}

func extractBearerToken(authHeader string) string {
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	return ""
}

func verifyInitSalt(extensionID, timestamp, clientSalt string) bool {
	serverSecret := config.Cfg.ClientSaltSecret
	if serverSecret == "" {
		return false
	}
	truncatedTs := timestamp
	if len(timestamp) > 2 {
		truncatedTs = timestamp[:len(timestamp)-2]
	}
	payload := extensionID + "|" + truncatedTs
	expectedSalt := hmacSHA256(payload, serverSecret)[:32]
	return hmac.Equal([]byte(expectedSalt), []byte(clientSalt))
}

func hmacSHA256(data, key string) string {
	h := hmac.New(sha256.New, []byte(key))
	h.Write([]byte(data))
	return fmt.Sprintf("%x", h.Sum(nil))
}

func encryptToken(payload TokenPayload) (string, error) {
	secret := config.Cfg.ServerSecret
	if len(secret) < 32 {
		return "", fmt.Errorf("SERVER_SECRET must be at least 32 bytes")
	}
	key := []byte(secret[:32])

	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

func decryptToken(tokenStr string) (*TokenPayload, error) {
	secret := config.Cfg.ServerSecret
	if len(secret) < 32 {
		return nil, fmt.Errorf("SERVER_SECRET must be at least 32 bytes")
	}
	key := []byte(secret[:32])

	ciphertext, err := base64.URLEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	var payload TokenPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, err
	}

	return &payload, nil
}

func checkRateLimit(uid, role, tempID string) bool {
	var key string
	var limit int

	if role == "user" {
		key = fmt.Sprintf("rate:user:%s", uid)
		limit = config.Cfg.LimitUserRPM
	} else {
		key = fmt.Sprintf("rate:guest:%s", tempID)
		limit = config.Cfg.LimitGuestRPM
	}

	count, err := redisClient.Client.Incr(redisClient.Ctx, key).Result()
	if err != nil {
		return true
	}

	if count == 1 {
		redisClient.Client.Expire(redisClient.Ctx, key, 60*time.Second)
	}

	return count <= int64(limit)
}
