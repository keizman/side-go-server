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
	"log"
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
	clientIP := c.ClientIP()

	if tempID == "" || extensionID == "" || timestamp == "" {
		missing := make([]string, 0, 3)
		if tempID == "" {
			missing = append(missing, "x-temp-id")
		}
		if extensionID == "" {
			missing = append(missing, "x-extension-id")
		}
		if timestamp == "" {
			missing = append(missing, "x-timestamp")
		}
		log.Printf("WARN auth_token rejected: reason=missing_headers ip=%s missing=%v", clientIP, missing)
		c.AbortWithStatusJSON(400, gin.H{"error": "Missing required headers"})
		return
	}

	if !isExtensionAllowed(extensionID) {
		log.Printf("WARN auth_token rejected: reason=extension_not_allowed ip=%s temp_id=%q extension_id=%q", clientIP, tempID, extensionID)
		c.AbortWithStatusJSON(403, gin.H{"error": "Invalid extension ID"})
		return
	}

	if !isTimestampValid(timestamp, 60) {
		log.Printf("WARN auth_token rejected: reason=timestamp_invalid ip=%s temp_id=%q extension_id=%q timestamp=%q tolerance_seconds=60", clientIP, tempID, extensionID, timestamp)
		c.AbortWithStatusJSON(401, gin.H{"error": "Timestamp expired"})
		return
	}

	var identity string
	var role string
	oldToken := extractBearerToken(authHeader)

	if oldToken != "" {
		payload, err := decryptToken(oldToken)
		if err != nil {
			log.Printf("WARN auth_token rejected: reason=token_decrypt_failed ip=%s temp_id=%q err=%v", clientIP, tempID, err)
			c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token format"})
			return
		}

		redisKey := fmt.Sprintf("token:%s:%s", payload.UID, payload.DeviceID)
		storedToken, err := redisClient.Client.Get(redisClient.Ctx, redisKey).Result()
		if err != nil {
			log.Printf("WARN auth_token rejected: reason=token_lookup_failed ip=%s temp_id=%q redis_key=%q err=%v", clientIP, tempID, redisKey, err)
			c.AbortWithStatusJSON(401, gin.H{"error": "Token revoked or expired"})
			return
		}
		if storedToken != oldToken {
			log.Printf("WARN auth_token rejected: reason=token_mismatch ip=%s temp_id=%q redis_key=%q", clientIP, tempID, redisKey)
			c.AbortWithStatusJSON(401, gin.H{"error": "Token revoked or expired"})
			return
		}

		if err := redisClient.Client.Del(redisClient.Ctx, redisKey).Err(); err != nil {
			log.Printf("WARN auth_token old token cleanup failed: ip=%s temp_id=%q redis_key=%q err=%v", clientIP, tempID, redisKey, err)
		}

		identity = payload.UID
		role = payload.Role

		if userID != "" && userID != identity {
			log.Printf("INFO auth_token identity switch: ip=%s temp_id=%q from_uid=%q to_uid=%q", clientIP, tempID, identity, userID)
			identity = userID
			role = "user"
		}

	} else if clientSalt != "" {
		if !verifyInitSalt(extensionID, timestamp, clientSalt) {
			log.Printf("WARN auth_token rejected: reason=invalid_init_salt ip=%s temp_id=%q extension_id=%q", clientIP, tempID, extensionID)
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
		log.Printf("WARN auth_token rejected: reason=missing_credentials ip=%s temp_id=%q extension_id=%q has_auth=%t has_init_salt=%t", clientIP, tempID, extensionID, oldToken != "", clientSalt != "")
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
		log.Printf("ERROR auth_token failed: reason=token_generation_failed ip=%s uid=%q role=%q temp_id=%q err=%v", clientIP, identity, role, tempID, err)
		c.AbortWithStatusJSON(500, gin.H{"error": "Token generation failed"})
		return
	}

	redisKey := fmt.Sprintf("token:%s:%s", identity, tempID)
	err = redisClient.Client.SetEX(redisClient.Ctx, redisKey, newToken, config.Cfg.TokenTTL).Err()
	if err != nil {
		log.Printf("ERROR auth_token failed: reason=token_storage_failed ip=%s uid=%q role=%q temp_id=%q redis_key=%q err=%v", clientIP, identity, role, tempID, redisKey, err)
		c.AbortWithStatusJSON(500, gin.H{"error": "Token storage failed"})
		return
	}

	log.Printf("INFO auth_token success: ip=%s uid=%q role=%q temp_id=%q ttl_seconds=%d", clientIP, identity, role, tempID, tokenTTL)

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
	clientIP := c.ClientIP()

	token := extractBearerToken(authHeader)
	if token == "" {
		log.Printf("WARN check_token rejected: reason=missing_bearer ip=%s has_auth_header=%t", clientIP, authHeader != "")
		c.AbortWithStatus(401)
		return
	}

	if tempID == "" || timestamp == "" || nonce == "" {
		missing := make([]string, 0, 3)
		if tempID == "" {
			missing = append(missing, "x-temp-id")
		}
		if timestamp == "" {
			missing = append(missing, "x-timestamp")
		}
		if nonce == "" {
			missing = append(missing, "x-nonce")
		}
		log.Printf("WARN check_token rejected: reason=missing_headers ip=%s missing=%v", clientIP, missing)
		c.AbortWithStatus(400)
		return
	}

	toleranceSeconds := int64(config.Cfg.TimestampTolerance.Seconds())
	if !isTimestampValid(timestamp, toleranceSeconds) {
		log.Printf("WARN check_token rejected: reason=timestamp_invalid ip=%s temp_id=%q timestamp=%q tolerance_seconds=%d", clientIP, tempID, timestamp, toleranceSeconds)
		c.AbortWithStatus(401)
		return
	}

	payload, err := decryptToken(token)
	if err != nil {
		log.Printf("WARN check_token rejected: reason=token_decrypt_failed ip=%s temp_id=%q err=%v", clientIP, tempID, err)
		c.AbortWithStatus(401)
		return
	}

	if time.Now().Unix() > payload.Exp {
		log.Printf("WARN check_token rejected: reason=token_expired ip=%s uid=%q temp_id=%q exp=%d", clientIP, payload.UID, tempID, payload.Exp)
		c.AbortWithStatus(401)
		return
	}

	if payload.DeviceID != tempID {
		log.Printf("WARN check_token rejected: reason=device_mismatch ip=%s uid=%q token_device=%q request_temp_id=%q", clientIP, payload.UID, payload.DeviceID, tempID)
		c.AbortWithStatus(401)
		return
	}

	redisKey := fmt.Sprintf("token:%s:%s", payload.UID, tempID)
	storedToken, err := redisClient.Client.Get(redisClient.Ctx, redisKey).Result()
	if err == redis.Nil {
		log.Printf("WARN check_token rejected: reason=token_not_found ip=%s uid=%q temp_id=%q redis_key=%q", clientIP, payload.UID, tempID, redisKey)
		c.AbortWithStatus(401)
		return
	} else if err != nil {
		log.Printf("ERROR check_token failed: reason=token_lookup_error ip=%s uid=%q temp_id=%q redis_key=%q err=%v", clientIP, payload.UID, tempID, redisKey, err)
		c.AbortWithStatus(500)
		return
	}

	if storedToken != token {
		log.Printf("WARN check_token rejected: reason=token_mismatch ip=%s uid=%q temp_id=%q redis_key=%q", clientIP, payload.UID, tempID, redisKey)
		c.AbortWithStatus(401)
		return
	}

	nonceKey := fmt.Sprintf("nonce:%s:%s", payload.UID, nonce)
	nonceTTL := config.Cfg.NonceTTL

	set, err := redisClient.Client.SetNX(redisClient.Ctx, nonceKey, "1", nonceTTL).Result()
	if err != nil {
		log.Printf("ERROR check_token failed: reason=nonce_store_error ip=%s uid=%q temp_id=%q nonce=%q err=%v", clientIP, payload.UID, tempID, nonce, err)
		c.AbortWithStatus(500)
		return
	}
	if !set {
		log.Printf("WARN check_token rejected: reason=nonce_replay ip=%s uid=%q temp_id=%q nonce=%q", clientIP, payload.UID, tempID, nonce)
		c.AbortWithStatus(401)
		return
	}

	if !checkRateLimit(payload.UID, payload.Role, tempID) {
		log.Printf("WARN check_token rejected: reason=rate_limited ip=%s uid=%q role=%q temp_id=%q", clientIP, payload.UID, payload.Role, tempID)
		c.AbortWithStatus(429)
		return
	}

	log.Printf("INFO check_token success: ip=%s uid=%q role=%q temp_id=%q", clientIP, payload.UID, payload.Role, tempID)

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
		log.Printf("WARN rate_limit bypass due to redis error: uid=%q role=%q temp_id=%q key=%q err=%v", uid, role, tempID, key, err)
		return true
	}

	if count == 1 {
		if err := redisClient.Client.Expire(redisClient.Ctx, key, 60*time.Second).Err(); err != nil {
			log.Printf("WARN rate_limit ttl set failed: uid=%q role=%q temp_id=%q key=%q err=%v", uid, role, tempID, key, err)
		}
	}

	return count <= int64(limit)
}
