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
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/joho/godotenv"
	"github.com/yourname/side-go-server/config"
	redisClient "github.com/yourname/side-go-server/internal/redis"
)

const allowedExtensionsRedisKey = "auth:allowed_extension_ids"

var allowedExtensionsReloadInterval = 10 * time.Second

var allowedExtensionsCache = struct {
	mu        sync.RWMutex
	expiresAt time.Time
	ids       map[string]struct{}
	source    string
}{}

type TokenPayload struct {
	UID      string `json:"uid"`
	Role     string `json:"role"`
	Tier     int    `json:"tier"`
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
	userID := strings.TrimSpace(c.GetHeader("x-user-id"))
	clientSalt := c.GetHeader("x-init-salt")
	authHeader := c.GetHeader("Authorization")
	clientIP := c.ClientIP()
	hasUserID := userID != ""
	userIDLen := len(userID)

	log.Printf(
		"INFO auth_token request: ip=%s temp_id=%q extension_id=%q has_user_id=%t user_id_len=%d has_auth=%t has_init_salt=%t",
		clientIP,
		tempID,
		extensionID,
		hasUserID,
		userIDLen,
		authHeader != "",
		clientSalt != "",
	)

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
		source, ids := getAllowedExtensionsSnapshotForLog()
		log.Printf(
			"WARN auth_token rejected: reason=extension_not_allowed ip=%s temp_id=%q extension_id=%q source=%s allowed_ids=%v",
			clientIP,
			tempID,
			extensionID,
			source,
			ids,
		)
		c.AbortWithStatusJSON(403, gin.H{"error": "Invalid extension ID"})
		return
	}

	if !checkAuthRateLimit(clientIP) {
		log.Printf("WARN auth_token rejected: reason=rate_limited ip=%s limit_auth_rpm=%d", clientIP, config.Cfg.LimitAuthRPM)
		c.AbortWithStatusJSON(429, gin.H{"error": "Rate limit exceeded"})
		return
	}

	toleranceSeconds := int64(config.Cfg.TimestampTolerance.Seconds())
	if toleranceSeconds <= 0 {
		toleranceSeconds = 60
	}

	if !isTimestampValid(timestamp, toleranceSeconds) {
		log.Printf("WARN auth_token rejected: reason=timestamp_invalid ip=%s temp_id=%q extension_id=%q timestamp=%q tolerance_seconds=%d", clientIP, tempID, extensionID, timestamp, toleranceSeconds)
		c.AbortWithStatusJSON(401, gin.H{"error": "Timestamp expired"})
		return
	}

	var identity string
	var role string
	var tier int
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
		tier = payload.Tier

		if userID != "" && userID != identity {
			log.Printf("INFO auth_token identity switch: ip=%s temp_id=%q from_uid=%q to_uid=%q", clientIP, tempID, identity, userID)
			identity = userID
			role = "user"
			tier = resolveUserTier(userID)
		}
		if tier <= 0 {
			if role == "guest" {
				tier = 1
			} else {
				tier = resolveUserTier(identity)
			}
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
			tier = resolveUserTier(userID)
		} else {
			identity = tempID
			role = "guest"
			tier = 1
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
		Tier:     tier,
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

	log.Printf(
		"INFO auth_token success: ip=%s uid=%q role=%q tier=%d temp_id=%q ttl_seconds=%d has_user_id=%t user_id_len=%d",
		clientIP,
		identity,
		role,
		tier,
		tempID,
		tokenTTL,
		hasUserID,
		userIDLen,
	)

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
	extensionID := c.GetHeader("x-extension-id")
	clientIP := c.ClientIP()

	token := extractBearerToken(authHeader)
	if token == "" {
		log.Printf("WARN check_token rejected: reason=missing_bearer ip=%s has_auth_header=%t", clientIP, authHeader != "")
		c.AbortWithStatus(401)
		return
	}

	if tempID == "" || timestamp == "" || nonce == "" || extensionID == "" {
		missing := make([]string, 0, 4)
		if tempID == "" {
			missing = append(missing, "x-temp-id")
		}
		if timestamp == "" {
			missing = append(missing, "x-timestamp")
		}
		if nonce == "" {
			missing = append(missing, "x-nonce")
		}
		if extensionID == "" {
			missing = append(missing, "x-extension-id")
		}
		log.Printf("WARN check_token rejected: reason=missing_headers ip=%s missing=%v", clientIP, missing)
		c.AbortWithStatus(400)
		return
	}

	if !isExtensionAllowed(extensionID) {
		source, ids := getAllowedExtensionsSnapshotForLog()
		log.Printf(
			"WARN check_token rejected: reason=extension_not_allowed ip=%s temp_id=%q extension_id=%q source=%s allowed_ids=%v",
			clientIP,
			tempID,
			extensionID,
			source,
			ids,
		)
		c.AbortWithStatus(403)
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

	payload.Tier = normalizeTierWithAuthState(payload.Tier, payload.Role)

	if !checkRateLimit(RateLimitContext{
		UID:       payload.UID,
		TempID:    tempID,
		Tier:      payload.Tier,
		Route:     c.FullPath(),
		Method:    c.Request.Method,
		AuthState: payload.Role,
	}) {
		log.Printf("WARN check_token rejected: reason=rate_limited ip=%s uid=%q role=%q tier=%d temp_id=%q", clientIP, payload.UID, payload.Role, payload.Tier, tempID)
		c.AbortWithStatus(429)
		return
	}

	log.Printf("INFO check_token success: ip=%s uid=%q role=%q tier=%d temp_id=%q", clientIP, payload.UID, payload.Role, payload.Tier, tempID)

	c.Header("X-Verified-UID", payload.UID)
	c.Header("X-Verified-Role", payload.Role)
	c.Header("X-Verified-Tier", strconv.Itoa(payload.Tier))
	c.Header("X-Verified-DeviceID", payload.DeviceID)
	c.Status(200)
}

func InitExtensionWhitelist() error {
	if redisClient.Client == nil {
		return fmt.Errorf("redis client is not initialized")
	}

	keyType, err := redisClient.Client.Type(redisClient.Ctx, allowedExtensionsRedisKey).Result()
	if err != nil {
		return fmt.Errorf("failed to check extension whitelist key type: %w", err)
	}

	switch keyType {
	case "none":
		ids := loadAllowedExtensionIDsFromEnvOrConfig()
		if len(ids) == 0 {
			return fmt.Errorf("no allowed extension IDs configured")
		}

		members := make([]interface{}, 0, len(ids))
		for _, id := range ids {
			members = append(members, id)
		}
		if err := redisClient.Client.SAdd(redisClient.Ctx, allowedExtensionsRedisKey, members...).Err(); err != nil {
			return fmt.Errorf("failed to seed extension whitelist: %w", err)
		}
		log.Printf("INFO extension whitelist seeded to redis: key=%q count=%d ids=%v", allowedExtensionsRedisKey, len(ids), ids)
		return nil

	case "set":
		ids, _, err := loadAllowedExtensionIDsFromRedis()
		if err != nil {
			log.Printf("WARN extension whitelist initialized but list query failed: key=%q err=%v", allowedExtensionsRedisKey, err)
			return nil
		}
		log.Printf("INFO extension whitelist loaded from redis: key=%q count=%d ids=%v", allowedExtensionsRedisKey, len(ids), ids)
		return nil

	case "string", "list":
		ids, _, err := loadAllowedExtensionIDsFromRedis()
		if err != nil {
			return fmt.Errorf("failed to migrate extension whitelist from redis %s: %w", keyType, err)
		}
		if len(ids) == 0 {
			ids = loadAllowedExtensionIDsFromEnvOrConfig()
		}
		if len(ids) == 0 {
			return fmt.Errorf("extension whitelist migration found empty ids")
		}

		if err := redisClient.Client.Del(redisClient.Ctx, allowedExtensionsRedisKey).Err(); err != nil {
			return fmt.Errorf("failed to clear extension whitelist key before migration: %w", err)
		}
		members := make([]interface{}, 0, len(ids))
		for _, id := range ids {
			members = append(members, id)
		}
		if err := redisClient.Client.SAdd(redisClient.Ctx, allowedExtensionsRedisKey, members...).Err(); err != nil {
			return fmt.Errorf("failed to migrate extension whitelist to set: %w", err)
		}
		log.Printf("INFO extension whitelist migrated to redis set: key=%q from_type=%s count=%d ids=%v", allowedExtensionsRedisKey, keyType, len(ids), ids)
		return nil

	default:
		return fmt.Errorf("unsupported redis key type for extension whitelist: %s", keyType)
	}
}

func normalizeAllowedExtensionIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(ids))
	result := make([]string, 0, len(ids))
	for _, id := range ids {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			continue
		}
		trimmed = strings.ToLower(trimmed)
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	sort.Strings(result)
	return result
}

func parseExtensionIDsRaw(raw string) []string {
	normalized := strings.ReplaceAll(raw, "\n", ",")
	normalized = strings.ReplaceAll(normalized, ";", ",")
	return normalizeAllowedExtensionIDs(strings.Split(normalized, ","))
}

func loadAllowedExtensionIDsFromEnvOrConfig() []string {
	raw := strings.TrimSpace(os.Getenv("INIT_ALLOWED_EXTENSION_IDS"))

	if raw == "" {
		if envMap, err := godotenv.Read(); err == nil {
			raw = strings.TrimSpace(envMap["INIT_ALLOWED_EXTENSION_IDS"])
		}
	}

	if raw != "" {
		ids := parseExtensionIDsRaw(raw)
		if len(ids) > 0 {
			return ids
		}
	}

	if strings.TrimSpace(config.Cfg.InitAllowedExtensionIDs) != "" {
		ids := parseExtensionIDsRaw(config.Cfg.InitAllowedExtensionIDs)
		if len(ids) > 0 {
			return ids
		}
	}

	return normalizeAllowedExtensionIDs(config.Cfg.AllowedExtensionIDs)
}

func loadAllowedExtensionIDsFromRedis() ([]string, string, error) {
	if redisClient.Client == nil {
		return nil, "none", fmt.Errorf("redis client is not initialized")
	}

	keyType, err := redisClient.Client.Type(redisClient.Ctx, allowedExtensionsRedisKey).Result()
	if err != nil {
		return nil, "", err
	}

	switch keyType {
	case "none":
		return nil, keyType, nil
	case "set":
		members, err := redisClient.Client.SMembers(redisClient.Ctx, allowedExtensionsRedisKey).Result()
		if err != nil {
			return nil, keyType, err
		}
		return normalizeAllowedExtensionIDs(members), keyType, nil
	case "string":
		raw, err := redisClient.Client.Get(redisClient.Ctx, allowedExtensionsRedisKey).Result()
		if err == redis.Nil {
			return nil, keyType, nil
		}
		if err != nil {
			return nil, keyType, err
		}
		return parseExtensionIDsRaw(raw), keyType, nil
	case "list":
		values, err := redisClient.Client.LRange(redisClient.Ctx, allowedExtensionsRedisKey, 0, -1).Result()
		if err != nil {
			return nil, keyType, err
		}
		return normalizeAllowedExtensionIDs(values), keyType, nil
	default:
		return nil, keyType, fmt.Errorf("unsupported redis key type: %s", keyType)
	}
}

func loadAllowedExtensionIDSet() (map[string]struct{}, string) {
	ids, sourceType, err := loadAllowedExtensionIDsFromRedis()
	if err != nil {
		log.Printf("WARN extension whitelist redis load failed, fallback to env/config: key=%q err=%v", allowedExtensionsRedisKey, err)
	} else if len(ids) > 0 {
		set := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			set[id] = struct{}{}
		}
		return set, "redis:" + sourceType
	}

	fallback := loadAllowedExtensionIDsFromEnvOrConfig()
	set := make(map[string]struct{}, len(fallback))
	for _, id := range fallback {
		set[id] = struct{}{}
	}
	return set, "env_or_config"
}

func getAllowedExtensionIDSet() map[string]struct{} {
	now := time.Now()

	allowedExtensionsCache.mu.RLock()
	if now.Before(allowedExtensionsCache.expiresAt) && len(allowedExtensionsCache.ids) > 0 {
		ids := allowedExtensionsCache.ids
		allowedExtensionsCache.mu.RUnlock()
		return ids
	}
	allowedExtensionsCache.mu.RUnlock()

	allowedExtensionsCache.mu.Lock()
	defer allowedExtensionsCache.mu.Unlock()

	now = time.Now()
	if now.Before(allowedExtensionsCache.expiresAt) && len(allowedExtensionsCache.ids) > 0 {
		return allowedExtensionsCache.ids
	}

	ids, source := loadAllowedExtensionIDSet()
	allowedExtensionsCache.ids = ids
	allowedExtensionsCache.source = source
	allowedExtensionsCache.expiresAt = now.Add(allowedExtensionsReloadInterval)
	log.Printf(
		"INFO extension whitelist cache refreshed: source=%s count=%d ids=%v next_refresh_in=%s",
		source,
		len(ids),
		mapKeysSorted(ids),
		allowedExtensionsReloadInterval,
	)

	return allowedExtensionsCache.ids
}

func resetAllowedExtensionsCache() {
	allowedExtensionsCache.mu.Lock()
	defer allowedExtensionsCache.mu.Unlock()
	allowedExtensionsCache.ids = nil
	allowedExtensionsCache.source = ""
	allowedExtensionsCache.expiresAt = time.Time{}
}

func isExtensionAllowed(extensionID string) bool {
	if extensionID == "" {
		return false
	}
	extensionID = strings.TrimSpace(extensionID)
	if extensionID == "" {
		return false
	}
	extensionID = strings.ToLower(extensionID)

	ids := getAllowedExtensionIDSet()
	if _, ok := ids[extensionID]; ok {
		return true
	}

	// 兼容 Firefox 风格的 "{id}" 与无花括号写法
	if strings.HasPrefix(extensionID, "{") && strings.HasSuffix(extensionID, "}") {
		trimmed := strings.TrimPrefix(strings.TrimSuffix(extensionID, "}"), "{")
		_, ok := ids[trimmed]
		return ok
	}
	if _, ok := ids["{"+extensionID+"}"]; ok {
		return true
	}

	return false
}

func mapKeysSorted(m map[string]struct{}) []string {
	if len(m) == 0 {
		return []string{}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func getAllowedExtensionsSnapshotForLog() (string, []string) {
	_ = getAllowedExtensionIDSet()
	allowedExtensionsCache.mu.RLock()
	defer allowedExtensionsCache.mu.RUnlock()
	return allowedExtensionsCache.source, mapKeysSorted(allowedExtensionsCache.ids)
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

func checkAuthRateLimit(clientIP string) bool {
	limit := config.Cfg.LimitAuthRPM
	if limit <= 0 {
		return true
	}
	if redisClient.Client == nil {
		log.Printf("WARN auth rate_limit bypass due to nil redis client: ip=%s", clientIP)
		return true
	}

	key := fmt.Sprintf("rate:auth:%s", clientIP)
	count, err := redisClient.Client.Incr(redisClient.Ctx, key).Result()
	if err != nil {
		log.Printf("WARN auth rate_limit bypass due to redis error: ip=%s key=%q err=%v", clientIP, key, err)
		return true
	}

	if count == 1 {
		if err := redisClient.Client.Expire(redisClient.Ctx, key, 60*time.Second).Err(); err != nil {
			log.Printf("WARN auth rate_limit ttl set failed: ip=%s key=%q err=%v", clientIP, key, err)
		}
	}

	return count <= int64(limit)
}
