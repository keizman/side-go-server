package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/yourname/side-go-server/config"
	redisClient "github.com/yourname/side-go-server/internal/redis"
)

func setupAuthEnv(t *testing.T, mutate func(*config.Config)) *miniredis.Miniredis {
	t.Helper()

	gin.SetMode(gin.TestMode)
	mr := miniredis.RunT(t)
	redisClient.Client = redis.NewClient(&redis.Options{Addr: mr.Addr()})
	redisClient.Ctx = context.Background()

	cfg := &config.Config{
		ServerSecret:        strings.Repeat("s", 32),
		ClientSaltSecret:    "client-salt-secret",
		AllowedExtensionIDs: []string{"ext-good"},
		TokenTTL:            2 * time.Minute,
		TimestampTolerance:  5 * time.Minute,
		NonceTTL:            2 * time.Minute,
		LimitGuestRPM:       5,
		LimitUserRPM:        5,
	}
	if mutate != nil {
		mutate(cfg)
	}
	config.Cfg = cfg
	resetAllowedExtensionsCache()
	oldInterval := allowedExtensionsReloadInterval
	allowedExtensionsReloadInterval = 10 * time.Second

	t.Cleanup(func() {
		allowedExtensionsReloadInterval = oldInterval
		resetAllowedExtensionsCache()
		_ = redisClient.Client.Close()
	})

	return mr
}

func runGinHandler(handler gin.HandlerFunc, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	handler(c)

	return w
}

func validInitSalt(extensionID, timestamp string) string {
	truncatedTs := timestamp
	if len(timestamp) > 2 {
		truncatedTs = timestamp[:len(timestamp)-2]
	}
	return hmacSHA256(extensionID+"|"+truncatedTs, config.Cfg.ClientSaltSecret)[:32]
}

func decodeAuthTokenResponse(t *testing.T, body []byte) AuthTokenResponse {
	t.Helper()
	var resp AuthTokenResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	return resp
}

func seedTokenInRedis(t *testing.T, uid, role, deviceID string, expiresAt int64) string {
	t.Helper()

	token, err := encryptToken(TokenPayload{
		UID:      uid,
		Role:     role,
		DeviceID: deviceID,
		Exp:      expiresAt,
		Iat:      time.Now().Unix(),
	})
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	key := fmt.Sprintf("token:%s:%s", uid, deviceID)
	if err := redisClient.Client.SetEX(redisClient.Ctx, key, token, config.Cfg.TokenTTL).Err(); err != nil {
		t.Fatalf("failed to seed token in redis: %v", err)
	}
	return token
}

func TestAuthToken(t *testing.T) {
	t.Run("Given missing required headers When requesting token Then returns 400", func(t *testing.T) {
		setupAuthEnv(t, nil)

		w := runGinHandler(AuthToken, http.MethodPost, "/auth_token", nil)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("Given extension is not allowed When requesting token Then returns 403", func(t *testing.T) {
		setupAuthEnv(t, nil)

		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		w := runGinHandler(AuthToken, http.MethodPost, "/auth_token", map[string]string{
			"x-temp-id":      "tmp-1",
			"x-extension-id": "ext-bad",
			"x-timestamp":    timestamp,
			"x-init-salt":    validInitSalt("ext-good", timestamp),
		})

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})

	t.Run("Given timestamp expired When requesting token Then returns 401", func(t *testing.T) {
		setupAuthEnv(t, nil)

		timestamp := fmt.Sprintf("%d", time.Now().Add(-10*time.Minute).Unix())
		w := runGinHandler(AuthToken, http.MethodPost, "/auth_token", map[string]string{
			"x-temp-id":      "tmp-1",
			"x-extension-id": "ext-good",
			"x-timestamp":    timestamp,
			"x-init-salt":    validInitSalt("ext-good", timestamp),
		})

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("Given timestamp is within configured tolerance When requesting token Then returns 200", func(t *testing.T) {
		setupAuthEnv(t, func(cfg *config.Config) {
			cfg.TimestampTolerance = 10 * time.Minute
		})

		timestamp := fmt.Sprintf("%d", time.Now().Add(-2*time.Minute).Unix())
		w := runGinHandler(AuthToken, http.MethodPost, "/auth_token", map[string]string{
			"x-temp-id":      "tmp-1",
			"x-extension-id": "ext-good",
			"x-timestamp":    timestamp,
			"x-init-salt":    validInitSalt("ext-good", timestamp),
		})

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d, body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("Given no authorization and no init salt When requesting token Then returns 400", func(t *testing.T) {
		setupAuthEnv(t, nil)

		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		w := runGinHandler(AuthToken, http.MethodPost, "/auth_token", map[string]string{
			"x-temp-id":      "tmp-1",
			"x-extension-id": "ext-good",
			"x-timestamp":    timestamp,
		})

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("Given valid init salt without user id When requesting token Then issues guest token and stores it", func(t *testing.T) {
		setupAuthEnv(t, nil)

		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		tempID := "guest-1"
		w := runGinHandler(AuthToken, http.MethodPost, "/auth_token", map[string]string{
			"x-temp-id":      tempID,
			"x-extension-id": "ext-good",
			"x-timestamp":    timestamp,
			"x-init-salt":    validInitSalt("ext-good", timestamp),
		})

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d, body=%s", w.Code, w.Body.String())
		}

		resp := decodeAuthTokenResponse(t, w.Body.Bytes())
		payload, err := decryptToken(resp.Token)
		if err != nil {
			t.Fatalf("failed to decrypt token: %v", err)
		}
		if payload.UID != tempID || payload.Role != "guest" || payload.DeviceID != tempID {
			t.Fatalf("unexpected payload: %+v", payload)
		}

		stored, err := redisClient.Client.Get(redisClient.Ctx, "token:"+tempID+":"+tempID).Result()
		if err != nil {
			t.Fatalf("failed reading token from redis: %v", err)
		}
		if stored != resp.Token {
			t.Fatalf("stored token mismatch")
		}
	})

	t.Run("Given valid init salt with user id When requesting token Then issues user token", func(t *testing.T) {
		setupAuthEnv(t, nil)

		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		w := runGinHandler(AuthToken, http.MethodPost, "/auth_token", map[string]string{
			"x-temp-id":      "device-1",
			"x-extension-id": "ext-good",
			"x-timestamp":    timestamp,
			"x-user-id":      "user-123",
			"x-init-salt":    validInitSalt("ext-good", timestamp),
		})

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}

		resp := decodeAuthTokenResponse(t, w.Body.Bytes())
		payload, err := decryptToken(resp.Token)
		if err != nil {
			t.Fatalf("failed to decrypt token: %v", err)
		}
		if payload.UID != "user-123" || payload.Role != "user" {
			t.Fatalf("unexpected payload: %+v", payload)
		}
	})

	t.Run("Given valid existing token in redis When refreshing token Then old token is revoked and replaced", func(t *testing.T) {
		setupAuthEnv(t, nil)

		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		tempID := "device-refresh"

		first := runGinHandler(AuthToken, http.MethodPost, "/auth_token", map[string]string{
			"x-temp-id":      tempID,
			"x-extension-id": "ext-good",
			"x-timestamp":    timestamp,
			"x-init-salt":    validInitSalt("ext-good", timestamp),
		})
		if first.Code != http.StatusOK {
			t.Fatalf("expected first token request 200, got %d", first.Code)
		}
		firstResp := decodeAuthTokenResponse(t, first.Body.Bytes())

		second := runGinHandler(AuthToken, http.MethodPost, "/auth_token", map[string]string{
			"x-temp-id":      tempID,
			"x-extension-id": "ext-good",
			"x-timestamp":    fmt.Sprintf("%d", time.Now().Unix()),
			"Authorization":  "Bearer " + firstResp.Token,
		})

		if second.Code != http.StatusOK {
			t.Fatalf("expected refresh request 200, got %d, body=%s", second.Code, second.Body.String())
		}
		secondResp := decodeAuthTokenResponse(t, second.Body.Bytes())
		if secondResp.Token == firstResp.Token {
			t.Fatalf("expected refreshed token to differ from old token")
		}

		stored, err := redisClient.Client.Get(redisClient.Ctx, "token:"+tempID+":"+tempID).Result()
		if err != nil {
			t.Fatalf("failed reading refreshed token from redis: %v", err)
		}
		if stored != secondResp.Token {
			t.Fatalf("expected redis to hold refreshed token")
		}
	})

	t.Run("Given token is absent in redis When refreshing with old token Then returns 401", func(t *testing.T) {
		setupAuthEnv(t, nil)

		token, err := encryptToken(TokenPayload{
			UID:      "guest-2",
			Role:     "guest",
			DeviceID: "tmp-2",
			Exp:      time.Now().Add(1 * time.Minute).Unix(),
			Iat:      time.Now().Unix(),
		})
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		w := runGinHandler(AuthToken, http.MethodPost, "/auth_token", map[string]string{
			"x-temp-id":      "tmp-2",
			"x-extension-id": "ext-good",
			"x-timestamp":    fmt.Sprintf("%d", time.Now().Unix()),
			"Authorization":  "Bearer " + token,
		})

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("Given auth request rate exceeds limit When requesting token repeatedly Then returns 429", func(t *testing.T) {
		setupAuthEnv(t, func(cfg *config.Config) {
			cfg.LimitAuthRPM = 1
		})

		ts1 := fmt.Sprintf("%d", time.Now().Unix())
		first := runGinHandler(AuthToken, http.MethodPost, "/auth_token", map[string]string{
			"x-temp-id":      "tmp-limit-1",
			"x-extension-id": "ext-good",
			"x-timestamp":    ts1,
			"x-init-salt":    validInitSalt("ext-good", ts1),
		})
		if first.Code != http.StatusOK {
			t.Fatalf("expected first request 200, got %d", first.Code)
		}

		ts2 := fmt.Sprintf("%d", time.Now().Unix())
		second := runGinHandler(AuthToken, http.MethodPost, "/auth_token", map[string]string{
			"x-temp-id":      "tmp-limit-2",
			"x-extension-id": "ext-good",
			"x-timestamp":    ts2,
			"x-init-salt":    validInitSalt("ext-good", ts2),
		})
		if second.Code != http.StatusTooManyRequests {
			t.Fatalf("expected second request 429, got %d", second.Code)
		}
	})
}

func TestCheckToken(t *testing.T) {
	t.Run("Given authorization header is missing When checking token Then returns 401", func(t *testing.T) {
		setupAuthEnv(t, nil)

		w := runGinHandler(CheckToken, http.MethodGet, "/check_token", nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("Given required headers missing When checking token Then returns 400", func(t *testing.T) {
		setupAuthEnv(t, nil)
		token := seedTokenInRedis(t, "user-a", "user", "dev-1", time.Now().Add(1*time.Minute).Unix())

		w := runGinHandler(CheckToken, http.MethodGet, "/check_token", map[string]string{
			"Authorization": "Bearer " + token,
		})

		if w.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", w.Code)
		}
	})

	t.Run("Given valid token and fresh nonce When checking token Then returns 200 and verified headers", func(t *testing.T) {
		setupAuthEnv(t, nil)
		token := seedTokenInRedis(t, "user-a", "user", "dev-1", time.Now().Add(1*time.Minute).Unix())

		w := runGinHandler(CheckToken, http.MethodGet, "/check_token", map[string]string{
			"Authorization":  "Bearer " + token,
			"x-temp-id":      "dev-1",
			"x-timestamp":    fmt.Sprintf("%d", time.Now().Unix()),
			"x-nonce":        "nonce-1",
			"x-extension-id": "ext-good",
		})

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", w.Code)
		}
		if w.Header().Get("X-Verified-UID") != "user-a" || w.Header().Get("X-Verified-Role") != "user" {
			t.Fatalf("missing verified headers: %+v", w.Header())
		}
	})

	t.Run("Given timestamp is outside tolerance When checking token Then returns 401", func(t *testing.T) {
		setupAuthEnv(t, nil)
		token := seedTokenInRedis(t, "user-a", "user", "dev-1", time.Now().Add(1*time.Minute).Unix())

		w := runGinHandler(CheckToken, http.MethodGet, "/check_token", map[string]string{
			"Authorization":  "Bearer " + token,
			"x-temp-id":      "dev-1",
			"x-timestamp":    fmt.Sprintf("%d", time.Now().Add(-10*time.Minute).Unix()),
			"x-nonce":        "nonce-1",
			"x-extension-id": "ext-good",
		})

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("Given token device does not match request device When checking token Then returns 401", func(t *testing.T) {
		setupAuthEnv(t, nil)
		token := seedTokenInRedis(t, "user-a", "user", "dev-1", time.Now().Add(1*time.Minute).Unix())

		w := runGinHandler(CheckToken, http.MethodGet, "/check_token", map[string]string{
			"Authorization":  "Bearer " + token,
			"x-temp-id":      "dev-2",
			"x-timestamp":    fmt.Sprintf("%d", time.Now().Unix()),
			"x-nonce":        "nonce-1",
			"x-extension-id": "ext-good",
		})

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("Given token is not in redis When checking token Then returns 401", func(t *testing.T) {
		setupAuthEnv(t, nil)
		token, err := encryptToken(TokenPayload{
			UID:      "user-a",
			Role:     "user",
			DeviceID: "dev-1",
			Exp:      time.Now().Add(1 * time.Minute).Unix(),
			Iat:      time.Now().Unix(),
		})
		if err != nil {
			t.Fatalf("failed to create token: %v", err)
		}

		w := runGinHandler(CheckToken, http.MethodGet, "/check_token", map[string]string{
			"Authorization":  "Bearer " + token,
			"x-temp-id":      "dev-1",
			"x-timestamp":    fmt.Sprintf("%d", time.Now().Unix()),
			"x-nonce":        "nonce-1",
			"x-extension-id": "ext-good",
		})

		if w.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", w.Code)
		}
	})

	t.Run("Given nonce already used When checking token Then returns 401", func(t *testing.T) {
		setupAuthEnv(t, nil)
		token := seedTokenInRedis(t, "user-a", "user", "dev-1", time.Now().Add(1*time.Minute).Unix())

		headers := map[string]string{
			"Authorization":  "Bearer " + token,
			"x-temp-id":      "dev-1",
			"x-timestamp":    fmt.Sprintf("%d", time.Now().Unix()),
			"x-nonce":        "nonce-replay",
			"x-extension-id": "ext-good",
		}
		first := runGinHandler(CheckToken, http.MethodGet, "/check_token", headers)
		if first.Code != http.StatusOK {
			t.Fatalf("expected first check 200, got %d", first.Code)
		}

		second := runGinHandler(CheckToken, http.MethodGet, "/check_token", headers)
		if second.Code != http.StatusUnauthorized {
			t.Fatalf("expected second check 401, got %d", second.Code)
		}
	})

	t.Run("Given guest limit exceeded When checking token repeatedly Then returns 429", func(t *testing.T) {
		setupAuthEnv(t, func(cfg *config.Config) {
			cfg.LimitGuestRPM = 1
		})
		token := seedTokenInRedis(t, "guest-1", "guest", "dev-guest", time.Now().Add(1*time.Minute).Unix())

		first := runGinHandler(CheckToken, http.MethodGet, "/check_token", map[string]string{
			"Authorization":  "Bearer " + token,
			"x-temp-id":      "dev-guest",
			"x-timestamp":    fmt.Sprintf("%d", time.Now().Unix()),
			"x-nonce":        "nonce-a",
			"x-extension-id": "ext-good",
		})
		if first.Code != http.StatusOK {
			t.Fatalf("expected first check 200, got %d", first.Code)
		}

		second := runGinHandler(CheckToken, http.MethodGet, "/check_token", map[string]string{
			"Authorization":  "Bearer " + token,
			"x-temp-id":      "dev-guest",
			"x-timestamp":    fmt.Sprintf("%d", time.Now().Unix()),
			"x-nonce":        "nonce-b",
			"x-extension-id": "ext-good",
		})
		if second.Code != http.StatusTooManyRequests {
			t.Fatalf("expected 429, got %d", second.Code)
		}
	})

	t.Run("Given extension id is not allowed When checking token Then returns 403", func(t *testing.T) {
		setupAuthEnv(t, nil)
		token := seedTokenInRedis(t, "user-a", "user", "dev-1", time.Now().Add(1*time.Minute).Unix())

		w := runGinHandler(CheckToken, http.MethodGet, "/check_token", map[string]string{
			"Authorization":  "Bearer " + token,
			"x-temp-id":      "dev-1",
			"x-timestamp":    fmt.Sprintf("%d", time.Now().Unix()),
			"x-nonce":        "nonce-1",
			"x-extension-id": "ext-bad",
		})

		if w.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", w.Code)
		}
	})
}

func TestAuthUtilityFunctions(t *testing.T) {
	t.Run("Given bearer and non-bearer headers When extracting token Then behavior is correct", func(t *testing.T) {
		if got := extractBearerToken("Bearer abc"); got != "abc" {
			t.Fatalf("expected token abc, got %s", got)
		}
		if got := extractBearerToken("Token abc"); got != "" {
			t.Fatalf("expected empty token, got %s", got)
		}
	})

	t.Run("Given valid and invalid timestamps When checking tolerance Then return expected validity", func(t *testing.T) {
		now := fmt.Sprintf("%d", time.Now().Unix())
		if !isTimestampValid(now, 5) {
			t.Fatalf("expected current timestamp to be valid")
		}
		if isTimestampValid("not-int", 5) {
			t.Fatalf("expected non-integer timestamp to be invalid")
		}
	})

	t.Run("Given token payload When encrypting then decrypting Then payload is preserved", func(t *testing.T) {
		setupAuthEnv(t, nil)

		original := TokenPayload{UID: "u1", Role: "user", DeviceID: "d1", Exp: time.Now().Add(1 * time.Minute).Unix(), Iat: time.Now().Unix()}
		token, err := encryptToken(original)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		decoded, err := decryptToken(token)
		if err != nil {
			t.Fatalf("decrypt failed: %v", err)
		}
		if decoded.UID != original.UID || decoded.Role != original.Role || decoded.DeviceID != original.DeviceID {
			t.Fatalf("decoded payload mismatch: %+v", decoded)
		}
	})
}

func TestExtensionWhitelist(t *testing.T) {
	t.Run("Given redis whitelist key is empty When initializing whitelist Then seeds values from config", func(t *testing.T) {
		setupAuthEnv(t, func(cfg *config.Config) {
			cfg.AllowedExtensionIDs = []string{"ext-good", "ext-new"}
		})

		if err := InitExtensionWhitelist(); err != nil {
			t.Fatalf("expected init whitelist success, got %v", err)
		}

		members, err := redisClient.Client.SMembers(redisClient.Ctx, allowedExtensionsRedisKey).Result()
		if err != nil {
			t.Fatalf("failed to read redis whitelist: %v", err)
		}
		if len(members) != 2 {
			t.Fatalf("expected 2 whitelist entries, got %v", members)
		}
	})

	t.Run("Given redis whitelist already exists When initializing whitelist Then keeps redis as source of truth", func(t *testing.T) {
		setupAuthEnv(t, func(cfg *config.Config) {
			cfg.AllowedExtensionIDs = []string{"ext-env"}
		})

		if err := redisClient.Client.SAdd(redisClient.Ctx, allowedExtensionsRedisKey, "ext-redis").Err(); err != nil {
			t.Fatalf("failed to seed redis whitelist: %v", err)
		}

		if err := InitExtensionWhitelist(); err != nil {
			t.Fatalf("expected init whitelist success, got %v", err)
		}

		members, err := redisClient.Client.SMembers(redisClient.Ctx, allowedExtensionsRedisKey).Result()
		if err != nil {
			t.Fatalf("failed to read redis whitelist: %v", err)
		}
		if len(members) != 1 || members[0] != "ext-redis" {
			t.Fatalf("expected redis whitelist unchanged, got %v", members)
		}
	})

	t.Run("Given redis whitelist exists When extension id is only in redis Then auth_token accepts it", func(t *testing.T) {
		setupAuthEnv(t, func(cfg *config.Config) {
			cfg.AllowedExtensionIDs = []string{"ext-env"}
		})

		if err := redisClient.Client.SAdd(redisClient.Ctx, allowedExtensionsRedisKey, "ext-redis-only").Err(); err != nil {
			t.Fatalf("failed to seed redis whitelist: %v", err)
		}

		timestamp := fmt.Sprintf("%d", time.Now().Unix())
		w := runGinHandler(AuthToken, http.MethodPost, "/auth_token", map[string]string{
			"x-temp-id":      "tmp-redis",
			"x-extension-id": "ext-redis-only",
			"x-timestamp":    timestamp,
			"x-init-salt":    validInitSalt("ext-redis-only", timestamp),
		})

		if w.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d, body=%s", w.Code, w.Body.String())
		}
	})

	t.Run("Given redis whitelist stored as string When checking extension Then parser still allows it", func(t *testing.T) {
		setupAuthEnv(t, func(cfg *config.Config) {
			cfg.AllowedExtensionIDs = []string{"ext-env"}
		})

		if err := redisClient.Client.Set(redisClient.Ctx, allowedExtensionsRedisKey, "ext-a,ext-b", 0).Err(); err != nil {
			t.Fatalf("failed to seed string whitelist: %v", err)
		}

		resetAllowedExtensionsCache()
		if !isExtensionAllowed("ext-b") {
			t.Fatalf("expected ext-b to be allowed from redis string key")
		}
	})

	t.Run("Given env whitelist changes When cache expires Then new env value is applied", func(t *testing.T) {
		setupAuthEnv(t, func(cfg *config.Config) {
			cfg.AllowedExtensionIDs = []string{"ext-config"}
		})
		t.Setenv("INIT_ALLOWED_EXTENSION_IDS", "ext-env-a")
		allowedExtensionsReloadInterval = 50 * time.Millisecond

		resetAllowedExtensionsCache()
		if !isExtensionAllowed("ext-env-a") {
			t.Fatalf("expected ext-env-a to be allowed")
		}

		t.Setenv("INIT_ALLOWED_EXTENSION_IDS", "ext-env-b")
		// 缓存周期内仍应命中旧快照
		if isExtensionAllowed("ext-env-b") {
			t.Fatalf("expected ext-env-b to be unavailable before cache refresh")
		}

		time.Sleep(70 * time.Millisecond)
		if !isExtensionAllowed("ext-env-b") {
			t.Fatalf("expected ext-env-b to be allowed after cache refresh")
		}
	})

	t.Run("Given firefox style extension id with braces When whitelist stores plain id Then check still passes", func(t *testing.T) {
		setupAuthEnv(t, func(cfg *config.Config) {
			cfg.AllowedExtensionIDs = []string{"ec1a757b-3969-4e9a-86e9-c9cd54028a1f"}
		})

		if err := redisClient.Client.SAdd(redisClient.Ctx, allowedExtensionsRedisKey, "ec1a757b-3969-4e9a-86e9-c9cd54028a1f").Err(); err != nil {
			t.Fatalf("failed to seed redis whitelist: %v", err)
		}

		resetAllowedExtensionsCache()
		if !isExtensionAllowed("{ec1a757b-3969-4e9a-86e9-c9cd54028a1f}") {
			t.Fatalf("expected brace-wrapped extension id to be allowed")
		}
	})
}
