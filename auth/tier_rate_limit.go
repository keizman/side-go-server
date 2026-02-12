package auth

import (
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/yourname/side-go-server/config"
	"github.com/yourname/side-go-server/internal/database"
	redisClient "github.com/yourname/side-go-server/internal/redis"
)

const (
	tierFree = 1
	tierUser = 2
	tierPay  = 3
)

var userTierCacheTTL = 10 * time.Minute

type RateLimitContext struct {
	UID       string
	TempID    string
	Tier      int
	Route     string
	Method    string
	AuthState string
}

type RateLimitPolicy interface {
	CounterKey(ctx RateLimitContext) string
	LimitRPM(ctx RateLimitContext) int
}

type GlobalTierRateLimitPolicy struct {
	tierRPM map[int]int
}

func (p GlobalTierRateLimitPolicy) CounterKey(ctx RateLimitContext) string {
	tier := normalizeTier(ctx.Tier)
	identity := strings.TrimSpace(ctx.UID)
	if tier == tierFree || identity == "" {
		identity = strings.TrimSpace(ctx.TempID)
	}
	if identity == "" {
		identity = "unknown"
	}
	return fmt.Sprintf("rate:v2:tier:%d:scope:global:id:%s", tier, identity)
}

func (p GlobalTierRateLimitPolicy) LimitRPM(ctx RateLimitContext) int {
	tier := normalizeTier(ctx.Tier)
	limit, ok := p.tierRPM[tier]
	if ok {
		return limit
	}
	return p.tierRPM[tierUser]
}

func checkRateLimit(ctx RateLimitContext) bool {
	if redisClient.Client == nil {
		log.Printf("WARN rate_limit bypass due to nil redis client: uid=%q temp_id=%q tier=%d route=%q method=%q", ctx.UID, ctx.TempID, ctx.Tier, ctx.Route, ctx.Method)
		return true
	}

	ctx.Tier = normalizeTierWithAuthState(ctx.Tier, ctx.AuthState)
	policy := GlobalTierRateLimitPolicy{tierRPM: tierRPMMap()}
	limit := policy.LimitRPM(ctx)
	if limit <= 0 {
		return true
	}

	key := policy.CounterKey(ctx)
	count, err := redisClient.Client.Incr(redisClient.Ctx, key).Result()
	if err != nil {
		log.Printf("WARN rate_limit bypass due to redis error: uid=%q temp_id=%q tier=%d key=%q err=%v", ctx.UID, ctx.TempID, ctx.Tier, key, err)
		return true
	}

	if count == 1 {
		if err := redisClient.Client.Expire(redisClient.Ctx, key, 60*time.Second).Err(); err != nil {
			log.Printf("WARN rate_limit ttl set failed: uid=%q temp_id=%q tier=%d key=%q err=%v", ctx.UID, ctx.TempID, ctx.Tier, key, err)
		}
	}

	return count <= int64(limit)
}

func resolveUserTier(userID string) int {
	uid := strings.TrimSpace(userID)
	if uid == "" {
		return tierUser
	}

	if tier, ok := readUserTierFromRedis(uid); ok {
		return tier
	}
	if tier, ok := readUserTierFromDB(uid); ok {
		cacheUserTier(uid, tier)
		return tier
	}

	return tierUser
}

func readUserTierFromRedis(userID string) (int, bool) {
	if redisClient.Client == nil {
		return 0, false
	}
	key := fmt.Sprintf("user:tier:%s", userID)
	value, err := redisClient.Client.Get(redisClient.Ctx, key).Result()
	if err == redis.Nil {
		return 0, false
	}
	if err != nil {
		log.Printf("WARN read user tier from redis failed: user_id=%q key=%q err=%v", userID, key, err)
		return 0, false
	}

	tier, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		log.Printf("WARN user tier in redis is invalid: user_id=%q key=%q value=%q err=%v", userID, key, value, err)
		return 0, false
	}
	if !isValidTier(tier) {
		log.Printf("WARN user tier in redis is out of range: user_id=%q key=%q tier=%d", userID, key, tier)
		return 0, false
	}
	return tier, true
}

func readUserTierFromDB(userID string) (int, bool) {
	if database.DB == nil {
		return 0, false
	}
	var tier int
	query := `
		SELECT tier
		FROM users
		WHERE (username = $1 OR email = $1) AND deleted_at IS NULL
		LIMIT 1
	`
	err := database.DB.QueryRow(query, userID).Scan(&tier)
	if err == sql.ErrNoRows {
		return 0, false
	}
	if err != nil {
		log.Printf("WARN read user tier from db failed: user_id=%q err=%v", userID, err)
		return 0, false
	}
	if !isValidTier(tier) {
		log.Printf("WARN user tier in db is out of range: user_id=%q tier=%d", userID, tier)
		return 0, false
	}
	return tier, true
}

func cacheUserTier(userID string, tier int) {
	if redisClient.Client == nil || !isValidTier(tier) {
		return
	}
	key := fmt.Sprintf("user:tier:%s", userID)
	if err := redisClient.Client.Set(redisClient.Ctx, key, tier, userTierCacheTTL).Err(); err != nil {
		log.Printf("WARN cache user tier failed: user_id=%q key=%q tier=%d err=%v", userID, key, tier, err)
	}
}

func tierRPMMap() map[int]int {
	tier1 := config.Cfg.LimitTier1RPM
	tier2 := config.Cfg.LimitTier2RPM
	tier3 := config.Cfg.LimitTier3RPM

	if tier1 <= 0 {
		tier1 = config.Cfg.LimitGuestRPM
	}
	if tier2 <= 0 {
		tier2 = config.Cfg.LimitUserRPM
	}
	if tier3 <= 0 {
		tier3 = tier2 * 10
	}

	return map[int]int{
		tierFree: tier1,
		tierUser: tier2,
		tierPay:  tier3,
	}
}

func normalizeTierWithAuthState(tier int, authState string) int {
	if isValidTier(tier) {
		return tier
	}
	if strings.EqualFold(strings.TrimSpace(authState), "guest") {
		return tierFree
	}
	return tierUser
}

func normalizeTier(tier int) int {
	if isValidTier(tier) {
		return tier
	}
	return tierUser
}

func isValidTier(tier int) bool {
	return tier == tierFree || tier == tierUser || tier == tierPay
}
