package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	// 基础配置
	AppName     string
	ServiceMode string
	Port        string
	GinMode     string

	// 安全密钥
	ServerSecret     string
	ClientSaltSecret string

	// 数据库
	SQLDSN          string
	SQLMaxIdleConns int
	SQLMaxOpenConns int
	SQLMaxLifetime  time.Duration

	// Redis
	RedisConnString   string
	RedisPoolSize     int
	RedisMinIdleConns int

	// Token
	TokenTTL           time.Duration
	TimestampTolerance time.Duration
	NonceTTL           time.Duration

	// 速率限制
	LimitGuestRPM int
	LimitUserRPM  int
	LimitAuthRPM  int

	// 扩展白名单
	InitAllowedExtensionIDs string
	AllowedExtensionIDs     []string

	// 第三方
	GoogleClientID string

	// 日志
	LogLevel  string
	LogFormat string
}

var Cfg *Config

func Load() error {
	// 加载 .env 文件 (开发环境)
	_ = godotenv.Load()

	Cfg = &Config{
		// 基础配置
		AppName:     getEnv("APP_NAME", "ExtensionBackend"),
		ServiceMode: getEnv("SERVICE_MODE", "AUTH"),
		Port:        getEnv("PORT", "8080"),
		GinMode:     getEnv("GIN_MODE", "release"),

		// 安全密钥
		ServerSecret:     mustGetEnv("SERVER_SECRET"),
		ClientSaltSecret: mustGetEnv("CLIENT_SALT_SECRET"),

		// 数据库
		SQLDSN:          getEnv("SQL_DSN", ""),
		SQLMaxIdleConns: getEnvInt("SQL_MAX_IDLE_CONNS", 100),
		SQLMaxOpenConns: getEnvInt("SQL_MAX_OPEN_CONNS", 1000),
		SQLMaxLifetime:  time.Duration(getEnvInt("SQL_MAX_LIFETIME", 60)) * time.Second,

		// Redis
		RedisConnString:   mustGetEnv("REDIS_CONN_STRING"),
		RedisPoolSize:     getEnvInt("REDIS_POOL_SIZE", 100),
		RedisMinIdleConns: getEnvInt("REDIS_MIN_IDLE_CONNS", 10),

		// Token
		TokenTTL:           time.Duration(getEnvInt("TOKEN_TTL_SECONDS", 3600)) * time.Second,
		TimestampTolerance: time.Duration(getEnvInt("TIMESTAMP_TOLERANCE_SECONDS", 300)) * time.Second,
		NonceTTL:           time.Duration(getEnvInt("NONCE_TTL_SECONDS", 310)) * time.Second,

		// 速率限制
		LimitGuestRPM: getEnvInt("LIMIT_GUEST_RPM", 10),
		LimitUserRPM:  getEnvInt("LIMIT_USER_RPM", 20),
		LimitAuthRPM:  getEnvInt("LIMIT_AUTH_RPM", 10),

		// 扩展白名单
		InitAllowedExtensionIDs: getEnv("INIT_ALLOWED_EXTENSION_IDS", ""),

		// 第三方
		GoogleClientID: getEnv("GOOGLE_CLIENT_ID", ""),

		// 日志
		LogLevel:  getEnv("LOG_LEVEL", "info"),
		LogFormat: getEnv("LOG_FORMAT", "json"),
	}

	// 解析扩展 ID
	if Cfg.InitAllowedExtensionIDs != "" {
		Cfg.AllowedExtensionIDs = strings.Split(Cfg.InitAllowedExtensionIDs, ",")
		for i := range Cfg.AllowedExtensionIDs {
			Cfg.AllowedExtensionIDs[i] = strings.TrimSpace(Cfg.AllowedExtensionIDs[i])
		}
	}

	return validate()
}

func validate() error {
	if len(Cfg.ServerSecret) < 32 {
		return fmt.Errorf("SERVER_SECRET must be at least 32 bytes")
	}
	if len(Cfg.ClientSaltSecret) == 0 {
		return fmt.Errorf("CLIENT_SALT_SECRET is required")
	}
	if len(Cfg.AllowedExtensionIDs) == 0 || Cfg.AllowedExtensionIDs[0] == "" {
		return fmt.Errorf("INIT_ALLOWED_EXTENSION_IDS must not be empty")
	}
	if Cfg.RedisConnString == "" {
		return fmt.Errorf("REDIS_CONN_STRING is required")
	}
	return nil
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func mustGetEnv(key string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	panic("Missing required environment variable: " + key)
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}
