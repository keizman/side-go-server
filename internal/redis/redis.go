package redis

import (
	"context"
	"fmt"

	"github.com/go-redis/redis/v8"
	"github.com/yourname/side-go-server/config"
)

var (
	Client *redis.Client
	Ctx    = context.Background()
)

// InitRedis 初始化 Redis 连接
func InitRedis() error {
	opt, err := redis.ParseURL(config.Cfg.RedisConnString)
	if err != nil {
		return fmt.Errorf("failed to parse redis url: %w", err)
	}

	opt.PoolSize = config.Cfg.RedisPoolSize
	opt.MinIdleConns = config.Cfg.RedisMinIdleConns

	Client = redis.NewClient(opt)

	// 测试连接
	if err := Client.Ping(Ctx).Err(); err != nil {
		return fmt.Errorf("failed to connect to redis: %w", err)
	}

	fmt.Println("✅ Redis connected successfully")
	return nil
}

// Close 关闭 Redis 连接
func Close() error {
	if Client != nil {
		return Client.Close()
	}
	return nil
}
