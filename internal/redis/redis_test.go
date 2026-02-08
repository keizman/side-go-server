package redis

import (
	"strings"
	"testing"

	miniredis "github.com/alicebob/miniredis/v2"
	"github.com/yourname/side-go-server/config"
)

func TestInitRedis(t *testing.T) {
	t.Run("Given invalid redis url When InitRedis called Then returns error", func(t *testing.T) {
		config.Cfg = &config.Config{
			RedisConnString:   "://bad-url",
			RedisPoolSize:     5,
			RedisMinIdleConns: 1,
		}

		err := InitRedis()
		if err == nil {
			t.Fatalf("expected InitRedis to fail for invalid url")
		}
	})

	t.Run("Given reachable redis endpoint When InitRedis called Then client is initialized", func(t *testing.T) {
		mr := miniredis.RunT(t)
		config.Cfg = &config.Config{
			RedisConnString:   "redis://" + mr.Addr() + "/1",
			RedisPoolSize:     8,
			RedisMinIdleConns: 2,
		}

		if err := InitRedis(); err != nil {
			t.Fatalf("InitRedis failed: %v", err)
		}
		t.Cleanup(func() {
			_ = Close()
		})

		if Client == nil {
			t.Fatalf("expected redis client to be initialized")
		}
		if Client.Options().PoolSize != 8 {
			t.Fatalf("expected pool size 8, got %d", Client.Options().PoolSize)
		}

		pong, err := Client.Ping(Ctx).Result()
		if err != nil {
			t.Fatalf("ping failed: %v", err)
		}
		if strings.ToUpper(pong) != "PONG" {
			t.Fatalf("expected PONG, got %s", pong)
		}
	})
}

func TestClose(t *testing.T) {
	t.Run("Given nil client When Close called Then no error", func(t *testing.T) {
		Client = nil
		if err := Close(); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})
}
