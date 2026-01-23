package main

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/yourname/side-go-server/api"
	"github.com/yourname/side-go-server/auth"
	"github.com/yourname/side-go-server/config"
	"github.com/yourname/side-go-server/internal/redis"
	"github.com/yourname/side-go-server/middleware"
)

func main() {
	if err := config.Load(); err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	if err := redis.InitRedis(); err != nil {
		log.Fatalf("Failed to initialize Redis: %v", err)
	}
	defer redis.Close()

	gin.SetMode(config.Cfg.GinMode)

	r := gin.Default()

	mode := config.Cfg.ServiceMode
	fmt.Printf("🚀 Starting server in %s mode on port %s\n", mode, config.Cfg.Port)

	switch mode {
	case "AUTH":
		r.POST("/auth_token", auth.AuthToken)
		r.GET("/check_token", auth.CheckToken)

	case "BUSINESS":
		apiGroup := r.Group("/api")
		apiGroup.Use(middleware.VerifySignature())
		{
			apiGroup.POST("/login", api.Login)
			apiGroup.POST("/logout", api.Logout)
			apiGroup.POST("/logout_all", api.LogoutAllDevices)
			apiGroup.POST("/translate", api.Translate)
			apiGroup.GET("/user/profile", api.GetProfile)
		}

	default:
		log.Fatalf("SERVICE_MODE must be AUTH or BUSINESS, got: %s", mode)
	}

	if err := r.Run(":" + config.Cfg.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
