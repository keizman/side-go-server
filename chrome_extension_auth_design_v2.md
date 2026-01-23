# Chrome 扩展认证系统设计文档 v2.0


## 目录

1. [系统架构概览](#1-系统架构概览)
2. [第一部分：通信协议设计](#2-第一部分通信协议设计-the-protocol)
3. [第二部分：后台服务设计](#3-第二部分后台服务设计-go-server)
4. [第三部分：网关配置](#4-第三部分网关配置-nginxopenresty)
5. [第四部分：客户端逻辑](#5-第四部分客户端逻辑-chrome-extension)
6. [第五部分：环境变量与配置](#6-第五部分环境变量与配置)
7. [附录：安全检查清单](#7-附录安全检查清单)

---
是此设计的代码归属地, E:\git\goog_trans\side-go-server 

## 1. 系统架构概览

### 1.1 架构图

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Chrome Extension                                │
│  ┌─────────────┐  ┌─────────────────┐  ┌─────────────────────────────┐  │
│  │ AuthManager │  │RequestInterceptor│  │ chrome.storage.local       │  │
│  │ - Token管理  │  │ - 签名计算       │  │ - authState (Token/过期时间)│  │
│  │ - 刷新锁    │  │ - Header构造     │  │ - tempId (设备ID)          │  │
│  │ - Alarm检查 │  │ - 重试机制       │  │                            │  │
│  └──────┬──────┘  └────────┬────────┘  └─────────────────────────────┘  │
└─────────┼──────────────────┼────────────────────────────────────────────┘
          │                  │
          ▼                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                              Nginx                                       │
│  ┌──────────────┐  ┌────────────────┐  ┌────────────────────────────┐  │
│  │ /auth_token  │  │ /_check_token  │  │ /*                     │  │
│  │ (直接转发)    │  │ (内部子请求)    │  │ auth_request → 业务层     │  │
│  │              │  │ ↓              │  │ auth_request_set 传递UID  │  │
│  └──────┬───────┘  │ Auth Service   │  └────────────┬───────────────┘  │
└─────────┼──────────┴───────┬────────┴───────────────┼───────────────────┘
          │                  │                        │
          ▼                  ▼                        ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                           Go Backend                                     │
│  ┌────────────────────────┐      ┌──────────────────────────────────┐  │
│  │ Auth Service (MODE=AUTH)│      │ Business Service (MODE=BUSINESS) │  │
│  │ - /auth_token           │      │ - AuthSDK 中间件                  │  │
│  │   · 扩展ID白名单校验     │      │   · Token 提取                   │  │
│  │   · 动态盐值校验        │      │   · 签名验证                     │  │
│  │   · Token 生成          │      │   · UID/Role 注入                │  │
│  │ - /check_token          │      │ - 业务接口                       │  │
│  │   · Token 解密验证      │      │   · /api/login                   │  │
│  │   · Redis 存在性校验    │      │   · /api/logout                  │  │
│  │   · Nonce 重放检查      │      │   · /api/translate 等            │  │
│  │   · 速率限制            │      │                                  │  │
│  └────────────┬───────────┘      └────────────────┬─────────────────┘  │
└───────────────┼────────────────────────────────────┼─────────────────────┘
                │                                    │
                ▼                                    ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                              Redis                                       │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ token:{identity}:{device_id}  = "encrypted_token"   TTL=3600s    │  │
│  │ nonce:{identity}:{nonce}      = "1"                 TTL=310s     │  │
│  │ rate:user:{user_id}           = count               TTL=60s      │  │
│  │ rate:guest:{temp_id}          = count               TTL=60s      │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 核心设计原则

| 原则 | 实现方式 |
|------|----------|
| 零信任 | 每个请求都需验证 Token + 签名 |
| 纵深防御 | Nginx 限流 → Auth 验证 → Business 验签 |
| 最小权限 | 游客/用户分级，不同速率限制 |
| 防重放 | Timestamp 窗口 + Nonce 唯一性 |
| 设备绑定 | Token 与 temp-id 绑定 |

---

## 2. 第一部分：通信协议设计 (The Protocol)

这是客户端与服务器交互的硬性规定。

### 2.1 统一请求头 (Headers)

所有请求（`/auth_token` 的首次请求除外）必须携带以下 Header：

| Header Key | 说明 | 来源/生成逻辑 | 必填 |
|------------|------|---------------|------|
| `Authorization` | `Bearer <TOKEN>` | 从 `/auth_token` 获取的 AES-GCM 加密令牌 | ✅ |
| `x-user-id` | 用户 ID | 登录用户填真实 ID，未登录留空 | ❌ |
| `x-temp-id` | 临时设备 ID | 基于 UUID 生成，同设备同浏览器必须固定 | ✅ |
| `x-timestamp` | Unix 时间戳 (秒) | `Math.floor(Date.now() / 1000)` | ✅ |
| `x-nonce` | 随机字符串 (16字符) | 每次请求生成，防重放 | ✅ |
| `x-extension-id` | 扩展 ID | Chrome 官方分配的 ID (防盗用) | ✅ |
| `x-extension-version` | 版本号 | 例如 `10801` (用于灰度/强制更新) | ✅ |
| `x-sign` | HMAC-SHA256 签名用于校验 body 未篡改 | 见下方签名算法 | ✅ |

**首次请求 `/auth_token` 时的额外 Header：**

| Header Key | 说明 | 来源/生成逻辑 |
|------------|------|---------------|
| `x-init-salt` | 初始盐值 | 客户端基于算法生成（见 2.3 节） |

### 2.2 签名算法 (Signature)

签名是防止**中间人篡改 (MITM)** 的核心机制。

#### 2.2.1 签名参数

| 参数 | 值 |
|------|------|
| **密钥 (Key)** | 当前有效的 TOKEN 字符串 |
| **算法** | HMAC-SHA256 |
| **分隔符** | `\|` (竖线) |

#### 2.2.2 Payload 构造规则

**GET 请求：**
```
x-sign = SortedQueryString + "|" + x-timestamp 

示例:
  URL: /api/search?b=2&a=1&c=3
  Timestamp: 1704067200
  
  SortedQuery: a=1&b=2&c=3
  Payload: "a=1&b=2&c=3|1704067200"
```

**POST/PUT/DELETE 请求：**
```
Payload = SHA256(RawBody) + "|" + x-timestamp

示例:
  Body: {"data":"hello","name":"test"}
  Timestamp: 1704067200
  

```

#### 2.2.3 签名计算

```javascript
// 客户端 JavaScript
const signature = HMAC_SHA256(payload, token);
// 将结果放入 Header: x-sign
```

```go
// 服务端 Go
serverSign := hmacSHA256(payload, token)
if !hmac.Equal([]byte(serverSign), []byte(clientSign)) {
    // 签名不匹配，拒绝请求
}
```

### 2.3 初始盐值生成算法

首次获取 Token 时，客户端需提供 `x-init-salt`，用于证明是合法客户端。

**客户端生成逻辑：**
```javascript
function generateInitSalt(extensionId, timestamp) {
    // 1. 获取硬编码的客户端密钥（混淆存储）
    const clientSecret = getObfuscatedSecret(); // 例如: "j21902j1mfkla-"
    
    // 2. 构造原始数据（时间戳去掉最后2位，允许小误差）
    const truncatedTimestamp = timestamp.toString().slice(0, -2);
    const payload = extensionId + "|" + truncatedTimestamp;
    
    // 3. HMAC 计算并截取
    const fullHash = HMAC_SHA256(payload, clientSecret);
    return fullHash.substring(0, 32);
}
```

**服务端验证逻辑：**
```go
func verifyInitSalt(extensionID, timestamp, clientSalt string) bool {
    serverSecret := os.Getenv("CLIENT_SALT_SECRET")
    truncatedTs := timestamp[:len(timestamp)-2]
    payload := extensionID + "|" + truncatedTs
    expectedSalt := hmacSHA256(payload, serverSecret)[:32]
    return hmac.Equal([]byte(expectedSalt), []byte(clientSalt))
}
```



---

## 3. 第二部分：后台服务设计 (Go Server)

同一个 Go 程序编译，通过环境变量 `SERVICE_MODE` 区分运行模式。

### 3.1 中间层 (Mode: AUTH)

职责：仅负责**颁发 Token** 和 **验证 Token 有效性**，不处理业务。

#### 3.1.1 接口 A: `/auth_token` (颁发令牌)

**请求方式：** POST

**请求 Headers：**
| Header | 首次获取 | 刷新 Token |
|--------|---------|-----------|
| `x-temp-id` | ✅ | ✅ |
| `x-extension-id` | ✅ | ✅ |
| `x-timestamp` | ✅ | ✅ |
| `x-user-id` | ❌ (空) | ✅ (如已登录) |
| `x-init-salt` | ✅ | ❌ |
| `Authorization` | ❌ | ✅ (旧 Token) |

**完整实现逻辑：**

```go
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
    "math"
    "os"
    "strconv"
    "strings"
    "time"

    "github.com/gin-gonic/gin"
    "github.com/go-redis/redis/v8"
)

// TokenPayload Token 内部结构
type TokenPayload struct {
    UID      string `json:"uid"`       // 用户ID或临时ID
    Role     string `json:"role"`      // guest | user
    DeviceID string `json:"device_id"` // 设备ID
    Exp      int64  `json:"exp"`       // 过期时间戳
    Iat      int64  `json:"iat"`       // 签发时间戳
}

// AuthTokenResponse 响应结构
type AuthTokenResponse struct {
    Token         string `json:"token"`
    ExpiresIn     int    `json:"expires_in"`
    CheckInterval int    `json:"check_interval"`
}

// AuthToken 颁发令牌接口
func AuthToken(c *gin.Context) {
    tempID := c.GetHeader("x-temp-id")
    extensionID := c.GetHeader("x-extension-id")
    timestamp := c.GetHeader("x-timestamp")
    userID := c.GetHeader("x-user-id")
    clientSalt := c.GetHeader("x-init-salt")
    authHeader := c.GetHeader("Authorization")

    // ========== 1. 基础校验 ==========
    
    // 1.1 必填字段校验
    if tempID == "" || extensionID == "" || timestamp == "" {
        c.AbortWithStatusJSON(400, gin.H{"error": "Missing required headers"})
        return
    }

    // 1.2 扩展 ID 白名单校验
    if !isExtensionAllowed(extensionID) {
        c.AbortWithStatusJSON(403, gin.H{"error": "Invalid extension ID"})
        return
    }

    // 1.3 时间戳校验 (60秒窗口)
    if !isTimestampValid(timestamp, 60) {
        c.AbortWithStatusJSON(401, gin.H{"error": "Timestamp expired"})
        return
    }

    // ========== 2. 身份确认 ==========
    
    var identity string
    var role string
    oldToken := extractBearerToken(authHeader)

    if oldToken != "" {
        // 场景A: 携带旧 Token 刷新
        payload, err := decryptToken(oldToken)
        if err != nil {
            c.AbortWithStatusJSON(401, gin.H{"error": "Invalid token format"})
            return
        }

        // 验证旧 Token 是否在 Redis 中（防止已登出的 Token 刷新）
        redisKey := fmt.Sprintf("token:%s:%s", payload.UID, payload.DeviceID)
        storedToken, err := redisClient.Get(ctx, redisKey).Result()
        if err != nil || storedToken != oldToken {
            c.AbortWithStatusJSON(401, gin.H{"error": "Token revoked or expired"})
            return
        }

        // 删除旧 Token
        redisClient.Del(ctx, redisKey)

        identity = payload.UID
        role = payload.Role

        // 如果请求携带了新的 userID（登录升级场景）
        if userID != "" && userID != identity {
            identity = userID
            role = "user"
        }

    } else if clientSalt != "" {
        // 场景B: 首次获取 Token
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

    // ========== 3. 生成新 Token ==========
    
    tokenTTL := getEnvInt("TOKEN_TTL_SECONDS", 3600)
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

    // ========== 4. 存入 Redis ==========
    
    redisKey := fmt.Sprintf("token:%s:%s", identity, tempID)
    err = redisClient.SetEX(ctx, redisKey, newToken, time.Duration(tokenTTL)*time.Second).Err()
    if err != nil {
        c.AbortWithStatusJSON(500, gin.H{"error": "Token storage failed"})
        return
    }

    // ========== 5. 返回响应 ==========
    
    c.JSON(200, AuthTokenResponse{
        Token:         newToken,
        ExpiresIn:     tokenTTL,
        CheckInterval: 300, // 建议客户端每5分钟检查一次
    })
}

// ========== 辅助函数 ==========

func isExtensionAllowed(extensionID string) bool {
    allowedIDs := strings.Split(os.Getenv("ALLOWED_EXTENSION_IDS"), ",")
    for _, id := range allowedIDs {
        if strings.TrimSpace(id) == extensionID {
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
    serverSecret := os.Getenv("CLIENT_SALT_SECRET")
    if serverSecret == "" {
        return false
    }
    // 时间戳去掉最后2位，允许小误差
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
    secret := os.Getenv("SERVER_SECRET")
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
    secret := os.Getenv("SERVER_SECRET")
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

func getEnvInt(key string, defaultVal int) int {
    if val := os.Getenv(key); val != "" {
        if i, err := strconv.Atoi(val); err == nil {
            return i
        }
    }
    return defaultVal
}
```

#### 3.1.2 接口 B: `/check_token` (内部接口，供 Nginx 调用)

**请求方式：** GET (内部子请求)

**完整实现逻辑：**

```go
// CheckToken 验证 Token 有效性（供 Nginx auth_request 调用）
func CheckToken(c *gin.Context) {
    authHeader := c.GetHeader("Authorization")
    timestamp := c.GetHeader("x-timestamp")
    nonce := c.GetHeader("x-nonce")
    tempID := c.GetHeader("x-temp-id")

    // ========== 1. 基础校验 ==========
    
    token := extractBearerToken(authHeader)
    if token == "" {
        c.AbortWithStatus(401)
        return
    }

    if tempID == "" || timestamp == "" || nonce == "" {
        c.AbortWithStatus(400)
        return
    }

    // ========== 2. 时间戳校验 (300秒窗口) ==========
    
    toleranceSeconds := getEnvInt("TIMESTAMP_TOLERANCE_SECONDS", 300)
    if !isTimestampValid(timestamp, int64(toleranceSeconds)) {
        c.AbortWithStatus(401)
        return
    }

    // ========== 3. Token 解密与验证 ==========
    
    payload, err := decryptToken(token)
    if err != nil {
        c.AbortWithStatus(401)
        return
    }

    // 3.1 检查 Token 内嵌的过期时间
    if time.Now().Unix() > payload.Exp {
        c.AbortWithStatus(401)
        return
    }

    // 3.2 检查设备 ID 是否匹配
    if payload.DeviceID != tempID {
        c.AbortWithStatus(401)
        return
    }

    // ========== 4. Redis 存在性校验 ==========
    
    redisKey := fmt.Sprintf("token:%s:%s", payload.UID, tempID)
    storedToken, err := redisClient.Get(ctx, redisKey).Result()
    if err == redis.Nil {
        c.AbortWithStatus(401) // Token 不存在（已登出或过期）
        return
    } else if err != nil {
        c.AbortWithStatus(500)
        return
    }

    if storedToken != token {
        c.AbortWithStatus(401) // Token 不匹配（可能被刷新替换）
        return
    }

    // ========== 5. Nonce 重放检查 ==========
    
    nonceKey := fmt.Sprintf("nonce:%s:%s", payload.UID, nonce)
    nonceTTL := getEnvInt("NONCE_TTL_SECONDS", 310)

    // 使用 SetNX 原子操作
    set, err := redisClient.SetNX(ctx, nonceKey, "1", time.Duration(nonceTTL)*time.Second).Result()
    if err != nil {
        c.AbortWithStatus(500)
        return
    }
    if !set {
        // Nonce 已存在，说明是重放攻击
        c.AbortWithStatus(401)
        return
    }

    // ========== 6. 速率限制 ==========
    
    if !checkRateLimit(payload.UID, payload.Role, tempID) {
        c.AbortWithStatus(429)
        return
    }

    // ========== 7. 验证通过，设置响应头 ==========
    
    c.Header("X-Verified-UID", payload.UID)
    c.Header("X-Verified-Role", payload.Role)
    c.Header("X-Verified-DeviceID", payload.DeviceID)
    c.Status(200)
}

// checkRateLimit 速率限制检查
func checkRateLimit(uid, role, tempID string) bool {
    var key string
    var limit int

    if role == "user" {
        key = fmt.Sprintf("rate:user:%s", uid)
        limit = getEnvInt("LIMIT_USER_RPM", 20)
    } else {
        key = fmt.Sprintf("rate:guest:%s", tempID)
        limit = getEnvInt("LIMIT_GUEST_RPM", 3)
    }

    // 滑动窗口计数
    count, err := redisClient.Incr(ctx, key).Result()
    if err != nil {
        return true // Redis 错误时放行，避免影响正常请求
    }

    if count == 1 {
        redisClient.Expire(ctx, key, 60*time.Second)
    }

    return count <= int64(limit)
}
```

### 3.2 内层业务层 (Mode: BUSINESS)

职责：处理 `/api/login`, `/api/translate` 等业务，必须嵌入 **AuthSDK 中间件**。

#### 3.2.1 AuthSDK 中间件

所有业务接口路由都必须包裹此中间件。

```go
package middleware

import (
    "bytes"
    "crypto/hmac"
    "crypto/sha256"
    "fmt"
    "io"
    "net/url"
    "sort"
    "strings"

    "github.com/gin-gonic/gin"
)

// VerifySignature 验证请求签名
func VerifySignature() gin.HandlerFunc {
    return func(c *gin.Context) {
        // ========== 1. 提取必要信息 ==========
        
        authHeader := c.GetHeader("Authorization")
        if !strings.HasPrefix(authHeader, "Bearer ") {
            c.AbortWithStatusJSON(401, gin.H{"error": "Invalid authorization header"})
            return
        }
        token := strings.TrimPrefix(authHeader, "Bearer ")

        timestamp := c.GetHeader("x-timestamp")
        tempID := c.GetHeader("x-temp-id")
        clientSign := c.GetHeader("x-sign")

        if timestamp == "" || tempID == "" || clientSign == "" {
            c.AbortWithStatusJSON(400, gin.H{"error": "Missing required headers"})
            return
        }

        // ========== 2. 构造 Payload ==========
        
        var payload string

        if c.Request.Method == "GET" {
            // GET: SortedQuery + "|" + timestamp + "|" + tempID
            sortedQuery := sortQueryString(c.Request.URL.Query())
            payload = fmt.Sprintf("%s|%s|%s", sortedQuery, timestamp, tempID)
        } else {
            // POST/PUT/DELETE: SHA256(Body) + "|" + timestamp + "|" + tempID
            bodyBytes, err := io.ReadAll(c.Request.Body)
            if err != nil {
                c.AbortWithStatusJSON(400, gin.H{"error": "Failed to read request body"})
                return
            }
            // 回写 Body 供后续 Handler 使用
            c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

            bodyHash := sha256Hex(bodyBytes)
            payload = fmt.Sprintf("%s|%s|%s", bodyHash, timestamp, tempID)
        }

        // ========== 3. 计算服务端签名 ==========
        
        serverSign := hmacSHA256(payload, token)

        // ========== 4. 常量时间比对（防止时序攻击）==========
        
        if !hmac.Equal([]byte(serverSign), []byte(clientSign)) {
            c.AbortWithStatusJSON(403, gin.H{"error": "Signature verification failed"})
            return
        }

        // ========== 5. 注入已验证的用户信息 ==========
        
        // 这些信息由 Nginx 从 Auth Service 传递过来
        c.Set("verified_uid", c.GetHeader("X-Verified-UID"))
        c.Set("verified_role", c.GetHeader("X-Verified-Role"))
        c.Set("verified_device_id", c.GetHeader("X-Verified-DeviceID"))

        c.Next()
    }
}

// sortQueryString 对 Query 参数排序并拼接
func sortQueryString(query url.Values) string {
    if len(query) == 0 {
        return ""
    }

    keys := make([]string, 0, len(query))
    for k := range query {
        keys = append(keys, k)
    }
    sort.Strings(keys)

    var pairs []string
    for _, k := range keys {
        values := query[k]
        sort.Strings(values) // 同一个 key 的多个 value 也排序
        for _, v := range values {
            pairs = append(pairs, fmt.Sprintf("%s=%s", k, v))
        }
    }
    return strings.Join(pairs, "&")
}

// sha256Hex 计算 SHA256 并返回十六进制字符串
func sha256Hex(data []byte) string {
    h := sha256.New()
    h.Write(data)
    return fmt.Sprintf("%x", h.Sum(nil))
}

// hmacSHA256 计算 HMAC-SHA256 并返回十六进制字符串
func hmacSHA256(data, key string) string {
    h := hmac.New(sha256.New, []byte(key))
    h.Write([]byte(data))
    return fmt.Sprintf("%x", h.Sum(nil))
}
```

#### 3.2.2 登录/登出接口

```go
package api

import (
    "fmt"

    "github.com/gin-gonic/gin"
)

// LoginRequest 登录请求
type LoginRequest struct {
    Email    string `json:"email" binding:"required,email"`
    Password string `json:"password" binding:"required,min=6"`
}

// LoginResponse 登录响应
type LoginResponse struct {
    UserID  string `json:"user_id"`
    Email   string `json:"email"`
    Action  string `json:"action"` // "refresh_token" 指示客户端需刷新 Token
}

// Login 登录接口
func Login(c *gin.Context) {
    var req LoginRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(400, gin.H{"error": "Invalid request body"})
        return
    }

    tempID := c.GetHeader("x-temp-id")

    // ========== 1. 验证用户凭据 ==========
    
    user, err := userService.Authenticate(req.Email, req.Password)
    if err != nil {
        c.JSON(401, gin.H{"error": "Invalid email or password"})
        return
    }

    // ========== 2. 删除该设备上的旧游客 Token ==========
    
    guestTokenKey := fmt.Sprintf("token:%s:%s", tempID, tempID)
    redisClient.Del(ctx, guestTokenKey)

    // ========== 3. 返回用户信息 ==========
    
    c.JSON(200, LoginResponse{
        UserID:  user.ID,
        Email:   user.Email,
        Action:  "refresh_token", // 客户端收到后需调用 /auth_token 获取新 Token
    })
}

// Logout 登出接口
func Logout(c *gin.Context) {
    uid := c.GetString("verified_uid")
    deviceID := c.GetString("verified_device_id")

    if uid == "" || deviceID == "" {
        c.JSON(400, gin.H{"error": "Not authenticated"})
        return
    }

    // 删除当前设备的 Token
    tokenKey := fmt.Sprintf("token:%s:%s", uid, deviceID)
    redisClient.Del(ctx, tokenKey)

    c.JSON(200, gin.H{"message": "Logged out successfully"})
}

// LogoutAllDevices 登出所有设备
func LogoutAllDevices(c *gin.Context) {
    uid := c.GetString("verified_uid")

    if uid == "" {
        c.JSON(400, gin.H{"error": "Not authenticated"})
        return
    }

    // 删除该用户的所有 Token
    pattern := fmt.Sprintf("token:%s:*", uid)
    keys, _ := redisClient.Keys(ctx, pattern).Result()
    if len(keys) > 0 {
        redisClient.Del(ctx, keys...)
    }

    c.JSON(200, gin.H{
        "message":         "Logged out from all devices",
        "devices_cleared": len(keys),
    })
}
```

#### 3.2.3 路由配置

```go
package main

import (
    "os"

    "github.com/gin-gonic/gin"
    "your-project/api"
    "your-project/auth"
    "your-project/middleware"
)

func main() {
    mode := os.Getenv("SERVICE_MODE")
    port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }

    r := gin.Default()

    switch mode {
    case "AUTH":
        // Auth Service 路由
        r.POST("/auth_token", auth.AuthToken)
        r.GET("/check_token", auth.CheckToken)

    case "BUSINESS":
        // Business Service 路由
        apiGroup := r.Group("/api")
        apiGroup.Use(middleware.VerifySignature())
        {
            // 用户相关
            apiGroup.POST("/login", api.Login)
            apiGroup.POST("/logout", api.Logout)
            apiGroup.POST("/logout_all", api.LogoutAllDevices)

            // 业务接口
            apiGroup.POST("/translate", api.Translate)
            apiGroup.GET("/user/profile", api.GetProfile)
            // ... 其他业务接口
        }

    default:
        panic("SERVICE_MODE must be AUTH or BUSINESS")
    }

    r.Run(":" + port)
}
```

---

## 4. 第三部分：网关配置 (Nginx/OpenResty)

Nginx 充当守门员，利用 `auth_request` 模块将鉴权卸载给中间层。

### 4.1 完整 Nginx 配置

```nginx
http {
    # ========== 日志格式 ==========
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" '
                    'uid=$upstream_http_x_verified_uid';

    # ========== 限流区域定义 ==========
    
    # IP 级限流 (粗粒度防御)
    limit_req_zone $binary_remote_addr zone=ip_limit:10m rate=100r/m;
    
    # Auth 接口限流 (防止暴力刷 Token)
    limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=10r/m;

    # ========== 上游服务定义 ==========
    
    upstream auth_service {
        server 127.0.0.1:8081;
        keepalive 32;
    }

    upstream business_service {
        server 127.0.0.1:8082;
        keepalive 64;
    }

    # ========== 主服务器配置 ==========
    
    server {
        listen 80;
        server_name api.your-domain.com;

        # 通用响应头
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;

        # ========== 1. 获取 Token 的接口 (不需要鉴权) ==========
        
        location /auth_token {
            # 专用限流
            limit_req zone=auth_limit burst=5 nodelay;
            
            # CORS 配置 (根据需要调整)
            add_header Access-Control-Allow-Origin "chrome-extension://*" always;
            add_header Access-Control-Allow-Methods "POST, OPTIONS" always;
            add_header Access-Control-Allow-Headers "Authorization, x-temp-id, x-user-id, x-timestamp, x-extension-id, x-extension-version, x-init-salt, Content-Type" always;

            if ($request_method = OPTIONS) {
                return 204;
            }

            proxy_pass http://auth_service/auth_token;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        # ========== 2. 内部鉴权子请求 (不对外暴露) ==========
        
        location = /_check_token {
            internal;
            
            proxy_pass http://auth_service/check_token;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            
            # 不传递请求体
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            
            # 传递原始请求信息
            proxy_set_header X-Original-URI $request_uri;
            proxy_set_header X-Original-Method $request_method;
            
            # 传递所有必要的 Header
            proxy_set_header Authorization $http_authorization;
            proxy_set_header x-timestamp $http_x_timestamp;
            proxy_set_header x-nonce $http_x_nonce;
            proxy_set_header x-temp-id $http_x_temp_id;
            proxy_set_header x-user-id $http_x_user_id;
            proxy_set_header x-extension-id $http_x_extension_id;
            proxy_set_header x-extension-version $http_x_extension_version;
        }

        # ========== 3. 业务接口 (需要鉴权) ==========
        
        location / {
            # IP 级限流
            limit_req zone=ip_limit burst=20 nodelay;

            # CORS 配置
            add_header Access-Control-Allow-Origin "chrome-extension://*" always;
            add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
            add_header Access-Control-Allow-Headers "Authorization, x-temp-id, x-user-id, x-timestamp, x-nonce, x-extension-id, x-extension-version, x-sign, Content-Type" always;

            if ($request_method = OPTIONS) {
                return 204;
            }

            # 调用鉴权服务
            auth_request /_check_token;

            # 【关键】从 auth 响应中提取用户信息并传递给业务层, 信任内部接口获取的真实 uid 和身份, 
            auth_request_set $verified_uid $upstream_http_x_verified_uid;
            auth_request_set $verified_role $upstream_http_x_verified_role;
            auth_request_set $verified_device_id $upstream_http_x_verified_device_id;

            # 错误处理
            error_page 401 = @handle_401;
            error_page 429 = @handle_429;

            # 转发给业务层
            proxy_pass http://business_service;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            
            # 传递已验证的用户信息
            proxy_set_header X-Verified-UID $verified_uid;
            proxy_set_header X-Verified-Role $verified_role;
            proxy_set_header X-Verified-DeviceID $verified_device_id;
            
            # 传递原始 Header (供业务层验签)
            proxy_set_header Authorization $http_authorization;
            proxy_set_header x-timestamp $http_x_timestamp;
            proxy_set_header x-temp-id $http_x_temp_id;
            proxy_set_header x-sign $http_x_sign;
        }

        # ========== 错误处理 ==========
        
        location @handle_401 {
            default_type application/json;
            return 401 '{"code":401,"error":"Token expired or invalid","action":"refresh_token"}';
        }

        location @handle_429 {
            default_type application/json;
            add_header Retry-After 60 always;
            return 429 '{"code":429,"error":"Rate limit exceeded","retry_after":60}';
        }

        # ========== 健康检查 ==========
        
        location /health {
            access_log off;
            return 200 'OK';
        }
    }
}
```

---

## 5. 第四部分：客户端逻辑 (Chrome Extension)

客户端采用**状态持久化 + 并发安全 + 自动刷新**机制。

### 5.1 配置常量

```javascript
// config.js
export const AuthConfig = {
    // Token 配置
    tokenRefreshThreshold: 600,  // 剩余 10 分钟时提前刷新
    tokenCheckInterval: 120,     // 每 2 分钟检查一次 (秒)
    
    // 重试配置
    maxRetryCount: 3,
    retryDelay: 1000,  // 毫秒
    
    // API 端点
    authEndpoint: 'https://api.your-domain.com/auth_token',
    apiBaseUrl: 'https://api.your-domain.com/api',
};
```

### 5.2 AuthManager 类

```javascript
// auth-manager.js
import { AuthConfig } from './config.js';
import { generateInitSalt, hmacSHA256, sha256Hex } from './crypto.js';

class AuthManager {
    constructor() {
        this.state = null;
        this.refreshPromise = null;
        this.initialized = false;
    }

    // ========== 初始化 ==========

    async init() {
        if (this.initialized) return;

        // 从 Storage 恢复状态
        const stored = await chrome.storage.local.get(['authState', 'tempId']);
        
        if (stored.authState) {
            this.state = stored.authState;
        }

        if (!stored.tempId) {
            // 首次安装，生成设备 ID
            const tempId = crypto.randomUUID();
            await chrome.storage.local.set({ tempId });
        }

        this.initialized = true;
        this.startCheckLoop();
    }

    // ========== Token 获取 ==========

    async getValidToken() {
        await this.init();

        const now = Date.now();

        // 无 Token 或已过期
        if (!this.state || now >= this.state.expiryTime) {
            await this.refreshToken();
        }
        // 即将过期，后台刷新
        else if (now >= this.state.expiryTime - AuthConfig.tokenRefreshThreshold * 1000) {
            this.refreshToken().catch(err => {
                console.warn('Background token refresh failed:', err);
            });
        }

        return this.state.token;
    }

    // ========== Token 刷新（带锁）==========

    async refreshToken(forceNew = false) {
        // 如果已有刷新在进行，等待其完成
        if (this.refreshPromise) {
            return this.refreshPromise;
        }

        this.refreshPromise = this._doRefresh(forceNew);

        try {
            return await this.refreshPromise;
        } finally {
            this.refreshPromise = null;
        }
    }

    async _doRefresh(forceNew) {
        const stored = await chrome.storage.local.get(['tempId', 'userId']);
        const tempId = stored.tempId;
        const userId = stored.userId || '';
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const extensionId = chrome.runtime.id;
        const extensionVersion = chrome.runtime.getManifest().version.replace(/\./g, '');

        const headers = {
            'Content-Type': 'application/json',
            'x-temp-id': tempId,
            'x-extension-id': extensionId,
            'x-extension-version': extensionVersion,
            'x-timestamp': timestamp,
            'x-user-id': userId,
        };

        // 场景判断：首次获取 vs 刷新
        if (this.state?.token && !forceNew) {
            // 刷新场景：携带旧 Token
            headers['Authorization'] = `Bearer ${this.state.token}`;
        } else {
            // 首次获取：携带初始盐值
            headers['x-init-salt'] = generateInitSalt(extensionId, timestamp);
        }

        const response = await fetch(AuthConfig.authEndpoint, {
            method: 'POST',
            headers,
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.error || `Auth failed: ${response.status}`);
        }

        const data = await response.json();

        // 更新状态
        this.state = {
            token: data.token,
            expiryTime: Date.now() + data.expires_in * 1000,
            checkInterval: data.check_interval || AuthConfig.tokenCheckInterval,
            userId: userId,
        };

        // 持久化
        await chrome.storage.local.set({ authState: this.state });

        return this.state;
    }

    // ========== 定期检查 ==========

    startCheckLoop() {
        // 使用 Alarm API (Service Worker 友好)
        chrome.alarms.create('tokenCheck', {
            periodInMinutes: AuthConfig.tokenCheckInterval / 60,
        });
    }

    async handleAlarm() {
        await this.init();
        
        if (!this.state) return;

        const now = Date.now();
        const threshold = AuthConfig.tokenRefreshThreshold * 1000;

        if (now >= this.state.expiryTime - threshold) {
            try {
                await this.refreshToken();
                console.log('Token refreshed by alarm');
            } catch (err) {
                console.error('Alarm token refresh failed:', err);
            }
        }
    }

    // ========== 登录/登出 ==========

    async onLoginSuccess(userId) {
        // 保存 userId
        await chrome.storage.local.set({ userId });
        
        // 强制获取新 Token
        await this.refreshToken(true);
    }

    async onLogout() {
        // 清除本地状态
        this.state = null;
        await chrome.storage.local.remove(['authState', 'userId']);
        
        // 获取新的游客 Token
        await this.refreshToken(true);
    }
}

export const authManager = new AuthManager();
```

### 5.3 RequestInterceptor 类

```javascript
// request-interceptor.js
import { AuthConfig } from './config.js';
import { authManager } from './auth-manager.js';
import { hmacSHA256, sha256Hex, generateNonce, sortQueryParams } from './crypto.js';

class RequestInterceptor {
    constructor() {
        this.tempId = null;
        this.extensionId = chrome.runtime.id;
        this.extensionVersion = chrome.runtime.getManifest().version.replace(/\./g, '');
    }

    async init() {
        if (this.tempId) return;
        
        const stored = await chrome.storage.local.get('tempId');
        this.tempId = stored.tempId;
    }

    // ========== 主请求方法 ==========

    async fetch(url, options = {}, retryCount = 0) {
        await this.init();
        await authManager.init();

        const token = await authManager.getValidToken();
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const nonce = generateNonce(16);
        const method = options.method || 'GET';

        // 计算签名
        const sign = await this.calculateSign(method, url, options.body, timestamp, token);

        // 构造 Headers
        const headers = {
            ...options.headers,
            'Authorization': `Bearer ${token}`,
            'x-user-id': authManager.state?.userId || '',
            'x-temp-id': this.tempId,
            'x-timestamp': timestamp,
            'x-nonce': nonce,
            'x-extension-id': this.extensionId,
            'x-extension-version': this.extensionVersion,
            'x-sign': sign,
        };

        if (options.body && typeof options.body === 'object') {
            headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(options.body);
        }

        try {
            const response = await fetch(url, { ...options, headers });

            // 处理 401 错误
            if (response.status === 401 && retryCount < AuthConfig.maxRetryCount) {
                const errorData = await response.json().catch(() => ({}));
                
                if (errorData.action === 'refresh_token') {
                    // Token 过期，刷新后重试
                    await authManager.refreshToken();
                    return this.fetch(url, options, retryCount + 1);
                }
            }

            return response;

        } catch (error) {
            // 网络错误重试
            if (retryCount < AuthConfig.maxRetryCount) {
                await this.delay(AuthConfig.retryDelay * (retryCount + 1));
                return this.fetch(url, options, retryCount + 1);
            }
            throw error;
        }
    }

    // ========== 签名计算 ==========

    async calculateSign(method, url, body, timestamp, token) {
        let payload;

        if (method === 'GET') {
            const urlObj = new URL(url);
            const sortedParams = sortQueryParams(urlObj.searchParams);
            payload = `${sortedParams}|${timestamp}|${this.tempId}`;
        } else {
            const bodyStr = typeof body === 'string' ? body : JSON.stringify(body || {});
            const bodyHash = await sha256Hex(bodyStr);
            payload = `${bodyHash}|${timestamp}|${this.tempId}`;
        }

        return hmacSHA256(payload, token);
    }

    // ========== 便捷方法 ==========

    async get(url, options = {}) {
        return this.fetch(url, { ...options, method: 'GET' });
    }

    async post(url, body, options = {}) {
        return this.fetch(url, { ...options, method: 'POST', body });
    }

    async put(url, body, options = {}) {
        return this.fetch(url, { ...options, method: 'PUT', body });
    }

    async delete(url, options = {}) {
        return this.fetch(url, { ...options, method: 'DELETE' });
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

export const httpClient = new RequestInterceptor();
```

### 5.4 加密工具函数

```javascript
// crypto.js

// 硬编码的客户端密钥（实际应用中需要混淆）
const CLIENT_SECRET = 'j21902j1mfkla-your-obfuscated-secret';

/**
 * 生成初始盐值
 */
export function generateInitSalt(extensionId, timestamp) {
    const truncatedTs = timestamp.toString().slice(0, -2);
    const payload = `${extensionId}|${truncatedTs}`;
    return hmacSHA256(payload, CLIENT_SECRET).substring(0, 32);
}

/**
 * 生成随机 Nonce
 */
export function generateNonce(length = 16) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => chars[byte % chars.length]).join('');
}

/**
 * 排序 Query 参数
 */
export function sortQueryParams(params) {
    const sorted = [...params.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    return sorted.map(([k, v]) => `${k}=${v}`).join('&');
}

/**
 * SHA256 哈希
 */
export async function sha256Hex(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    return bufferToHex(hashBuffer);
}

/**
 * HMAC-SHA256
 */
export async function hmacSHA256(message, key) {
    const keyData = new TextEncoder().encode(key);
    const msgData = new TextEncoder().encode(message);

    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', cryptoKey, msgData);
    return bufferToHex(signature);
}

/**
 * ArrayBuffer 转十六进制字符串
 */
function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}
```

### 5.5 Service Worker 入口

```javascript
// background.js (Service Worker)
import { authManager } from './auth-manager.js';

// ========== 安装/更新时初始化 ==========

chrome.runtime.onInstalled.addListener(async (details) => {
    console.log('Extension installed:', details.reason);
    await authManager.init();
});

// ========== Service Worker 激活时恢复状态 ==========

self.addEventListener('activate', async () => {
    console.log('Service Worker activated');
    await authManager.init();
});

// ========== Alarm 处理 ==========

chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === 'tokenCheck') {
        await authManager.handleAlarm();
    }
});

// ========== 消息处理（来自 Content Script 或 Popup）==========

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message).then(sendResponse);
    return true; // 保持消息通道开放
});

async function handleMessage(message) {
    switch (message.type) {
        case 'GET_TOKEN':
            await authManager.init();
            return { token: await authManager.getValidToken() };

        case 'LOGIN_SUCCESS':
            await authManager.onLoginSuccess(message.userId);
            return { success: true };

        case 'LOGOUT':
            await authManager.onLogout();
            return { success: true };

        case 'GET_AUTH_STATE':
            return { state: authManager.state };

        default:
            return { error: 'Unknown message type' };
    }
}
```

### 5.6 使用示例

```javascript
// 在 Content Script 或 Popup 中使用
import { httpClient } from './request-interceptor.js';
import { AuthConfig } from './config.js';

// ========== 普通 API 调用 ==========

async function translateText(text, targetLang) {
    const response = await httpClient.post(
        `${AuthConfig.apiBaseUrl}/translate`,
        { text, target_lang: targetLang }
    );
    
    if (!response.ok) {
        throw new Error('Translation failed');
    }
    
    return response.json();
}

// ========== 登录流程 ==========

async function login(email, password) {
    const response = await httpClient.post(
        `${AuthConfig.apiBaseUrl}/login`,
        { email, password }
    );
    
    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Login failed');
    }
    
    const data = await response.json();
    
    // 通知 Service Worker 登录成功
    if (data.action === 'refresh_token') {
        await chrome.runtime.sendMessage({
            type: 'LOGIN_SUCCESS',
            userId: data.user_id,
        });
    }
    
    return data;
}

// ========== 登出流程 ==========

async function logout() {
    await httpClient.post(`${AuthConfig.apiBaseUrl}/logout`);
    await chrome.runtime.sendMessage({ type: 'LOGOUT' });
}
```

---

## 6. 第五部分：环境变量与配置

### 6.1 完整 .env 文件

```env
# ============================================================
# Chrome Extension Backend - Environment Configuration
# ============================================================

# ========== 基础配置 ==========
APP_NAME=ExtensionBackend
SERVICE_MODE=AUTH
# 可选值: AUTH (中间层) | BUSINESS (业务层)

PORT=8081
# AUTH 服务默认 8081, BUSINESS 服务默认 8082

GIN_MODE=release
# 可选值: debug | release | test

# ========== 安全密钥 ==========

# Token 加密密钥 (必须 32 字节, 用于 AES-256-GCM)
SERVER_SECRET=YourSuperLongRandomString32Bytes!!

# 客户端初始盐值计算密钥 (用于动态生成盐值)
CLIENT_SALT_SECRET=AnotherRandomSecretForSaltGen123

# ========== 数据库配置 ==========

SQL_DSN=postgres://postgres:password@localhost:5432/extension_db?sslmode=disable
SQL_MAX_IDLE_CONNS=100
SQL_MAX_OPEN_CONNS=1000
SQL_MAX_LIFETIME=60
# 单位: 秒

# ========== Redis 配置 ==========

REDIS_CONN_STRING=redis://default:password@localhost:6379/0
# 格式: redis://user:pass@host:port/db

REDIS_POOL_SIZE=100
REDIS_MIN_IDLE_CONNS=10

# ========== Token 配置 ==========

TOKEN_TTL_SECONDS=3600
# Token 有效期, 默认 1 小时

TIMESTAMP_TOLERANCE_SECONDS=300
# 时间戳容差, 默认 5 分钟

NONCE_TTL_SECONDS=310
# Nonce 有效期, 略大于时间戳容差

# ========== 速率限制 ==========

LIMIT_GUEST_RPM=10
# 游客每分钟请求数

LIMIT_USER_RPM=20
# 登录用户每分钟请求数

LIMIT_AUTH_RPM=10
# /auth_token 每分钟请求数 (IP 级)

# ========== 扩展白名单, 初始值, 若 redis 为空则写入redis, 之后从 redis 读取 ==========

INIT_ALLOWED_EXTENSION_IDS=abcdefghijklmnopqrstuvwxyz1234,anothertextensionid5678901234
# 逗号分隔的合法扩展 ID 列表

# ========== 第三方服务, 后续使用 ==========

GOOGLE_CLIENT_ID=731421594606-xxx.apps.googleusercontent.com
# Google OAuth 客户端 ID (如需 Google 登录)

# ========== 日志配置 ==========

LOG_LEVEL=info
# 可选值: debug | info | warn | error

LOG_FORMAT=json
# 可选值: json | text
```

### 6.2 配置加载代码

```go
package config

import (
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
    RedisConnString  string
    RedisPoolSize    int
    RedisMinIdleConns int

    // Token
    TokenTTL            time.Duration
    TimestampTolerance  time.Duration
    NonceTTL            time.Duration

    // 速率限制
    LimitGuestRPM int
    LimitUserRPM  int
    LimitAuthRPM  int

    // 扩展白名单
    AllowedExtensionIDs []string

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
        LimitGuestRPM: getEnvInt("LIMIT_GUEST_RPM", 3),
        LimitUserRPM:  getEnvInt("LIMIT_USER_RPM", 20),
        LimitAuthRPM:  getEnvInt("LIMIT_AUTH_RPM", 10),

        // 扩展白名单
        AllowedExtensionIDs: strings.Split(getEnv("ALLOWED_EXTENSION_IDS", ""), ","),

        // 第三方
        GoogleClientID: getEnv("GOOGLE_CLIENT_ID", ""),

        // 日志
        LogLevel:  getEnv("LOG_LEVEL", "info"),
        LogFormat: getEnv("LOG_FORMAT", "json"),
    }

    return validate()
}

func validate() error {
    if len(Cfg.ServerSecret) < 32 {
        panic("SERVER_SECRET must be at least 32 bytes")
    }
    if len(Cfg.AllowedExtensionIDs) == 0 || Cfg.AllowedExtensionIDs[0] == "" {
        panic("ALLOWED_EXTENSION_IDS must not be empty")
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
```

---

## 7. 附录：安全检查清单

### 7.1 实现状态

| 检查项 | 状态 | 实现位置 | 说明 |
|--------|------|----------|------|
| Token 加密 | ✅ | Auth Service | AES-256-GCM |
| Token 内嵌过期时间 | ✅ | TokenPayload.Exp | 双重检查 |
| Redis TTL | ✅ | token:{id}:{device} | 3600秒 |
| 时间戳校验 | ✅ | check_token | 300秒窗口 |
| Nonce 防重放 | ✅ | check_token | Redis 存储 |
| 签名防篡改 | ✅ | Business Middleware | HMAC-SHA256 |
| 设备绑定 | ✅ | TokenPayload.DeviceID | x-temp-id |
| 常量时间比对 | ✅ | hmac.Equal | 防时序攻击 |
| IP 级限流 | ✅ | Nginx | 100r/m |
| 用户级限流 | ✅ | check_token | 3/20 r/m |
| 扩展 ID 白名单 | ✅ | auth_token | 环境变量配置 |
| 动态初始盐值 | ✅ | auth_token | HMAC 生成 |
| Token 刷新锁 | ✅ | Client AuthManager | Promise 复用 |
| 状态持久化 | ✅ | chrome.storage.local | Service Worker 友好 |
| Alarm 定时检查 | ✅ | chrome.alarms | 2分钟间隔 |

### 7.2 安全流程图

```
首次获取 Token:
┌──────────┐         ┌───────┐          ┌──────────────┐       ┌───────┐
│Extension │         │ Nginx │          │ Auth Service │       │ Redis │
└────┬─────┘         └───┬───┘          └──────┬───────┘       └───┬───┘
     │ POST /auth_token  │                     │                   │
     │ x-init-salt=xxx   │                     │                   │
     │   │                     │                   │
     │──────────────────>│                     │                   │
     │                   │ proxy_pass          │                   │
     │                   │────────────────────>│                   │
     │                   │                     │ 1. 校验扩展ID白名单│
     │                   │                     │ 2. 验证动态盐值    │
     │                   │                     │ 3. 生成加密 Token │
     │                   │                     │ SETEX token:xxx   │
     │                   │                     │───────────────────>│
     │                   │                     │<───────────────────│
     │                   │<────────────────────│                   │
     │<──────────────────│                     │                   │
     │ {token, expires_in}                     │                   │


业务请求流程:
┌──────────┐      ┌───────┐      ┌──────────────┐   ┌─────────────┐   ┌───────┐
│Extension │      │ Nginx │      │ Auth Service │   │Bus. Service │   │ Redis │
└────┬─────┘      └───┬───┘      └──────┬───────┘   └──────┬──────┘   └───┬───┘
     │ GET /api/data  │                 │                  │              │
     │ Authorization  │                 │                  │              │
     │ x-sign, x-nonce│                 │                  │              │
     │───────────────>│                 │                  │              │
     │                │ auth_request    │                  │              │
     │                │ /_check_token   │                  │              │
     │                │────────────────>│                  │              │
     │                │                 │ 1. 解密 Token    │              │
     │                │                 │ 2. 检查过期时间  │              │
     │                │                 │ 3. Redis 校验    │              │
     │                │                 │─────────────────────────────────>│
     │                │                 │<─────────────────────────────────│
     │                │                 │ 4. Nonce 检查    │              │
     │                │                 │─────────────────────────────────>│
     │                │                 │ 5. 速率限制      │              │
     │                │<────────────────│                  │              │
     │                │ 200 + Headers   │                  │              │
     │                │                 │                  │              │
     │                │ proxy_pass      │                  │              │
     │                │────────────────────────────────────>│              │
     │                │                 │                  │ 验证签名     │
     │                │                 │                  │ 处理业务     │
     │                │<────────────────────────────────────│              │
     │<───────────────│                 │                  │              │
     │ {data}         │                 │                  │              │
```

扩展: 除了 VerifySignature GO 之外, 维护一个代码相同单使用 python 写的库, 以及一个相同代码使用 ts 写的库, 用于目前兼容阶段我依旧需要使用 python server 服务某一个 api , 这时需要使用 这个 python/ts 库进行 sign 校验.

extension 修改: 如上放所述, 需要进行 token 验证, 因此需要在浏览器启动时就获取token , 如果长时间置于后台后可能无法实时更新, 并且为了不浪费电量, 
❌ 旧方案：每 2 分钟轮询检查（浪费电量）
✅ 新方案：事件驱动 + 请求时检查（按需刷新）触发 Token 检查/刷新的时机时机事件说明浏览器启动chrome.runtime.onStartup冷启动时获取 Token扩展安装/更新chrome.runtime.onInstalled首次安装或更新后从后台恢复chrome.idle.onStateChanged用户从离开/锁屏恢复发送请求前请求拦截器Lazy 检查，最可靠



## 完整的刷新策略总结
```
┌─────────────────────────────────────────────────────────────────┐
│                      Token 刷新触发时机                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐                                               │
│  │ 浏览器启动    │ ──→ onStartup ──→ checkAndRefreshIfNeeded   │
│  └──────────────┘                                               │
│                                                                 │
│  ┌──────────────┐                                               │
│  │ 扩展安装/更新 │ ──→ onInstalled ──→ checkAndRefreshIfNeeded │
│  └──────────────┘                                               │
│                                                                 │
│  ┌──────────────┐                                               │
│  │ 用户离开后返回│ ──→ idle.onStateChanged("active")            │
│  │ (锁屏/切走)  │     ──→ checkAndRefreshIfNeeded              │
│  └──────────────┘                                               │
│                                                                 │
│  ┌──────────────┐                                               │
│  │ 发送 API 请求│ ──→ getValidToken() ──→ 按需刷新             │
│  │ （最后防线） │     （过期则等待，即将过期则后台刷新）         │
│  └──────────────┘                                               │
│                                                                 │
│  ┌──────────────┐                                               │
│  │ 页面变为可见 │ ──→ visibilitychange ──→ CHECK_TOKEN 消息    │
│  │ （可选）     │                                               │
│  └──────────────┘                    

nginx 的配置我自己会配置到对饮位置, 你不需要理会, 只有你认为有冲突时提醒我

### 7.3 攻击防护说明

| 攻击类型 | 防护措施 |
|----------|----------|
| **中间人攻击 (MITM)** | HTTPS + HMAC 签名 |
| **重放攻击** | Timestamp 窗口 + Nonce 唯一性 |
| **Token 窃取** | AES-GCM 加密 + 设备绑定 + Redis 撤销 |
| **暴力破解** | IP 级限流 + 用户级限流 |
| **扩展盗用** | Extension ID 白名单 + 动态盐值 |
| **时序攻击** | hmac.Equal 常量时间比对 |
| **Token 过期后使用** | 双重检查 (Redis TTL + Token 内嵌时间) |

