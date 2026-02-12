# Chrome Extension Authentication System

## Overview

This authentication system implements a secure token-based authentication mechanism for Chrome extensions, following the design specifications in `chrome_extension_auth_design_v2.md`.

## Architecture

### Components

1. **Go Backend Server** (`side-go-server/`)
   - Dual-mode operation: AUTH mode and BUSINESS mode
   - Token issuance and validation
   - Request signature verification
   - Redis-based token storage and nonce management

2. **Chrome Extension Auth Module** (`tranlation-overlay-extension/src/modules/auth/`)
   - Automatic token lifecycle management
   - Event-driven token refresh
   - Request signature calculation
   - HTTP client wrapper with auto-authentication

3. **Verification Libraries**
   - `auth_sdk.py` - Python signature verification
   - `auth_sdk.ts` - TypeScript signature verification

## Quick Start

### 1. Start Redis Server

```bash
# Install Redis (if not already installed)
# Windows: Download from https://github.com/microsoftarchive/redis/releases
# Linux: sudo apt-get install redis-server
# macOS: brew install redis

# Start Redis
redis-server
```

### 2. Configure Environment Variables

```bash
cd side-go-server
cp .env.example .env
```

Edit `.env` and set required values:

```env
# Required: Secret keys (MUST MATCH EXTENSION CONFIG)
AUTH_SECRET=your-32-character-secret-key-here-change-this
INIT_SALT_SECRET=your-32-character-init-salt-secret

# Redis configuration
REDIS_ADDR=localhost:6379
REDIS_PASSWORD=
REDIS_DB=0

# Server configuration
SERVICE_MODE=AUTH  # or BUSINESS
PORT=8081          # AUTH mode port (8080 for BUSINESS)
```

### 3. Start Auth Server

```bash
cd side-go-server
SERVICE_MODE=AUTH PORT=8081 ./server.exe
```

Server will start on `http://localhost:8081` and display:
```
🚀 Server running in AUTH mode on :8081
```

### 4. Start Business Server (Optional)

In another terminal:

```bash
cd side-go-server
SERVICE_MODE=BUSINESS PORT=8080 ./server.exe
```

### 5. Load Extension

1. Open Chrome and navigate to `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select `tranlation-overlay-extension/.output/chrome-mv3`

## API Endpoints

### AUTH Mode (Port 8081)

#### `POST /auth/token`
Issue new authentication token.

**Request:**
```json
{
  "temp_id": "guest_123abc",
  "device_id": "chrome_ext_xyz",
  "init_salt": "base64_encoded_dynamic_salt"
}
```

**Response:**
```json
{
  "token": "encrypted_token_string",
  "expires_in": 3600
}
```

#### `POST /auth/check`
Validate existing token.

**Request:**
```json
{
  "token": "encrypted_token_string",
  "temp_id": "guest_123abc",
  "device_id": "chrome_ext_xyz",
  "timestamp": 1234567890,
  "nonce": "random_nonce_123"
}
```

**Response:**
```json
{
  "valid": true,
  "uid": "guest_123abc",
  "expires_in": 3500
}
```

### BUSINESS Mode (Port 8080)

All business endpoints require:
- `X-Auth-Token` header
- `X-Temp-Id` header
- `X-Timestamp` header
- `X-Nonce` header
- `X-Sign` header (request signature)

#### `POST /api/login`
User login (upgrades guest to user token).

**Request:**
```json
{
  "username": "user@example.com",
  "password": "password123"
}
```

#### `POST /api/logout`
Logout current device.

#### `POST /api/logout-all`
Logout all devices.

#### `POST /api/translate`
Translation service example.

**Request:**
```json
{
  "text": "Hello",
  "target_lang": "es"
}
```

#### `GET /api/profile`
Get user profile example.

## Extension Integration

### Basic Usage

```typescript
import { httpClient, AuthConfig } from '@/src/modules/auth';

// Make authenticated API call
const response = await httpClient.post(
  `${AuthConfig.apiBaseUrl}/translate`,
  { text: 'Hello', target_lang: 'es' }
);

const data = await response.json();
```

### Token Management

The `AuthManager` automatically handles:
- ✅ Token refresh when approaching expiration (5 min threshold)
- ✅ Token validation on browser startup
- ✅ Token refresh after system idle/lock
- ✅ Concurrent request safety (promise locking)
- ✅ Periodic token health checks (every 30 min)

### Event Triggers

Token refresh happens automatically on:
1. **Browser Startup** - `chrome.runtime.onStartup`
2. **Extension Install/Update** - `chrome.runtime.onInstalled`
3. **Idle State Recovery** - `chrome.idle.onStateChanged` (user returns from lock/idle)
4. **Periodic Check** - `chrome.alarms` (every 30 minutes)
5. **Request Time** - Lazy check before API calls if threshold reached

## Security Features

### Request Signature

All business API requests include signature calculated as:

**GET requests:**
```
signature = HMAC-SHA256(sortedQueryParams|timestamp|tempId, token)
```

**POST/PUT/DELETE requests:**
```
signature = HMAC-SHA256(SHA256(body)|timestamp|tempId, token)
```

### Nonce Replay Prevention

- Each request must include unique nonce
- Redis stores used nonces with TTL (310 seconds)
- Duplicate nonce = request rejected

### Rate Limiting

- **Tier 1 (free/guest)**: default 10 requests per minute
- **Tier 2 (user)**: default 20 requests per minute
- **Tier 3 (pay)**: default 200 requests per minute (10x tier 2)
- Counters stored in Redis with 60-second TTL

### Token Encryption

- AES-256-GCM encryption
- Payload includes: uid, device_id, expiration
- AUTH_SECRET used as encryption key

## Testing

### 1. Test Token Issuance

```bash
curl -X POST http://localhost:8081/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "temp_id": "test_guest_123",
    "device_id": "test_device",
    "init_salt": "dGVzdF9zYWx0X2Jhc2U2NA=="
  }'
```

### 2. Test Token Validation

```bash
curl -X POST http://localhost:8081/auth/check \
  -H "Content-Type: application/json" \
  -d '{
    "token": "YOUR_TOKEN_HERE",
    "temp_id": "test_guest_123",
    "device_id": "test_device",
    "timestamp": 1234567890,
    "nonce": "test_nonce_abc123"
  }'
```

### 3. Test Business API (with extension)

1. Load extension in Chrome
2. Open browser console (F12)
3. Check background service worker logs:
   ```
   Token refreshed: guest_abc123
   Token expires in: 3600 seconds
   ```
4. Make API call from extension:
   ```javascript
   // In popup or content script
   const response = await httpClient.get('http://localhost:8080/api/profile');
   console.log(await response.json());
   ```

## Troubleshooting

### Extension: "Token refresh failed"

**Check:**
1. Is auth server running? `curl http://localhost:8081/auth/token`
2. Are secrets matching between server `.env` and extension `config.ts`?
3. Check browser console for detailed error messages
4. Verify Redis is running: `redis-cli ping` (should return "PONG")

### Server: "Redis connection failed"

**Fix:**
```bash
# Check Redis status
redis-cli ping

# Start Redis if not running
redis-server

# Test connection with custom config
redis-cli -h localhost -p 6379 -a yourpassword
```

### Extension: LSP shows import errors but build works

This is normal - TypeScript compilation succeeds even with LSP errors. The build uses `tsconfig.json` which extends `.wxt/tsconfig.json` with proper path mappings.

### Server: Go LSP shows import errors but build works

Dependencies are cached in `go.mod` and `go.sum`. Build works fine, LSP just needs restart:
```bash
# Reload Go language server
# In VS Code: Cmd+Shift+P → "Go: Restart Language Server"

# Or verify manually
go mod verify
go build
```

## File Structure

```
side-go-server/
├── main.go                  # Entry point, dual-mode routing
├── go.mod                   # Go module definition
├── .env.example             # Environment template
├── auth/
│   └── auth.go             # Token issuance/validation
├── middleware/
│   └── signature.go        # Request signature verification
├── config/
│   └── config.go           # Configuration management
├── internal/redis/
│   └── redis.go            # Redis client
├── api/
│   └── handlers.go         # Business API handlers
├── auth_sdk.py             # Python verification library
└── auth_sdk.ts             # TypeScript verification library

tranlation-overlay-extension/
└── src/modules/auth/
    ├── config.ts           # Auth constants
    ├── crypto.ts           # Cryptographic utilities
    ├── AuthManager.ts      # Token lifecycle manager
    ├── RequestInterceptor.ts # HTTP client wrapper
    ├── index.ts            # Module exports
    └── examples/
        └── usage.ts        # Usage examples
```

## Configuration Reference

### Server Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SERVICE_MODE` | Yes | - | `AUTH` or `BUSINESS` |
| `PORT` | Yes | - | Server port (8081 for AUTH, 8080 for BUSINESS) |
| `AUTH_SECRET` | Yes | - | 32-char secret for token encryption (MUST MATCH EXTENSION) |
| `INIT_SALT_SECRET` | Yes | - | Secret for init salt validation (MUST MATCH EXTENSION) |
| `REDIS_ADDR` | No | `localhost:6379` | Redis server address |
| `REDIS_PASSWORD` | No | - | Redis password (if any) |
| `REDIS_DB` | No | `0` | Redis database number |
| `ALLOWED_EXTENSION_IDS` | No | `*` | Comma-separated extension IDs (`*` = allow all) |

### Extension Configuration

Edit `src/modules/auth/config.ts`:

```typescript
export const AuthConfig = {
  authServerUrl: 'http://localhost:8081',  // AUTH mode endpoint
  apiBaseUrl: 'http://localhost:8080',      // BUSINESS mode endpoint
  authSecret: 'your-32-character-secret-key-here-change-this',
  initSaltSecret: 'your-32-character-init-salt-secret',
  tokenRefreshThreshold: 5 * 60 * 1000,     // 5 minutes
  maxRetries: 3,
  retryDelay: 1000,
  alarmInterval: 30,  // 30 minutes
};
```

## Production Deployment

### 1. Update Secrets

**Generate secure secrets:**
```bash
# Linux/Mac
openssl rand -base64 32

# Windows PowerShell
[Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))
```

### 2. Update Extension Config

Replace hardcoded secrets in `src/modules/auth/config.ts` with production values:
```typescript
export const AuthConfig = {
  authServerUrl: 'https://auth.yourdomain.com',
  apiBaseUrl: 'https://api.yourdomain.com',
  authSecret: process.env.VITE_AUTH_SECRET || 'production-secret',
  // ...
};
```

### 3. Build Production Extension

```bash
cd tranlation-overlay-extension
npm run build
npm run zip
```

Upload `.output/chrome-mv3-<version>.zip` to Chrome Web Store.

### 4. Deploy Server

```bash
cd side-go-server

# Build for Linux
GOOS=linux GOARCH=amd64 go build -o server

# Build for Windows
GOOS=windows GOARCH=amd64 go build -o server.exe

# Deploy with systemd (Linux)
sudo cp server /usr/local/bin/auth-server
sudo cp .env /etc/auth-server/.env
sudo systemctl start auth-server
```

### 5. Configure Reverse Proxy (Nginx)

```nginx
# AUTH server
upstream auth_backend {
    server localhost:8081;
}

# BUSINESS server
upstream api_backend {
    server localhost:8080;
}

server {
    listen 443 ssl;
    server_name auth.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://auth_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}

server {
    listen 443 ssl;
    server_name api.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://api_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Next Steps

1. ✅ **Complete**: Server implementation
2. ✅ **Complete**: Extension integration
3. ✅ **Complete**: Build verification
4. ⚠️ **TODO**: Manual testing
   - Start auth server
   - Load extension
   - Verify token refresh logs
   - Test API calls
5. ⚠️ **TODO**: Production deployment
   - Update secrets
   - Deploy servers
   - Configure HTTPS
   - Submit extension to store

## Support

For issues or questions:
1. Check server logs: `tail -f server.log`
2. Check browser console (F12 → Console)
3. Check background service worker (chrome://extensions → Service Worker)
4. Review design document: `chrome_extension_auth_design_v2.md`
