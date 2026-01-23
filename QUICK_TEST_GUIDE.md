# Quick Testing Guide

## Prerequisites

- ✅ Go installed (1.16+)
- ✅ Node.js installed (18+)
- ✅ Redis installed and running
- ✅ Chrome browser

## 5-Minute Quick Test

### Step 1: Start Redis (1 min)

```bash
# Check if Redis is running
redis-cli ping
# Expected: PONG

# If not running, start Redis
redis-server
```

### Step 2: Start Auth Server (1 min)

```bash
cd E:\git\goog_trans\side-go-server

# Server is already built, just run it
SERVICE_MODE=AUTH PORT=8081 ./server.exe
```

**Expected output:**
```
🚀 Server running in AUTH mode on :8081
```

Leave this terminal running.

### Step 3: Load Extension (1 min)

1. Open Chrome
2. Go to `chrome://extensions`
3. Enable "Developer mode" (top right)
4. Click "Load unpacked"
5. Select: `E:\git\goog_trans\tranlation-overlay-extension\.output\chrome-mv3`

**Expected:** Extension icon appears in toolbar

### Step 4: Verify Token Management (2 min)

1. Click extension icon (if popup exists) OR
2. Open any webpage
3. Press F12 (Developer Tools)
4. Go to "Console" tab
5. Filter by "background" or "service worker"

**Expected logs:**
```
✅ Token refreshed: guest_xxxxx
✅ Token expires in: 3600 seconds
```

### Step 5: Test API Call (Optional)

Open browser console and run:

```javascript
// Get current token
chrome.runtime.sendMessage({action: 'GET_TOKEN'}, response => {
  console.log('Current token:', response.token);
});

// Check auth state
chrome.runtime.sendMessage({action: 'GET_AUTH_STATE'}, response => {
  console.log('Auth state:', response);
});
```

**Expected response:**
```javascript
{
  isAuthenticated: true,
  tempId: "guest_xxxxx",
  deviceId: "chrome_ext_xxxxx",
  expiresAt: 1234567890
}
```

## Troubleshooting

### Problem: Server fails to start

**Error:** "Redis connection failed"
```bash
# Solution: Start Redis
redis-server
```

**Error:** "Port already in use"
```bash
# Solution: Use different port
PORT=8082 SERVICE_MODE=AUTH ./server.exe
# Then update extension config.ts with new port
```

### Problem: Extension not loading

**Error:** "Manifest file is missing or unreadable"
```bash
# Solution: Rebuild extension
cd E:\git\goog_trans\tranlation-overlay-extension
npm run build
```

**Error:** "Service worker registration failed"
- Check browser console for detailed errors
- Ensure `alarms` and `idle` permissions are in manifest
- Try reloading the extension

### Problem: No token refresh logs

1. **Check background service worker:**
   - Go to `chrome://extensions`
   - Find extension
   - Click "Service Worker" link
   - Check console logs

2. **Force token refresh:**
   - Open extension popup (if exists)
   - OR trigger browser restart
   - OR wait for alarm (30 min)

3. **Check auth server logs:**
   - Look for POST /auth/token requests
   - Check for any error messages

### Problem: LSP errors in VS Code

**Go files showing import errors:**
- ✅ **Ignore it** - Server builds successfully
- Dependencies are cached, LSP just needs restart
- Or run: `Ctrl+Shift+P` → "Go: Restart Language Server"

**TypeScript files showing path errors:**
- ✅ **Ignore it** - Extension builds successfully
- Paths are resolved via WXT framework
- Build process uses correct tsconfig

## Success Criteria

✅ **Minimum working setup:**
- [ ] Redis responds to `redis-cli ping`
- [ ] Server starts without errors
- [ ] Extension loads in Chrome
- [ ] Token refresh logs appear in background console

✅ **Full functionality:**
- [ ] Token auto-refreshes on browser startup
- [ ] Token refresh triggered by alarms (30 min)
- [ ] Token refresh triggered by idle state change
- [ ] API calls include authentication headers

## Next Steps After Testing

1. **Test business server:**
   ```bash
   # Start in another terminal
   SERVICE_MODE=BUSINESS PORT=8080 ./server.exe
   ```

2. **Test API endpoints:**
   - POST /api/login
   - GET /api/profile
   - POST /api/translate

3. **Test signature verification:**
   - Check X-Sign header in requests
   - Verify nonce uniqueness
   - Test rate limiting

4. **Test error handling:**
   - Stop Redis, check extension behavior
   - Stop auth server, check retry logic
   - Invalid token, check refresh mechanism

## Manual Test Scenarios

### Scenario 1: Browser Restart
1. Load extension
2. Check logs: Token refreshed
3. Close browser completely
4. Reopen browser
5. ✅ **Expected:** Token refresh triggered immediately

### Scenario 2: Idle Recovery
1. Load extension
2. Lock computer (Windows+L or Mac Ctrl+Cmd+Q)
3. Wait 1 minute
4. Unlock computer
5. ✅ **Expected:** Token refresh triggered within seconds

### Scenario 3: Token Expiration
1. Load extension
2. Wait for token to approach expiration (or manually set short expiry)
3. Make API call
4. ✅ **Expected:** Token auto-refreshes before call

### Scenario 4: Concurrent Requests
1. Load extension
2. Open console
3. Fire multiple API calls simultaneously:
   ```javascript
   Promise.all([
     httpClient.get('/api/profile'),
     httpClient.get('/api/profile'),
     httpClient.get('/api/profile'),
   ]).then(console.log);
   ```
4. ✅ **Expected:** Only one token refresh, all requests succeed

## Performance Benchmarks

**Token refresh time:** < 200ms  
**API call overhead:** < 50ms (signature calculation)  
**Memory usage:** < 5MB (auth module)  
**Background CPU:** < 0.1% (idle state)

## Common Questions

**Q: Do I need to manually refresh tokens?**  
A: No. AuthManager handles everything automatically.

**Q: What happens if auth server is down?**  
A: Requests retry up to 3 times with exponential backoff, then fail gracefully.

**Q: Can I use custom API endpoints?**  
A: Yes. Edit `src/modules/auth/config.ts` and rebuild.

**Q: How do I test in production mode?**  
A: Change server URLs in config.ts, rebuild extension, test with production servers.

**Q: Does it work in Firefox?**  
A: Build with `npm run build:firefox`, but storage requires proper addon ID configuration (see main README).
