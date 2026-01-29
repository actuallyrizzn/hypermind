# Hypermind Code Audit Findings

**Auditor**: Neckbeard Security Analysis  
**Date**: January 2026  
**Scope**: Code quality, security, stability, and correctness (excluding features/roadmap and CI/CD)

---

## BLUF (Bottom Line Up Front)

**Critical**: 3 | **High**: 8 | **Medium**: 14 | **Low**: 12 | **Informational**: 9

The codebase exhibits solid P2P fundamentals but has significant gaps in input validation, error handling, and resource management. The most pressing concerns are:

1. **Unbounded memory growth** in several data structures
2. **Missing input sanitization** on user-controlled data
3. **DoS vectors** via malformed messages and resource exhaustion
4. **Silent error swallowing** masking real issues
5. **Race conditions** in connection handling

Immediate attention required on items marked **[CRITICAL]** and **[HIGH]**.

---

## Table of Contents

1. [Critical Issues](#critical-issues)
2. [High Severity](#high-severity)
3. [Medium Severity](#medium-severity)
4. [Low Severity](#low-severity)
5. [Informational](#informational)

---

## Critical Issues

### [CRIT-001] Unbounded SSE Client Growth

**File**: `src/web/sse.js`  
**Lines**: 9-11

```javascript
addClient(res) {
    this.clients.add(res);
}
```

**Issue**: No limit on SSE clients. An attacker can open thousands of connections, exhausting server memory and file descriptors.

**Impact**: Denial of Service, server crash

**Recommendation**:
```javascript
constructor(maxClients = 1000) {
    this.clients = new Set();
    this.maxClients = maxClients;
}

addClient(res) {
    if (this.clients.size >= this.maxClients) {
        res.status(503).end();
        return false;
    }
    this.clients.add(res);
    return true;
}
```

---

### [CRIT-002] JSON Parsing Without Size Limit

**File**: `src/web/routes.js`  
**Line**: 23

```javascript
app.use(express.json());
```

**Issue**: No body size limit. Attackers can send multi-GB JSON payloads causing memory exhaustion.

**Impact**: Denial of Service, OOM kill

**Recommendation**:
```javascript
app.use(express.json({ limit: '10kb' }));
```

---

### [CRIT-003] Socket Buffer Unbounded Accumulation

**File**: `src/p2p/swarm.js`  
**Lines**: 69-85

```javascript
socket.buffer = "";

socket.on("data", (data) => {
    this.diagnostics.increment("bytesReceived", data.length);
    socket.buffer += data.toString();
    // ...
});
```

**Issue**: If a peer sends data without newlines, `socket.buffer` grows indefinitely until OOM.

**Impact**: Memory exhaustion, DoS

**Recommendation**:
```javascript
const MAX_BUFFER_SIZE = 65536; // 64KB

socket.on("data", (data) => {
    this.diagnostics.increment("bytesReceived", data.length);
    socket.buffer += data.toString();
    
    if (socket.buffer.length > MAX_BUFFER_SIZE) {
        socket.destroy();
        return;
    }
    // ...
});
```

---

## High Severity

### [HIGH-001] Rate Limit Bypass via Multiple Connections

**File**: `src/web/routes/chat.js`  
**Lines**: 7-22

```javascript
let chatHistory = [];  // Module-level, shared across all requests

router.post("/api/chat", (req, res) => {
    const now = Date.now();
    chatHistory = chatHistory.filter((time) => now - time < CHAT_RATE_LIMIT);
    if (chatHistory.length >= 5) {
        return res.status(429).json({...});
    }
    chatHistory.push(now);
```

**Issue**: Rate limit is per-server, not per-client. All users share the same 5 msg/5s limit. One user can consume the entire quota.

**Impact**: Legitimate users blocked, unfair rate limiting

**Recommendation**: Implement per-IP or per-session rate limiting:
```javascript
const rateLimits = new Map(); // IP -> { count, windowStart }
```

---

### [HIGH-002] Missing Content-Type Validation

**File**: `src/web/routes/chat.js`  
**Line**: 26

```javascript
const { content, scope = "GLOBAL", target } = req.body;
```

**Issue**: No validation that `req.body` is an object. If `Content-Type` header is missing or wrong, `req.body` could be undefined or a string.

**Impact**: Server crash, undefined behavior

**Recommendation**:
```javascript
if (!req.body || typeof req.body !== 'object') {
    return res.status(400).json({ error: "Invalid request body" });
}
```

---

### [HIGH-003] Prototype Pollution Risk in Message Validation

**File**: `src/p2p/messaging.js`  
**Lines**: 226-234

```javascript
if (msg.type === "HEARTBEAT") {
    const allowedFields = ["type", "id", "seq", "hops", "nonce", "sig"];
    const fields = Object.keys(msg);
    return (
        fields.every((f) => allowedFields.includes(f)) &&
        // ...
    );
}
```

**Issue**: `Object.keys()` doesn't include inherited properties, but `msg.hasOwnProperty` is not checked. Malicious `__proto__` or `constructor` fields could pass validation in some scenarios.

**Impact**: Prototype pollution, potential RCE

**Recommendation**:
```javascript
const fields = Object.keys(msg);
if (fields.includes('__proto__') || fields.includes('constructor') || fields.includes('prototype')) {
    return false;
}
```

---

### [HIGH-004] No Validation of Peer ID Format

**File**: `src/p2p/messaging.js`  
**Line**: 51

```javascript
const { id, seq, hops, nonce, sig } = msg;
```

**Issue**: `id` is used directly without validating it's a valid hex string of expected length. Malformed IDs could cause issues in `createPublicKey()` or when used as Map keys.

**Impact**: Crashes, unexpected behavior, potential injection

**Recommendation**:
```javascript
const isValidPeerId = (id) => {
    return typeof id === 'string' && 
           /^[a-f0-9]+$/i.test(id) && 
           id.length >= 64 && id.length <= 256;
};
```

---

### [HIGH-005] GitHub API Response Not Validated

**File**: `src/web/routes/github.js`  
**Lines**: 44-52

```javascript
try {
    const release = JSON.parse(data);
    res.json({
        tag_name: release.tag_name,
        html_url: release.html_url,
        // ...
    });
}
```

**Issue**: No validation that `release` has expected properties. Malformed GitHub response could leak undefined values or cause issues.

**Impact**: Information disclosure, client-side errors

**Recommendation**:
```javascript
const release = JSON.parse(data);
if (!release || typeof release !== 'object') {
    throw new Error('Invalid release data');
}
res.json({
    tag_name: release.tag_name || null,
    html_url: release.html_url || null,
    // ...
});
```

---

### [HIGH-006] LRU Cache Doesn't Prevent Memory Exhaustion

**File**: `src/state/lru.js`  
**Lines**: 20-28

```javascript
set(key, value) {
    this.cache.delete(key);
    this.cache.set(key, value);
    if (this.cache.size > this.capacity) {
        const oldestKey = this.cache.keys().next().value;
        this.cache.delete(oldestKey);
    }
}
```

**Issue**: While count is limited, value sizes are not. An attacker could store large values consuming excessive memory.

**Impact**: Memory exhaustion

**Recommendation**: Add value size limits or total memory budget tracking.

---

### [HIGH-007] Timestamp Validation Window Too Large

**File**: `src/p2p/messaging.js`  
**Lines**: 189-191

```javascript
if (Math.abs(now - msg.timestamp) > 60000) {
    return;
}
```

**Issue**: 60-second window allows replay attacks within that timeframe. Combined with bloom filter rotation every 30 seconds, there's a gap.

**Impact**: Message replay attacks

**Recommendation**: Reduce window to 30 seconds and ensure bloom filter covers the full window:
```javascript
if (Math.abs(now - msg.timestamp) > 30000) {
    return;
}
```

---

### [HIGH-008] No CORS Configuration

**File**: `src/web/routes.js`

**Issue**: No CORS headers configured. The API is open to any origin, enabling CSRF attacks against users with authenticated sessions (if added later).

**Impact**: CSRF vulnerability, unauthorized API access

**Recommendation**:
```javascript
const cors = require('cors');
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || false,
    credentials: true
}));
```

---

## Medium Severity

### [MED-001] Silent Error Swallowing in Message Parsing

**File**: `src/p2p/swarm.js`  
**Lines**: 79-84

```javascript
try {
    const msg = JSON.parse(msgStr);
    this.messageHandler.handleMessage(msg, socket);
} catch (e) {}
```

**Issue**: All parsing errors silently swallowed. Legitimate debugging info lost.

**Recommendation**:
```javascript
} catch (e) {
    this.diagnostics.increment('parseErrors');
}
```

---

### [MED-002] HyperLogLog Hash Function Weak

**File**: `src/state/hyperloglog.js`  
**Lines**: 18-24

```javascript
_hash(str) {
    let h = 0x811c9dc5;
    for (let i = 0; i < str.length; i++) {
        h ^= str.charCodeAt(i);
        h = (h * 0x01000193) >>> 0;
    }
    return h;
}
```

**Issue**: FNV-1a is fast but has known weaknesses for short strings. For peer IDs (which are hex), collision probability is higher than ideal.

**Impact**: Inaccurate unique peer counts

**Recommendation**: Use a stronger hash like MurmurHash3 or XXHash.

---

### [MED-003] Bloom Filter False Positive Rate Not Tuned

**File**: `src/state/bloom.js`  
**Lines**: 6-7

```javascript
constructor(size = 200000, hashCount = 3) {
```

**Issue**: With 200K bits and 3 hashes, false positive rate is ~1.2% at 10K items but degrades quickly. At 50K items (MAX_PEERS default), it's ~15%.

**Impact**: Legitimate messages may be incorrectly identified as duplicates

**Recommendation**: Increase size or hash count, or dynamically resize based on load.

---

### [MED-004] Integer Overflow in Sequence Numbers

**File**: `src/state/peers.js`  
**Line**: 79

```javascript
incrementSeq() {
    return ++this.mySeq;
}
```

**Issue**: JavaScript numbers lose precision above 2^53. In extreme long-running scenarios, sequence comparisons could fail.

**Impact**: Peer state corruption after very long uptime

**Recommendation**: Use BigInt or reset periodically:
```javascript
incrementSeq() {
    this.mySeq = (this.mySeq + 1) % Number.MAX_SAFE_INTEGER;
    return this.mySeq;
}
```

---

### [MED-005] Diagnostics Reset Loses Data

**File**: `src/state/diagnostics.js`  
**Lines**: 34-37

```javascript
startLogging(getPeerCount, getConnectionCount) {
    this.interval = setInterval(() => {
        this.reset();
    }, DIAGNOSTICS_INTERVAL);
}
```

**Issue**: Stats reset every 10 seconds, but the previous values are discarded without being logged or aggregated anywhere.

**Impact**: No historical data, debugging difficult

**Recommendation**: Log before reset, or maintain rolling totals.

---

### [MED-006] Connection Rotation Can Disconnect Critical Peers

**File**: `src/p2p/swarm.js`  
**Lines**: 127-150

```javascript
startRotation() {
    this.rotationInterval = setInterval(() => {
        // ... disconnect oldest connection
    }, CONNECTION_ROTATION_INTERVAL);
}
```

**Issue**: Oldest connection is disconnected regardless of its value. Could disconnect a well-connected peer providing valuable network access.

**Impact**: Network fragmentation, reduced connectivity

**Recommendation**: Consider peer value metrics before disconnecting.

---

### [MED-007] No Graceful Shutdown for HTTP Server

**File**: `src/web/server.js`  
**Lines**: 13-18

```javascript
const startServer = (app, identity) => {
    app.listen(PORT, () => {
        console.log(`Hypermind Node running on port ${PORT}`);
    });
}
```

**Issue**: HTTP server handle not stored, no graceful shutdown. SSE clients will be abruptly disconnected.

**Impact**: Poor user experience on restart, potential data loss

**Recommendation**:
```javascript
let server;
const startServer = (app, identity) => {
    server = app.listen(PORT, () => {...});
    return server;
};
const stopServer = () => server?.close();
```

---

### [MED-008] Chat Content Not Sanitized for Storage

**File**: `src/p2p/messaging.js`  
**Lines**: 249-269

```javascript
if (msg.type === "CHAT") {
    // ...
    msg.content &&
    typeof msg.content === "string" &&
    msg.content.length <= 140
```

**Issue**: Only length is validated. Content could contain control characters, null bytes, or other problematic data.

**Impact**: Log injection, display issues, potential XSS if content escaping fails

**Recommendation**:
```javascript
const sanitizeContent = (content) => {
    return content.replace(/[\x00-\x1F\x7F]/g, ''); // Remove control chars
};
```

---

### [MED-009] Hardcoded PoW Difficulty

**File**: `src/config/constants.js`  
**Lines**: 6-7

```javascript
const MY_POW_PREFIX = "00000";
const VERIFICATION_POW_PREFIX = "0000";
```

**Issue**: Different PoW requirements for self vs verification. Self requires 5 zeros (~1M iterations avg), verification only 4 (~65K). This asymmetry is unexplained.

**Impact**: Easier for attackers to verify than to generate legitimately

**Recommendation**: Document reasoning or unify the values.

---

### [MED-010] Leaflet CDN Dependency

**File**: `public/index.html`  
**Lines**: 30-33

```html
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
```

**Issue**: External CDN dependency. If unpkg is down or compromised, map functionality fails or becomes a vector.

**Impact**: Availability, supply chain risk

**Recommendation**: Bundle locally or use SRI hashes:
```html
<script src="..." integrity="sha384-..." crossorigin="anonymous"></script>
```

---

### [MED-011] localStorage Used Without Error Handling

**File**: `public/app.js`  
**Multiple locations**

```javascript
localStorage.setItem("chatCollapsed", isCollapsed);
```

**Issue**: localStorage can throw in private browsing mode or when quota exceeded.

**Impact**: JavaScript errors, broken functionality

**Recommendation**:
```javascript
const safeSetItem = (key, value) => {
    try { localStorage.setItem(key, value); } catch (e) {}
};
```

---

### [MED-012] No Request Timeout on GitHub API

**File**: `src/web/routes/github.js`  
**Lines**: 17-64

```javascript
const request = https.request(options, (response) => {
```

**Issue**: No timeout set. If GitHub is slow/unresponsive, the request hangs indefinitely.

**Impact**: Resource leak, hanging requests

**Recommendation**:
```javascript
request.setTimeout(5000, () => {
    request.destroy();
    res.status(504).json({ error: "GitHub API timeout" });
});
```

---

### [MED-013] Event Listener Memory Leak on Close

**File**: `src/web/routes/sse.js`  
**Lines**: 27-29

```javascript
req.on("close", () => {
    sseManager.removeClient(res);
});
```

**Issue**: If `res` is already removed or invalid, no error handling. Additionally, no cleanup of the event listener itself.

**Impact**: Potential memory leak

**Recommendation**: Add error handling and ensure cleanup.

---

### [MED-014] Theme Frenzy Can Cause Performance Issues

**File**: `public/js/chat-commands/frenzy.js`  
**Lines**: 27-41

```javascript
const frenzyInterval = setInterval(() => {
    window.cycleTheme();
    count++;
}, 100);
```

**Issue**: 100 theme changes in 10 seconds causes excessive DOM manipulation and stylesheet loading.

**Impact**: Browser freeze, poor UX

**Recommendation**: Reduce iterations or add debouncing.

---

## Low Severity

### [LOW-001] Console Logging in Production

**Files**: Multiple (`server.js`, `github.js`, etc.)

```javascript
console.log(`Hypermind Node running on port ${PORT}`);
console.error("Failed to fetch latest GitHub release:", ...);
```

**Issue**: Console logs in production code without structured logging.

**Recommendation**: Use proper logging library (winston, pino) with configurable levels.

---

### [LOW-002] Magic Numbers Throughout Codebase

**File**: `src/p2p/relay.js`  
**Lines**: 11-12

```javascript
const MIN_GOSSIP_COUNT = 6;
const GOSSIP_FACTOR = 0.25;
```

**Issue**: Magic numbers defined locally instead of in constants.

**Recommendation**: Move to `constants.js` with documentation.

---

### [LOW-003] Inconsistent Error Response Format

**Files**: Various route files

```javascript
res.status(400).json({ error: "Invalid content" });
res.status(500).json({ error: "Failed to fetch latest release" });
```

**Issue**: Error format varies (sometimes `error`, sometimes with additional fields).

**Recommendation**: Standardize error response format:
```javascript
{ error: { code: "INVALID_CONTENT", message: "..." } }
```

---

### [LOW-004] Missing `rel="noopener"` on External Links

**File**: `public/index.html`  
**Line**: 59

```html
<a href="https://github.com/lklynet/hypermind" target="_blank" class="footer-link">
```

**Issue**: Missing `rel="noopener noreferrer"` on `target="_blank"` links.

**Impact**: Potential tabnabbing attack

**Recommendation**:
```html
<a href="..." target="_blank" rel="noopener noreferrer">
```

---

### [LOW-005] No Input Sanitization in HTML Template

**File**: `src/web/routes/page.js`  
**Lines**: 11-20

```javascript
const html = htmlTemplate
    .replace(/\{\{COUNT\}\}/g, count)
    .replace(/\{\{ID\}\}/g, identity.screenname || "Unknown")
```

**Issue**: While current values are safe, if `screenname` contained HTML, it would be injected.

**Recommendation**: HTML-escape all template values.

---

### [LOW-006] SeededRandom Using Math.sin is Predictable

**File**: `src/utils/name-generator.js`  
**Lines**: 17-20

```javascript
next() {
    const x = Math.sin(this.seed++) * 10000;
    return x - Math.floor(x);
}
```

**Issue**: `Math.sin` based PRNG is predictable and has poor distribution properties.

**Impact**: Screennames are deterministic (intended) but could be predicted

**Recommendation**: Not critical for screennames, but document this is intentionally deterministic.

---

### [LOW-007] Missing Helmet Security Headers

**File**: `src/web/server.js`

**Issue**: No security headers set (CSP, X-Frame-Options, X-Content-Type-Options, etc.)

**Recommendation**:
```javascript
const helmet = require('helmet');
app.use(helmet());
```

---

### [LOW-008] Version Exposed in Multiple Places

**File**: `public/index.html`  
**Lines**: 41, 109

```html
<body data-version="{{VERSION}}">
<span class="stat-value" id="diag-version">{{VERSION}}</span>
```

**Issue**: Version information readily exposed to potential attackers.

**Impact**: Version fingerprinting for targeted attacks

**Recommendation**: Consider making version display optional via environment variable.

---

### [LOW-009] No Rate Limit on Static Files

**File**: `src/web/routes.js`  
**Line**: 70

```javascript
app.use(express.static(path.join(__dirname, "../../public")));
```

**Issue**: Static files served without rate limiting.

**Impact**: Bandwidth exhaustion via repeated requests

**Recommendation**: Add rate limiting middleware for static routes.

---

### [LOW-010] Deprecated Express 4 vs 5 Patterns

**File**: `package.json`

```json
"express": "^5.2.1"
```

**Issue**: Using Express 5 but some patterns (like error handling) may follow Express 4 conventions.

**Recommendation**: Review Express 5 migration guide for breaking changes.

---

### [LOW-011] No Health Check Endpoint

**File**: `src/web/routes.js`

**Issue**: No `/health` or `/ready` endpoint for container orchestration.

**Recommendation**:
```javascript
app.get('/health', (req, res) => res.json({ status: 'ok' }));
```

---

### [LOW-012] Test File Ships with Production

**File**: `test-api.js`

**Issue**: Test file is at project root and would be included in non-Docker deployments.

**Recommendation**: Move to `tests/` directory and add to `.dockerignore` (already excluded via selective COPY).

---

## Informational

### [INFO-001] No TypeScript

**Issue**: Project uses plain JavaScript without type checking.

**Note**: TypeScript would catch many potential issues at compile time.

---

### [INFO-002] No JSDoc Comments

**Issue**: Functions lack JSDoc documentation.

**Note**: Would improve maintainability and IDE support.

---

### [INFO-003] Inconsistent Async Patterns

**Files**: Various

**Note**: Mix of callbacks, Promises, and async/await. Consider standardizing on async/await.

---

### [INFO-004] No Input Schema Validation Library

**Issue**: Manual validation throughout. Consider using Joi, Zod, or express-validator.

---

### [INFO-005] No Database/Persistence

**Note**: All state is in-memory. This is intentional per design but worth documenting for operators.

---

### [INFO-006] Single-Threaded Node.js

**Note**: CPU-intensive PoW verification runs on main thread. Consider worker threads for heavy loads.

---

### [INFO-007] No Metrics/Observability

**Issue**: No Prometheus metrics, OpenTelemetry, or similar.

**Note**: Would help with production monitoring.

---

### [INFO-008] Package-lock.json Should Be Audited

**File**: `package-lock.json`

**Note**: Run `npm audit` regularly for dependency vulnerabilities.

---

### [INFO-009] No API Versioning

**Issue**: API routes are unversioned (`/api/chat` vs `/api/v1/chat`).

**Note**: Consider versioning for future compatibility.

---

## Summary by Category

| Category | Critical | High | Medium | Low | Info |
|----------|----------|------|--------|-----|------|
| Memory/Resources | 2 | 1 | 2 | 0 | 0 |
| Input Validation | 1 | 4 | 2 | 2 | 1 |
| Error Handling | 0 | 0 | 2 | 2 | 1 |
| Security | 0 | 2 | 1 | 3 | 0 |
| DoS/Rate Limiting | 0 | 1 | 1 | 1 | 0 |
| Network/Protocol | 0 | 0 | 3 | 0 | 0 |
| Code Quality | 0 | 0 | 2 | 3 | 5 |
| Frontend | 0 | 0 | 1 | 1 | 0 |
| Dependencies | 0 | 0 | 1 | 1 | 2 |

---

## Recommended Priority Order

### Immediate (This Week)
1. [CRIT-001] SSE client limit
2. [CRIT-002] JSON body size limit
3. [CRIT-003] Socket buffer limit
4. [HIGH-001] Per-client rate limiting
5. [HIGH-002] Request body validation

### Short Term (This Month)
6. [HIGH-003] Prototype pollution protection
7. [HIGH-004] Peer ID validation
8. [HIGH-008] CORS configuration
9. [MED-001] Error logging
10. [MED-007] Graceful shutdown

### Medium Term (This Quarter)
11. Remaining HIGH items
12. All MED items affecting stability
13. Security headers (LOW-007)
14. Health check endpoint (LOW-011)

---

## Appendix: Test Commands

```bash
# Test SSE connection limit
for i in {1..1000}; do curl -N localhost:3000/events & done

# Test JSON body limit
curl -X POST localhost:3000/api/chat \
  -H "Content-Type: application/json" \
  -d '{"content":"'$(python3 -c "print('A'*1000000)")'"}'

# Test socket buffer
nc localhost $P2P_PORT <<< "$(python3 -c "print('A'*10000000)")"
```
