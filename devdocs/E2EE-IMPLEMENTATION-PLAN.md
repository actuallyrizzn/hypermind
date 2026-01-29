# Hypermind E2EE Security Implementation Plan

## Executive Summary

This document outlines a phased approach to implement End-to-End Encryption (E2EE) and address the security concerns raised in the security audit. The implementation is designed to be incremental, allowing each phase to be tested and deployed independently.

### Current Security Model (As-Is)

| Feature | Status | Notes |
|---------|--------|-------|
| Message Signing | ✅ Implemented | Ed25519 signatures for authenticity/integrity |
| Message Encryption | ❌ Missing | Messages are plaintext |
| Forward Secrecy | ❌ Missing | Compromised keys expose all history |
| Metadata Protection | ❌ Missing | IPs exposed to all clients |
| TLS | ⚠️ Optional | HTTP by default |
| Key Verification | ❌ Missing | No trust model |

### Target Security Model (To-Be)

| Feature | Status | Notes |
|---------|--------|-------|
| Message Signing | ✅ Keep | Ed25519 signatures |
| Message Encryption | ✅ Add | X25519 ECDH + ChaCha20-Poly1305 |
| Forward Secrecy | ✅ Add | Double Ratchet for 1:1, Session keys for groups |
| Metadata Protection | ✅ Add | IP stripping, optional onion routing |
| TLS | ✅ Enforce | HTTPS by default |
| Key Verification | ✅ Add | TOFU + Fingerprint verification |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         HYPERMIND NODE                               │
├─────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────────┐ │
│  │   Identity      │  │   Key Store     │  │   Session Manager   │ │
│  │  (Ed25519)      │  │  (X25519 keys)  │  │  (Ratchet State)    │ │
│  │  - Sign         │  │  - Identity Key │  │  - Per-peer sessions│ │
│  │  - Verify       │  │  - Ephemeral    │  │  - Group sessions   │ │
│  └────────┬────────┘  └────────┬────────┘  └──────────┬──────────┘ │
│           │                    │                       │            │
│           └────────────────────┼───────────────────────┘            │
│                                │                                     │
│  ┌─────────────────────────────▼───────────────────────────────────┐│
│  │                      Crypto Layer                                ││
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌───────────┐  ││
│  │  │   X25519   │  │   HKDF     │  │  ChaCha20  │  │  HMAC     │  ││
│  │  │   ECDH     │  │   KDF      │  │  Poly1305  │  │  SHA256   │  ││
│  │  └────────────┘  └────────────┘  └────────────┘  └───────────┘  ││
│  └─────────────────────────────────────────────────────────────────┘│
│                                │                                     │
│  ┌─────────────────────────────▼───────────────────────────────────┐│
│  │                      Message Layer                               ││
│  │  ┌────────────────┐  ┌────────────────┐  ┌───────────────────┐  ││
│  │  │ HEARTBEAT      │  │ CHAT           │  │ KEY_EXCHANGE      │  ││
│  │  │ (signed)       │  │ (encrypted)    │  │ (new message type)│  ││
│  │  └────────────────┘  └────────────────┘  └───────────────────┘  ││
│  └─────────────────────────────────────────────────────────────────┘│
│                                │                                     │
│  ┌─────────────────────────────▼───────────────────────────────────┐│
│  │                      Transport Layer                             ││
│  │           Hyperswarm (DHT + Hole Punching)                       ││
│  └─────────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
```

---

## Phase 1: Cryptographic Foundation

### 1.1 Add Required Dependencies

```bash
npm install tweetnacl tweetnacl-util
```

**Why TweetNaCl?**
- Pure JavaScript, no native bindings (works everywhere)
- Audited and widely used
- Provides X25519, ChaCha20-Poly1305, and compatible with Ed25519
- ~5KB gzipped

### 1.2 New Files to Create

#### `src/core/crypto.js` - Core Cryptographic Primitives

```javascript
/**
 * Core cryptographic primitives for E2EE
 * Uses TweetNaCl for X25519 key agreement and symmetric encryption
 */
const nacl = require('tweetnacl');
const crypto = require('crypto');

// Re-export nacl for convenience
module.exports.nacl = nacl;

/**
 * Generate an X25519 keypair for key agreement
 * Separate from Ed25519 signing keys for security isolation
 */
const generateX25519Keypair = () => {
    const keypair = nacl.box.keyPair();
    return {
        publicKey: Buffer.from(keypair.publicKey),
        secretKey: Buffer.from(keypair.secretKey)
    };
};

/**
 * Derive a shared secret using X25519 ECDH
 * @param {Buffer} ourSecretKey - Our X25519 private key
 * @param {Buffer} theirPublicKey - Their X25519 public key
 * @returns {Buffer} 32-byte shared secret
 */
const deriveSharedSecret = (ourSecretKey, theirPublicKey) => {
    const shared = nacl.box.before(
        new Uint8Array(theirPublicKey),
        new Uint8Array(ourSecretKey)
    );
    return Buffer.from(shared);
};

/**
 * HKDF key derivation (RFC 5869)
 * @param {Buffer} inputKeyMaterial - The shared secret
 * @param {string} info - Context string
 * @param {number} length - Output length in bytes
 * @returns {Buffer} Derived key
 */
const hkdf = (inputKeyMaterial, info, length = 32) => {
    // Extract
    const salt = Buffer.alloc(32, 0); // Zero salt (acceptable for our use case)
    const prk = crypto.createHmac('sha256', salt)
        .update(inputKeyMaterial)
        .digest();
    
    // Expand
    let output = Buffer.alloc(0);
    let previous = Buffer.alloc(0);
    let counter = 1;
    
    while (output.length < length) {
        const hmac = crypto.createHmac('sha256', prk);
        hmac.update(previous);
        hmac.update(info);
        hmac.update(Buffer.from([counter]));
        previous = hmac.digest();
        output = Buffer.concat([output, previous]);
        counter++;
    }
    
    return output.slice(0, length);
};

/**
 * Encrypt a message using NaCl secretbox (XSalsa20-Poly1305)
 * @param {string|Buffer} plaintext - The message to encrypt
 * @param {Buffer} key - 32-byte symmetric key
 * @returns {{nonce: string, ciphertext: string}} Encrypted data (hex encoded)
 */
const encrypt = (plaintext, key) => {
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const messageBytes = typeof plaintext === 'string' 
        ? Buffer.from(plaintext, 'utf8')
        : plaintext;
    
    const ciphertext = nacl.secretbox(
        new Uint8Array(messageBytes),
        nonce,
        new Uint8Array(key)
    );
    
    return {
        nonce: Buffer.from(nonce).toString('hex'),
        ciphertext: Buffer.from(ciphertext).toString('hex')
    };
};

/**
 * Decrypt a message using NaCl secretbox
 * @param {string} ciphertextHex - Encrypted data (hex)
 * @param {string} nonceHex - Nonce (hex)
 * @param {Buffer} key - 32-byte symmetric key
 * @returns {string|null} Decrypted plaintext or null if authentication fails
 */
const decrypt = (ciphertextHex, nonceHex, key) => {
    const ciphertext = Buffer.from(ciphertextHex, 'hex');
    const nonce = Buffer.from(nonceHex, 'hex');
    
    const plaintext = nacl.secretbox.open(
        new Uint8Array(ciphertext),
        new Uint8Array(nonce),
        new Uint8Array(key)
    );
    
    if (!plaintext) return null;
    return Buffer.from(plaintext).toString('utf8');
};

/**
 * Generate a key fingerprint for verification
 * @param {Buffer} publicKey - Public key to fingerprint
 * @returns {string} Human-readable fingerprint (e.g., "AB12 CD34 EF56 ...")
 */
const generateFingerprint = (publicKey) => {
    const hash = crypto.createHash('sha256').update(publicKey).digest('hex');
    // Format as groups of 4 for readability
    return hash.slice(0, 32).match(/.{1,4}/g).join(' ').toUpperCase();
};

module.exports = {
    generateX25519Keypair,
    deriveSharedSecret,
    hkdf,
    encrypt,
    decrypt,
    generateFingerprint,
    nacl
};
```

#### `src/core/key-store.js` - Secure Key Management

```javascript
/**
 * Key Store - Manages encryption keys for peers
 * Implements TOFU (Trust On First Use) by default
 */
const { generateX25519Keypair, generateFingerprint } = require('./crypto');
const { LRUCache } = require('../state/lru');

class KeyStore {
    constructor(maxPeers = 1000) {
        // Our identity key (long-term, regenerated on restart for now)
        this.identityKey = generateX25519Keypair();
        
        // Known peer keys (TOFU: first seen key is trusted)
        this.peerKeys = new LRUCache(maxPeers);
        
        // Verified peers (explicitly confirmed by user)
        this.verifiedPeers = new Set();
        
        // Session keys for active encrypted sessions
        this.sessionKeys = new Map();
    }

    /**
     * Get our public key for sharing
     */
    getPublicKey() {
        return this.identityKey.publicKey;
    }

    /**
     * Get our public key as hex string
     */
    getPublicKeyHex() {
        return this.identityKey.publicKey.toString('hex');
    }

    /**
     * Get our fingerprint for display
     */
    getFingerprint() {
        return generateFingerprint(this.identityKey.publicKey);
    }

    /**
     * Store a peer's public key (TOFU)
     * @param {string} peerId - The peer's Ed25519 identity
     * @param {string} encryptionKeyHex - Their X25519 public key (hex)
     * @returns {{isNew: boolean, keyChanged: boolean}}
     */
    storePeerKey(peerId, encryptionKeyHex) {
        const existingKey = this.peerKeys.get(peerId);
        
        if (!existingKey) {
            // First time seeing this peer - trust on first use
            this.peerKeys.set(peerId, {
                key: encryptionKeyHex,
                firstSeen: Date.now(),
                lastSeen: Date.now()
            });
            return { isNew: true, keyChanged: false };
        }
        
        const keyChanged = existingKey.key !== encryptionKeyHex;
        
        if (keyChanged) {
            // Key changed! This could be a MITM attack or legitimate key rotation
            // For now, we update but flag it
            this.peerKeys.set(peerId, {
                key: encryptionKeyHex,
                firstSeen: existingKey.firstSeen,
                lastSeen: Date.now(),
                previousKey: existingKey.key
            });
            
            // Remove from verified if key changed
            this.verifiedPeers.delete(peerId);
        } else {
            // Same key, just update last seen
            existingKey.lastSeen = Date.now();
            this.peerKeys.set(peerId, existingKey);
        }
        
        return { isNew: false, keyChanged };
    }

    /**
     * Get a peer's encryption key
     * @param {string} peerId 
     * @returns {Buffer|null}
     */
    getPeerKey(peerId) {
        const data = this.peerKeys.get(peerId);
        if (!data) return null;
        return Buffer.from(data.key, 'hex');
    }

    /**
     * Check if we have a key for a peer
     */
    hasPeerKey(peerId) {
        return this.peerKeys.has(peerId);
    }

    /**
     * Mark a peer as verified (user confirmed fingerprint)
     */
    verifyPeer(peerId) {
        if (this.peerKeys.has(peerId)) {
            this.verifiedPeers.add(peerId);
            return true;
        }
        return false;
    }

    /**
     * Check if a peer is verified
     */
    isPeerVerified(peerId) {
        return this.verifiedPeers.has(peerId);
    }

    /**
     * Get a peer's fingerprint for verification
     */
    getPeerFingerprint(peerId) {
        const key = this.getPeerKey(peerId);
        if (!key) return null;
        return generateFingerprint(key);
    }

    /**
     * Store a session key for a peer (for forward secrecy)
     */
    storeSessionKey(peerId, sessionKey, epoch) {
        this.sessionKeys.set(peerId, {
            key: sessionKey,
            epoch,
            createdAt: Date.now()
        });
    }

    /**
     * Get session key for a peer
     */
    getSessionKey(peerId) {
        return this.sessionKeys.get(peerId);
    }

    /**
     * Clear session for a peer
     */
    clearSession(peerId) {
        this.sessionKeys.delete(peerId);
    }
}

module.exports = { KeyStore };
```

### 1.3 Modify Identity Generation

Update `src/core/identity.js` to include encryption keys:

```javascript
// Add to existing identity generation
const { generateX25519Keypair } = require('./crypto');

const generateIdentity = () => {
    // Existing Ed25519 for signing
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
    const id = publicKey.export({ type: "spki", format: "der" }).toString("hex");
    const screenname = generateScreenname(id);

    // PoW for spam prevention
    let nonce = 0;
    while (true) {
        const hash = crypto.createHash("sha256")
            .update(id + nonce)
            .digest("hex");
        if (hash.startsWith(MY_POW_PREFIX)) break;
        nonce++;
    }

    // NEW: X25519 for encryption
    const encryptionKey = generateX25519Keypair();

    return { 
        publicKey, 
        privateKey, 
        id, 
        nonce, 
        screenname,
        // New encryption-related fields
        encryptionPublicKey: encryptionKey.publicKey,
        encryptionSecretKey: encryptionKey.secretKey
    };
};
```

---

## Phase 2: 1:1 Encrypted Messages (Whisper Mode)

### 2.1 New Message Type: KEY_ANNOUNCE

Peers announce their encryption public key when connecting:

```javascript
// New message type for key exchange
{
    type: "KEY_ANNOUNCE",
    sender: "<ed25519-identity-hex>",
    encryptionKey: "<x25519-public-key-hex>",
    timestamp: Date.now(),
    sig: "<signature-of-encryptionKey+timestamp>"
}
```

### 2.2 Encrypted Chat Message Format

```javascript
// Encrypted whisper message
{
    type: "CHAT",
    scope: "WHISPER_E2EE",
    sender: "<ed25519-identity-hex>",
    target: "<recipient-ed25519-identity-hex>",
    id: "<message-id>",
    timestamp: Date.now(),
    sig: "<signature>",
    
    // NEW encrypted payload
    encrypted: {
        nonce: "<24-byte-nonce-hex>",
        ciphertext: "<encrypted-content-hex>",
        ephemeralKey: "<optional-ephemeral-x25519-for-forward-secrecy>"
    }
}
```

### 2.3 Create Session Manager

#### `src/core/session-manager.js`

```javascript
/**
 * Session Manager - Handles encrypted sessions between peers
 * Implements optional forward secrecy via ephemeral keys
 */
const { deriveSharedSecret, hkdf, encrypt, decrypt, generateX25519Keypair } = require('./crypto');
const nacl = require('tweetnacl');

class SessionManager {
    constructor(keyStore) {
        this.keyStore = keyStore;
    }

    /**
     * Create an encrypted message for a specific recipient
     * @param {string} recipientId - Recipient's Ed25519 identity
     * @param {string} content - Plaintext message
     * @param {boolean} forwardSecrecy - Use ephemeral key for PFS
     * @returns {object|null} Encrypted payload or null if no key for recipient
     */
    encryptForPeer(recipientId, content, forwardSecrecy = true) {
        const recipientKey = this.keyStore.getPeerKey(recipientId);
        if (!recipientKey) return null;

        let sharedSecret;
        let ephemeralPublicKey = null;

        if (forwardSecrecy) {
            // Generate ephemeral keypair for this message
            const ephemeral = generateX25519Keypair();
            ephemeralPublicKey = ephemeral.publicKey.toString('hex');
            
            // Derive shared secret from ephemeral + recipient's static key
            sharedSecret = deriveSharedSecret(ephemeral.secretKey, recipientKey);
        } else {
            // Use static-static ECDH (no forward secrecy)
            sharedSecret = deriveSharedSecret(
                this.keyStore.identityKey.secretKey,
                recipientKey
            );
        }

        // Derive encryption key
        const encryptionKey = hkdf(sharedSecret, 'hypermind-e2ee-v1');

        // Encrypt
        const { nonce, ciphertext } = encrypt(content, encryptionKey);

        return {
            nonce,
            ciphertext,
            ephemeralKey: ephemeralPublicKey
        };
    }

    /**
     * Decrypt a message from a peer
     * @param {string} senderId - Sender's Ed25519 identity
     * @param {object} encrypted - The encrypted payload
     * @returns {string|null} Decrypted content or null
     */
    decryptFromPeer(senderId, encrypted) {
        const { nonce, ciphertext, ephemeralKey } = encrypted;

        let sharedSecret;

        if (ephemeralKey) {
            // Forward secrecy: derive from ephemeral + our static key
            const ephemeralPubKey = Buffer.from(ephemeralKey, 'hex');
            sharedSecret = deriveSharedSecret(
                this.keyStore.identityKey.secretKey,
                ephemeralPubKey
            );
        } else {
            // Static-static: need sender's key
            const senderKey = this.keyStore.getPeerKey(senderId);
            if (!senderKey) return null;
            
            sharedSecret = deriveSharedSecret(
                this.keyStore.identityKey.secretKey,
                senderKey
            );
        }

        // Derive decryption key
        const decryptionKey = hkdf(sharedSecret, 'hypermind-e2ee-v1');

        // Decrypt
        return decrypt(ciphertext, nonce, decryptionKey);
    }

    /**
     * Check if we can encrypt for a peer
     */
    canEncryptFor(peerId) {
        return this.keyStore.hasPeerKey(peerId);
    }
}

module.exports = { SessionManager };
```

### 2.4 Update Message Handler

Add handling for KEY_ANNOUNCE and encrypted messages in `src/p2p/messaging.js`:

```javascript
// Add to handleMessage()
if (msg.type === "KEY_ANNOUNCE") {
    this.handleKeyAnnounce(msg, sourceSocket);
} else if (msg.type === "CHAT" && msg.scope === "WHISPER_E2EE") {
    this.handleEncryptedChat(msg, sourceSocket);
}

// New handler
handleKeyAnnounce(msg, sourceSocket) {
    const { sender, encryptionKey, timestamp, sig } = msg;
    
    // Verify signature
    const key = createPublicKey(sender);
    if (!verifySignature(`key:${encryptionKey}:${timestamp}`, sig, key)) {
        this.diagnostics.increment("invalidSig");
        return;
    }
    
    // Check timestamp freshness (prevent replay)
    if (Math.abs(Date.now() - timestamp) > 60000) {
        return;
    }
    
    // Store the key (TOFU)
    const result = this.keyStore.storePeerKey(sender, encryptionKey);
    
    if (result.keyChanged) {
        // Emit warning about key change
        if (this.chatSystemFn) {
            this.chatSystemFn({
                type: "SECURITY_WARNING",
                content: `⚠️ Encryption key changed for peer ${generateScreenname(sender)}`,
                timestamp: Date.now()
            });
        }
    }
    
    // Relay to other peers
    if (msg.hops < MAX_RELAY_HOPS && !this.bloomFilter.hasRelayed(sender, "key")) {
        this.bloomFilter.markRelayed(sender, "key");
        this.relayCallback({ ...msg, hops: msg.hops + 1 }, sourceSocket);
    }
}

handleEncryptedChat(msg, sourceSocket) {
    const { sender, target, encrypted, sig, id } = msg;
    
    // Only process if we're the target
    if (target !== this.identity.id) {
        // Relay to target if possible
        if (msg.hops < MAX_RELAY_HOPS) {
            this.relayCallback({ ...msg, hops: msg.hops + 1 }, sourceSocket);
        }
        return;
    }
    
    // Verify signature
    const key = createPublicKey(sender);
    if (!verifySignature(`chat:${id}`, sig, key)) {
        this.diagnostics.increment("invalidSig");
        return;
    }
    
    // Decrypt
    const content = this.sessionManager.decryptFromPeer(sender, encrypted);
    if (!content) {
        this.diagnostics.increment("decryptionFailed");
        return;
    }
    
    // Deliver decrypted message
    if (this.chatCallback) {
        this.chatCallback({
            type: "CHAT",
            scope: "WHISPER_E2EE",
            sender,
            content,
            timestamp: msg.timestamp,
            id,
            encrypted: true // Flag to show lock icon in UI
        });
    }
}
```

---

## Phase 3: Forward Secrecy (Double Ratchet - Optional)

For maximum security in long-lived 1:1 conversations, implement a simplified Double Ratchet:

### 3.1 Ratchet State

```javascript
/**
 * Simplified Double Ratchet for forward secrecy
 * Based on Signal protocol principles
 */
class RatchetSession {
    constructor(sharedSecret, isInitiator) {
        this.rootKey = sharedSecret;
        this.sendingChainKey = null;
        this.receivingChainKey = null;
        this.sendMessageNumber = 0;
        this.recvMessageNumber = 0;
        this.isInitiator = isInitiator;
        
        // Initialize chain keys
        this.deriveInitialChains();
    }

    deriveInitialChains() {
        const derived = hkdf(this.rootKey, 'hypermind-ratchet-init', 64);
        if (this.isInitiator) {
            this.sendingChainKey = derived.slice(0, 32);
            this.receivingChainKey = derived.slice(32, 64);
        } else {
            this.receivingChainKey = derived.slice(0, 32);
            this.sendingChainKey = derived.slice(32, 64);
        }
    }

    /**
     * Get next message key for sending
     */
    getNextSendKey() {
        const messageKey = hkdf(this.sendingChainKey, 'msg-key', 32);
        this.sendingChainKey = hkdf(this.sendingChainKey, 'chain-advance', 32);
        this.sendMessageNumber++;
        return messageKey;
    }

    /**
     * Get next message key for receiving
     */
    getNextRecvKey() {
        const messageKey = hkdf(this.receivingChainKey, 'msg-key', 32);
        this.receivingChainKey = hkdf(this.receivingChainKey, 'chain-advance', 32);
        this.recvMessageNumber++;
        return messageKey;
    }
}
```

### 3.2 When to Use Double Ratchet

- **Use for**: Extended 1:1 conversations where participants expect multiple message exchanges
- **Skip for**: One-off whispers (ephemeral key per message is sufficient)

---

## Phase 4: Metadata Protection

### 4.1 Remove IP Exposure

Current code exposes IPs via SSE:

```javascript
// In broadcastUpdate()
peers: peerManager.getPeersWithIps()  // ❌ Exposes IPs to all clients
```

**Fix**: Create a new method that strips IPs for broadcast:

```javascript
// In PeerManager
getPeersForBroadcast(stripIps = true) {
    const peers = [];
    for (const [id, data] of this.seenPeers.entries()) {
        peers.push({ 
            id,
            // Only include IP in admin/local views, not broadcast
            ...(stripIps ? {} : { ip: data.ip })
        });
    }
    return peers;
}
```

### 4.2 Add Environment Variable for IP Exposure

```javascript
// In constants.js
const EXPOSE_PEER_IPS = process.env.EXPOSE_PEER_IPS === "true"; // default false
```

### 4.3 Optional: Onion-style Routing

For true metadata protection, implement layered routing:

```javascript
// Onion message format
{
    type: "ONION",
    layers: [
        // Each layer encrypted for next hop
        { 
            nextHop: "<peer-id>", 
            encryptedPayload: "..." 
        }
    ]
}
```

This is a significant undertaking and should be Phase 5+.

---

## Phase 5: Group E2EE (Future)

### Options

1. **Per-recipient encryption**: Encrypt message once for each group member
   - Simple but O(n) overhead per message
   - Works for small groups (< 20 members)

2. **Shared group key**: All members share a symmetric key
   - Efficient O(1) overhead
   - Requires key rotation on membership changes
   - Potential for compromise if any member is malicious

3. **MLS (Messaging Layer Security)**: Modern group encryption protocol
   - Scalable, efficient
   - Complex to implement correctly
   - Consider using existing library (e.g., `openmls`)

### Recommendation for Hypermind

Given the ephemeral, ad-hoc nature of Hypermind groups:

1. **Start with per-recipient encryption** for groups < 10
2. **Add shared group key** option for larger groups
3. **Defer MLS** unless group E2EE becomes a primary use case

---

## Implementation Order

### MVP (Minimum Viable Privacy)

1. ✅ Add X25519 key generation (`src/core/crypto.js`)
2. ✅ Create KeyStore for TOFU key management
3. ✅ Add KEY_ANNOUNCE message type
4. ✅ Implement encrypted 1:1 whispers
5. ✅ Remove IP exposure from broadcasts

### Phase 2 Enhancements

6. ⬜ Add fingerprint verification UI
7. ⬜ Implement session ratcheting for extended conversations
8. ⬜ Add key rotation mechanism

### Phase 3 Hardening

9. ⬜ Add HTTPS enforcement
10. ⬜ Implement message padding (hide length metadata)
11. ⬜ Add timing attack mitigations

### Phase 4 Advanced

12. ⬜ Group E2EE (per-recipient or shared key)
13. ⬜ Optional onion routing
14. ⬜ Consider Tor/I2P integration

---

## Security Considerations

### What This Protects Against

| Threat | Protected? | Notes |
|--------|------------|-------|
| Eavesdropping on messages | ✅ Yes | E2EE prevents content reading |
| Message tampering | ✅ Yes | Signatures + authenticated encryption |
| Replay attacks | ✅ Yes | Timestamps + bloom filter |
| Key impersonation | ⚠️ Partial | TOFU provides initial trust, fingerprints allow verification |
| Traffic analysis | ⚠️ Partial | Message timing/volume still visible |
| IP exposure | ⚠️ Configurable | Can be disabled, but DHT still reveals IPs to some nodes |

### What This Does NOT Protect Against

| Threat | Protection | Mitigation |
|--------|------------|------------|
| Compromised endpoint | ❌ None | Security is only as good as the device |
| Global passive adversary | ❌ Limited | Tor/I2P integration needed |
| Metadata (who talks to whom) | ❌ Limited | Onion routing needed |
| Key compromise before ratchet | ❌ Limited | Ephemeral keys help but don't eliminate |

### Cryptographic Choices Rationale

| Choice | Rationale |
|--------|-----------|
| X25519 | Modern, fast, 128-bit security, widely audited |
| XSalsa20-Poly1305 | AEAD, no padding oracle attacks, fast in JS |
| HKDF | Standard key derivation, composable |
| Ed25519 signatures | Already in use, compatible with X25519 |

---

## Testing Plan

### Unit Tests

```javascript
// test/crypto.test.js
const { generateX25519Keypair, deriveSharedSecret, encrypt, decrypt, hkdf } = require('../src/core/crypto');

describe('Crypto Primitives', () => {
    it('should generate valid X25519 keypairs', () => {
        const kp = generateX25519Keypair();
        expect(kp.publicKey).toHaveLength(32);
        expect(kp.secretKey).toHaveLength(32);
    });

    it('should derive same shared secret from both sides', () => {
        const alice = generateX25519Keypair();
        const bob = generateX25519Keypair();
        
        const aliceShared = deriveSharedSecret(alice.secretKey, bob.publicKey);
        const bobShared = deriveSharedSecret(bob.secretKey, alice.publicKey);
        
        expect(aliceShared.equals(bobShared)).toBe(true);
    });

    it('should encrypt and decrypt correctly', () => {
        const key = hkdf(Buffer.from('test-secret'), 'test-info');
        const plaintext = 'Hello, World!';
        
        const { nonce, ciphertext } = encrypt(plaintext, key);
        const decrypted = decrypt(ciphertext, nonce, key);
        
        expect(decrypted).toBe(plaintext);
    });

    it('should fail to decrypt with wrong key', () => {
        const key1 = hkdf(Buffer.from('test-secret-1'), 'test-info');
        const key2 = hkdf(Buffer.from('test-secret-2'), 'test-info');
        
        const { nonce, ciphertext } = encrypt('secret', key1);
        const decrypted = decrypt(ciphertext, nonce, key2);
        
        expect(decrypted).toBeNull();
    });
});
```

### Integration Tests

```javascript
// test/e2ee-integration.test.js
describe('E2EE Messaging', () => {
    it('should exchange keys on connection');
    it('should encrypt whisper messages');
    it('should decrypt received whispers');
    it('should warn on key change');
    it('should relay encrypted messages to non-recipients');
});
```

---

## Migration Path

### Backward Compatibility

The implementation maintains backward compatibility:

1. **Unencrypted messages still work**: `scope: "GLOBAL"` remains unencrypted
2. **Gradual adoption**: Encryption is opt-in per message
3. **Key exchange is additive**: Peers without encryption keys can still communicate in plaintext

### Feature Flag

```javascript
// constants.js
const ENABLE_E2EE = process.env.ENABLE_E2EE === "true";
const E2EE_WHISPER_ONLY = process.env.E2EE_WHISPER_ONLY !== "false"; // default: only encrypt whispers
```

---

## UI Considerations

### Visual Indicators

- 🔒 Lock icon for encrypted messages
- 🔓 Unlocked icon for unencrypted messages
- ⚠️ Warning icon for unverified peers
- ✅ Checkmark for verified peers

### Fingerprint Verification Flow

1. User clicks on peer name
2. Context menu shows "Verify Fingerprint"
3. Dialog shows:
   ```
   Your fingerprint:
   AB12 CD34 EF56 7890 ...
   
   [PeerName]'s fingerprint:
   12AB 34CD 56EF 9078 ...
   
   Compare these with your contact out-of-band.
   [ ] I have verified this fingerprint
   [Cancel] [Confirm]
   ```
4. Verified peers show ✅ badge

---

## Conclusion

This plan provides a realistic path to meaningful E2EE in Hypermind while acknowledging the inherent limitations of the P2P gossip architecture. The phased approach allows for incremental deployment and testing.

**Key takeaways:**
1. E2EE for 1:1 whispers is achievable with reasonable effort
2. Metadata protection is harder and requires architectural changes
3. Group E2EE is complex but feasible for small groups
4. Full Signal-level privacy would require fundamental redesign

The recommended starting point is Phase 1-2 (crypto foundation + 1:1 E2EE), which provides immediate privacy benefits for sensitive direct messages while maintaining compatibility with the existing system.
