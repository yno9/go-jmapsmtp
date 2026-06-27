# go-jmapsmtp Architecture

A small daemon that bridges SMTP (port 25) and JMAP (RFC 8621) bidirectionally. Acts as an MTA equivalent to Postfix, managing user mailboxes.

---

## Source Files

```
go-jmapsmtp/
├── main.go               # Entry point, config, JMAP handler, SMTP server, send logic
├── auth_env.go           # Auth endpoints and envelope I/O
├── autocrypt.go          # Autocrypt header injection/parsing, PGP helpers, pgpMIMEWrapInline
├── dkim.go               # DKIM key management and signing
├── wkd.go                # WKD and /pgp/* endpoints
├── cryptenv/
│   ├── envelope.go       # KEK envelope: NewEnvelope, Unseal, Rewrap, VerifyAuth
│   └── envelope_test.go  # Round-trip and VerifyAuth tests
├── config.example.json   # Config template
├── go.mod / go.sum
└── ARC.md
```

### File responsibilities

| File | Responsibility |
|---|---|
| `main.go` | Reads config; builds alias map and per-account Stores; wires `OnCreateEmail` and `OnSubmitEmail` hooks; starts SMTP server and JMAP HTTP server. Also contains: JMAP `handler`, incoming message buffer (`bufCh`/`drainBuffer`), `sendEmail` (SMTP delivery), `/setup` HTML endpoint, `cleanupOrphanedData`. |
| `auth_env.go` | `authenticate(r, dataDir)` shared auth helper; `GET /auth/envelope`, `PUT /auth/envelope`, `POST /auth/signup` endpoints; `readEnvelope`/`writeEnvelope` disk I/O. |
| `autocrypt.go` | Parse and inject `Autocrypt:` headers; store/load peer public keys (`peers/<addr>.pgp`); `pgpEncryptInline` (Layer 1 storage encryption); `pgpMIMEWrapInline` (wrap inline PGP as RFC 3156 multipart/encrypted for SMTP); load user pubkey/privkey entity. |
| `dkim.go` | Generate and persist RSA 2048 DKIM keys per domain; `signDKIMForDomain` signs outgoing raw messages; `loadOrGenerateDKIMKeys` called at startup. |
| `wkd.go` | `GET /.well-known/openpgpkey/…` (WKD key lookup); `PUT /pgp/pubkey`, `GET/PUT /pgp/privkey`, `GET/PUT /pgp/peerkey` (all require Basic Auth via `authenticate`). |
| `cryptenv/envelope.go` | Self-contained KEK envelope package. `NewEnvelope(pw)` generates master_secret and wraps it; `Unseal(pw)` derives authToken + KEK; `Rewrap(old, new)` rotates the password without changing master_secret; `VerifyAuth(tok)` does constant-time SHA-256 comparison. No dependencies outside the standard library and `golang.org/x/crypto`. |

---

## Roles

- **Receive**: Store incoming SMTP mail in the JMAP Store
- **Send**: Accept `EmailSubmission/set` from JMAP clients and deliver via SMTP
- **Serve**: Expose an RFC 8621-compliant JMAP HTTP endpoint to clients
- **Account management**: Password setup flow via one-time setup URL

---

## config.json

```json
{
  "listen_addr": "0.0.0.0:8767",
  "base_url": "https://mail.example.com",
  "relayname": "jmap-smtp",
  "hostname": "mail.example.com",
  "smtp_port": 25,
  "relay_host": "",
  "domain": {
    "example.com": {
      "dkim_selector": "",
      "account": {
        "you@example.com": { "alias": ["alias@example.com"] },
        "friend@example.com": {}
      }
    }
  }
}
```

### Fields

| Field | Purpose |
|---|---|
| `listen_addr` | JMAP HTTP port |
| `base_url` | Used to generate setup URLs |
| `hostname` | SMTP EHLO and Message-Id domain for outgoing mail |
| `relay_host` | Empty = direct MX delivery; set = route through this host |
| `domain.<d>.dkim_selector` | Empty = falls back to `"default"` |
| `account.<addr>.alias` | Aliases delivered to this account |

The config contains no passwords. Authentication is handled by `data/<domain>/<localpart>/envelope.json` (cryptenv envelope). Accounts with no envelope log a setup URL on startup.

---

## Runtime Directory Layout

```
~/jmapsmtp/
├── jmapsmtp             # binary
├── config.json
├── jmapsmtp.log
└── data/
    └── example.com/
        ├── key.pem          # DKIM RSA private key (auto-generated on startup)
        ├── dkim-dns.txt     # DNS TXT record to publish (reference)
        ├── peers/           # Autocrypt peer public keys (prerequisite for encrypted sends)
        │   └── <peer-addr>.pgp
        └── you/             # Per-localpart JMAP Store
            ├── messages/<id>.json  # One file per message
            ├── mailboxes.json      # Mailbox list
            ├── identities.json     # Identity records
            ├── delta.json          # State counters + change log
            ├── envelope.json       # cryptenv envelope (auth + key wrap, see below)
            ├── pubkey.pgp          # User public key (served via WKD)
            ├── privkey.enc         # Private key encrypted with KEK (decrypted client-side)
            └── setup.token         # One-time setup token (only present before first login)
```

**Note**: Deleting everything (`rm -rf data/`) **also removes `peers/`**, resetting Autocrypt state with all known contacts. Avoid outside of testing.

---

## Components

### JMAP Server (`go-jmapserver`)

- `handler` implements the `jmapserver.Handler` interface
- Each account has its own independent `jmapserver.Store`
- `Handle(method, args)` inspects `accountId` and routes to the corresponding Store

Supported methods:

| Method | Implementation |
|---|---|
| `Email/query` | Drain buffer, then Store |
| `Email/get`, `Email/changes`, `Email/queryChanges` | Store |
| `Email/set` | Draft creation (PutPending) and keyword updates |
| `EmailSubmission/set` | SMTP delivery |
| `Thread/get`, `Thread/changes` | Store |
| `Mailbox/get`, `Mailbox/changes` | Store |
| `Identity/get`, `Identity/changes` | Store |

### SMTP Server (port 25)

- Uses `github.com/emersion/go-smtp`
- Resolves `RCPT TO` through the alias map to identify the primary account
- Incoming mail is queued in a channel buffer (256 messages)
- Buffer is drained into the Store when `Email/query` is called

### Authentication (`auth_env.go` + `cryptenv/`)

Zero-knowledge authentication via cryptenv envelope. The server never holds a password.

- JMAP HTTP and `/pgp/*` use Basic Auth: `username = email`, `password = base64(auth_token)` (32-byte random value, HKDF-derived from master_secret)
- Verification: read `data/<d>/<lp>/envelope.json`, call `Envelope.VerifyAuth(authToken)` with constant-time SHA-256 comparison
- `authenticate(r, dataDir) → (domain, localpart, ok)` is shared across all endpoints

Endpoints:

| Method / Path | Auth | Purpose |
|---|---|---|
| `GET /auth/envelope?email=...` | None | Return envelope JSON (opaque; useless to an attacker without the password) |
| `PUT /auth/envelope` | Basic | Replace envelope with a rewrapped one (password change) |
| `POST /auth/signup?token=...` | Setup token | Register envelope for the first time; delete token |
| `GET /setup?token=...` | Setup token | HTML page that builds the Argon2id envelope client-side and POSTs it to `/auth/signup` |

The setup page runs Argon2id via `hash-wasm` (esm.sh CDN). The server never receives the plaintext password.

### DKIM (`dkim.go`)

- Manages an RSA 2048 key per domain
- Keys are persisted to `data/<domain>/key.pem` and loaded on startup (generated if missing)
- On send, the key for the From address domain is selected and used to sign

### Autocrypt / PGP (`autocrypt.go`)

- Outgoing mail gets an `Autocrypt:` header and `Chat-Version: 1.0` (advertising the sender's `pubkey.pgp`)
- Incoming `Autocrypt:` headers are parsed and the peer public key is stored in `data/<domain>/peers/<addr>.pgp`
- When the client (biset-ui) submits an inline PGP message, `pgpMIMEWrapInline` wraps it as RFC 3156 `multipart/encrypted` for SMTP delivery (DeltaChat-compatible)
- The server performs **no Layer 2 encryption or signing** (it holds no private key)

### WKD (`wkd.go`)

- Serves user public keys at `/.well-known/openpgpkey/` (Web Key Directory)
- Per-user key: `data/<domain>/<localpart>/pubkey.pgp`
- `PUT /pgp/pubkey` — client uploads its own public key (Basic Auth)
- `GET/PUT /pgp/privkey` — server-side storage of KEK-encrypted private key (Basic Auth)
- `GET/PUT /pgp/peerkey?addr=<email>` — read/write Autocrypt peer public keys (Basic Auth)

All endpoints go through `authenticate()` which calls `Envelope.VerifyAuth(authToken)`.

### cryptenv (`cryptenv/`)

A self-contained package for password-derived key envelopes. Currently embedded in go-jmapsmtp; designed to be extracted as a standalone module if needed by other relays.

```go
type Envelope struct {
    Version       int       `json:"v"`
    Salt          []byte    `json:"salt"`            // base64
    KDF           KDFParams `json:"kdf"`             // Argon2id params
    WrappedSecret []byte    `json:"wrapped_secret"`  // nonce(12) || AES-GCM(master_secret)
    AuthTokenHash []byte    `json:"auth_token_hash"` // sha256(auth_token)
}

NewEnvelope(pw)               → *Envelope, authToken, kek
(env).Unseal(pw)              → authToken, kek
(env).Rewrap(oldPw, newPw)    → *Envelope  // master_secret unchanged
(env).VerifyAuth(authToken)   → bool       // zero-knowledge server-side verification
```

Default KDF parameters: Argon2id, t=3, m=64 MiB, p=4 (OWASP recommended).

---

## Encryption Architecture

Two clearly separated layers of responsibility.

| Layer | Responsibility | Owner |
|---|---|---|
| Layer 1 | Storage encryption (saved with recipient's own public key) | **jmapsmtp** |
| Layer 2 | E2E encryption + signing (encrypted for recipient, decrypted by recipient) | **biset-ui** |

### Layer 1: Storage Encryption (jmapsmtp)

To prevent plaintext from being stored on disk, all messages — received or sent — are encrypted with the user's own public key (`data/<domain>/<localpart>/pubkey.pgp`) before being written to the Store.

- **On receive**: plaintext SMTP mail is encrypted with the recipient's public key → `keywords: {$e2e: false}`
- **On receive (already ciphertext)**: stored as-is → `keywords: {$e2e: true}`
- **Sent copy**: if plaintext, encrypted with the sender's public key; if already E2E-encrypted, stored as-is

The server holds no private key — once stored, it cannot decrypt.

### Layer 2: E2E Encryption (biset-ui)

All cryptographic operations happen in the client browser via OpenPGP.js.

- **Key generation**: keypair generated in the browser on first login (curve25519Legacy)
- **On send**: fetch `peers/<toAddr>.pgp` from server → encrypt body with recipient + sender public keys → sign with sender private key → submit as inline PGP via JMAP
- **On receive**: decrypt in-browser with private key from IndexedDB → parse Protected Headers → display plaintext only
- **WKD prefetch**: when composing a new message, on recipient address blur, hit WKD to fetch the recipient's public key → store in server's `peers/` (avoids delay at send time)

jmapsmtp only wraps client-submitted inline PGP messages using `pgpMIMEWrapInline` into `multipart/encrypted`; it does not encrypt.

### Data Flow

```
[Receive: external MTA → user]
External MTA → SMTP:25 → session.Data()
  → ParseMIMEEmail (extract inner PGP block if multipart/encrypted)
  → Extract peer public key from Autocrypt header → save to peers/<addr>.pgp
  → Body is PGP block → store as-is ($e2e: true)
  → Body is plaintext → [Layer 1] encrypt with recipient pubkey.pgp → store
  → bufferEmail → [on Email/query] drainBuffer() → store.Put()

[Send: biset-ui → external]
biset-ui:
  fetchRecipientPublicKey(peers/<to>.pgp from server)
    → encryptText: OpenPGP encrypt(body, [recipient, sender]) + sign(senderPriv)
    → embed MIME wrapper (Content-Type, Chat-Version)
  → JMAP EmailSubmission/set
jmapsmtp:
  → buildRaw() → injectAutocryptHeader (sender pubkey.pgp) + Chat-Version: 1.0
  → if body contains inline PGP block: pgpMIMEWrapInline → multipart/encrypted
  → DKIM sign → SMTP delivery
  → Sent copy: if PGP block, store as-is ($e2e: true)

[Account setup]
Admin: add account to config.json (no envelope yet)
  → on startup: generate token, log URL
  → GET /setup?token=xxx → HTML form (loads hash-wasm from CDN)
  → client builds Argon2id + AES-GCM envelope in browser
  → POST /auth/signup?token=xxx → save envelope.json → delete token
  Subsequent logins: GET /auth/envelope → client-side unseal → authToken
```

### Key Derivation (KEK Wrap)

```
password
  │
  ├─Argon2id(salt, t=3, m=64MiB, p=4)──> wrap_key (32B)
  │     │
  │     └─AES-GCM-open(wrapped_secret)──> master_secret (32B, random, stored wrapped in envelope)
  │           │
  │           ├─HKDF-SHA256("biset-jmapsmtp/auth/v1")──> auth_token (32B)
  │           │     │
  │           │     ├─Sent to server as Basic Auth password = base64(auth_token)
  │           │     └─Server stores sha256(auth_token) in envelope.json (constant-time compare)
  │           │
  │           └─HKDF-SHA256("biset-jmapsmtp/enc/v1")───> KEK (32B)
  │                 │
  │                 └─Used as AES-GCM key to encrypt the OpenPGP private key (privkey.enc)
```

**Core design principle**: master_secret is a random 32-byte value generated once and **never changes**, even when the password changes. `Rewrap(oldPw, newPw)` only regenerates `wrapped_secret` and `salt`; master_secret is preserved. As a result:

- `auth_token` is unchanged → existing sessions (base64(auth_token) stored in localStorage) remain valid
- `KEK` is unchanged → `privkey.enc` stored on the server does not need to be re-encrypted

A password change requires **writing a single file (`envelope.json`)** and nothing else.

### Keypair Management

```
Browser (first login)
  │
  ├─→ buildEnvelope(pw) → generate master_secret → POST /auth/signup
  │     │                            ↑
  │     └─→ authToken + KEK derived (in memory)
  │
  ├─→ Generate OpenPGP keypair (curve25519Legacy, OpenPGP.js)
  │     │
  │     ├─→ Private key
  │     │     ├─→ Save to IndexedDB (plaintext cache)
  │     │     └─→ AES-GCM(KEK) encrypt → PUT /pgp/privkey (server storage)
  │     │
  │     └─→ Public key → PUT /pgp/pubkey → served via WKD
  │
  └─→ Additional devices (restore flow)
        GET /auth/envelope → unsealEnvelope(env, pw) → authToken + KEK
        GET /pgp/privkey → AES-GCM decrypt(KEK) → save to IndexedDB
```

Multiple devices derive the same master_secret from the same password, naturally sharing the same authToken and KEK. After a password change, an authToken stored in localStorage on an old device remains valid (master_secret is unchanged).

### What Can the Server Operator Read?

| Information | What the server holds | Readable? |
|---|---|---|
| Password | Nothing (envelope only, gated by Argon2id) | No |
| master_secret / auth_token / KEK | sha256(authToken) only | No (requires Argon2id with the password) |
| Private key (privkey.enc) | AES-GCM ciphertext only | No |
| Message body | OpenPGP ciphertext only (after Layer 1) | No |
| Incoming plaintext mail | Plaintext for an instant during receive | Technically possible (SMTP constraint) |
| Incoming PGP/MIME mail | PGP ciphertext only | No |

### External Compatibility

External communication follows standard OpenPGP/Autocrypt. Interoperability with DeltaChat, Thunderbird, and K-9 Mail has been confirmed. Autocrypt peer public keys accumulate in `peers/<addr>.pgp`. **The first message is sent in plaintext** (advertising the sender's key via the Autocrypt header); encryption begins only after receiving a reply that carries the peer's key. This is per the Autocrypt specification.
