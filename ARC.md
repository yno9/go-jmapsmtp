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
├── provision.go          # Dynamic account provisioning, identity anchor, reply_only helpers
├── maintenance.go        # Per-account storage limit check, inactive account purge
├── wkd.go                # WKD and /pgp/* endpoints
├── cryptenv/
│   ├── envelope.go       # KEK envelope: NewEnvelope, Unseal, Rewrap, VerifyAuth
│   └── envelope_test.go
├── config.example.json
├── go.mod / go.sum
└── ARC.md
```

### File responsibilities

| File | Responsibility |
|---|---|
| `main.go` | Reads config; builds alias map and per-account Stores; wires `OnCreateEmail` and `OnSubmitEmail` hooks; starts SMTP server and JMAP HTTP server. Contains: JMAP `handler`, incoming message buffer, `sendEmail` (SMTP delivery), `/setup` HTML endpoint. |
| `auth_env.go` | `authenticate(r, dataDir)` shared auth helper; `GET /auth/envelope`, `PUT /auth/envelope`, `POST /auth/signup` endpoints; `readEnvelope`/`writeEnvelope` disk I/O. |
| `autocrypt.go` | Parse and inject `Autocrypt:` headers; store/load peer public keys (`peers/<addr>.pgp`); `pgpEncryptInline`; `pgpMIMEWrapInline` (wrap inline PGP as RFC 3156 multipart/encrypted for SMTP). |
| `dkim.go` | Generate and persist RSA 2048 DKIM keys per domain; `signDKIMForDomain` signs outgoing raw messages; `loadOrGenerateDKIMKeys` called at startup. |
| `provision.go` | `POST /account/provision` (dynamic account creation); `scanDynAccounts` (restart recovery); identity anchor push (`anchorClaim`, `backfillAnchorPush`); `provisionDomain()` (returns the one `allow_provision` domain); `replyOnlyExempt(sender)`. |
| `maintenance.go` | `dirSizeMB(dir)` (walk-based disk usage); `lastActivity(dir)` (newest file mtime); `startMaintenance` (launch purge goroutine every 6h); `purgeInactiveAccounts`. |
| `wkd.go` | WKD key lookup; `PUT /pgp/pubkey`, `GET/PUT /pgp/privkey`, `GET/PUT /pgp/peerkey`. |
| `cryptenv/envelope.go` | Self-contained KEK envelope package. |

---

## Roles

- **Receive**: Store incoming SMTP mail in the JMAP Store
- **Send**: Accept `EmailSubmission/set` from JMAP clients and deliver via SMTP
- **Serve**: Expose an RFC 8621-compliant JMAP HTTP endpoint to clients
- **Account management**: Password setup via one-time setup URL; dynamic provisioning for open-registration domains

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
  "anchor_url": "http://127.0.0.1:8768",
  "reply_only_outbound": true,
  "reply_only_exempt": ["example.com"],
  "max_account_storage_mb": 500,
  "inactive_purge_days": 14,
  "peer_data_dirs": ["/root/jmapap/data"],
  "domain": {
    "example.com": {
      "allow_provision": false,
      "account": {
        "you": { "alias": ["yu"] }
      }
    },
    "t.example.com": {
      "allow_provision": true,
      "account": {}
    }
  }
}
```

### Fields

| Field | Purpose |
|---|---|
| `listen_addr` | JMAP HTTP port |
| `base_url` | Used to generate setup URLs |
| `hostname` | SMTP EHLO and Message-Id domain |
| `relay_host` | Empty = direct MX delivery; set = route through this host |
| `anchor_url` | URL of the identity anchor (jmapap); empty = single-relay mode |
| `reply_only_outbound` | When true, outbound is blocked unless every recipient has previously sent a message to the sender |
| `reply_only_exempt` | Domains (e.g. `"example.com"`) or addresses (e.g. `"y@t.example.com"`) exempt from `reply_only_outbound` |
| `max_account_storage_mb` | Per-account disk usage cap. 0 = unlimited |
| `inactive_purge_days` | Auto-delete accounts on `allow_provision` domains inactive for this many days across **all** relays. 0 = disabled |
| `peer_data_dirs` | Sibling relay data directories consulted before purging; account is only purged if all peers are also inactive |
| `domain.<d>.allow_provision` | Enables self-service account creation via `POST /account/provision` |
| `domain.<d>.dkim_selector` | Empty = defaults to `"default"` |
| `account.<lp>.alias` | Aliases delivered to this account |

---

## Domain Model: Static vs Dynamic Accounts

**Static accounts** are declared in `config.json` under `domain.<d>.account`. They are initialized via setup tokens (admin-issued). `allow_provision: false` prevents self-service creation.

**Dynamic accounts** are created at runtime via `POST /account/provision` on a domain with `allow_provision: true`. They are persisted to disk and recovered on restart by `scanDynAccounts`. `provisionDomain()` returns the single domain with `allow_provision: true`.

---

## Outbound Security: reply_only_outbound

When `reply_only_outbound: true`, `OnSubmitEmail` checks that every `RCPT TO` address appears as a `From` in the sender's own Store. If any recipient has never sent a message to the sender, the submission is rejected.

Senders listed in `reply_only_exempt` (by domain or full address) bypass this check.

**Rationale**: prevents spam abuse on open-registration domains. An attacker can only send to addresses that have already initiated contact, making mass outbound spam infeasible. The DeltaChat SecureJoin flow (vc-request arrives first) is naturally compatible.

---

## Maintenance

`startMaintenance` launches a goroutine that runs `purgeInactiveAccounts` every 6 hours.

**Purge criteria** (all must be true):
1. Account is on a domain with `allow_provision: true`
2. Account is not in the static `account` map
3. Newest file mtime in `data/<domain>/<lp>/` is older than `inactive_purge_days`
4. Same check passes for every path in `peer_data_dirs` — i.e. the sibling relay (jmapap) is also inactive

An account active on jmapap but idle on jmapsmtp (or vice versa) is **not** purged.

Purge operation: `os.RemoveAll(acctDir)` + evict from `h.stores`, `h.dyn`, `h.aliases` under write lock.

**Storage limit**: `OnCreateEmail` (inbound) and `OnSubmitEmail` (outbound) check `dirSizeMB` before accepting. If the per-account cap is reached, the operation returns an error.

---

## Runtime Directory Layout

```
~/jmapsmtp/
├── jmapsmtp
├── config.json
└── data/
    └── example.com/
        ├── key.pem          # DKIM RSA private key
        ├── dkim-dns.txt     # DNS TXT record to publish
        ├── peers/           # Autocrypt peer public keys
        │   └── <peer-addr>.pgp
        └── you/             # Per-localpart JMAP Store
            ├── messages/<encid>.json  # encid = encodeURIComponent(jmap-id)
            ├── mailboxes.json
            ├── identities.json
            ├── delta.json
            ├── envelope.json
            ├── pubkey.pgp
            ├── privkey.enc
            └── setup.token    # Only present before first login
```

**Note**: Message filenames use `encodeURIComponent(id)` because AP message IDs are URLs containing `/` and `:` which are invalid filesystem names.

---

## Components

### JMAP Server

- `handler` implements the `jmapserver.Handler` interface
- Each account has its own independent `jmapserver.Store`
- `Handle(method, args)` inspects `accountId` and routes to the corresponding Store

### SMTP Server (port 25)

- Uses `github.com/emersion/go-smtp`
- Resolves `RCPT TO` through the alias map to identify the primary account
- Incoming mail is queued in a channel buffer (256 messages)
- Buffer is drained into the Store on `Email/query`

### Authentication

Zero-knowledge authentication via cryptenv envelope. The server never holds a password.

| Method / Path | Auth | Purpose |
|---|---|---|
| `GET /auth/envelope?email=...` | None | Return envelope JSON |
| `PUT /auth/envelope` | Basic | Replace envelope (password change) |
| `POST /auth/signup?token=...` | Setup token | Register envelope for the first time |
| `GET /setup?token=...` | Setup token | HTML page; builds Argon2id envelope client-side |
| `POST /account/provision` | None | Create a new dynamic account (domain must have `allow_provision: true`) |

### DKIM

- RSA 2048 key per domain, persisted to `data/<domain>/key.pem`
- Generated on startup if missing; DNS record written to `dkim-dns.txt`
- Selector defaults to `"default"`

### Autocrypt / PGP

- Outgoing mail gets `Autocrypt:` and `Chat-Version: 1.0` headers
- Incoming `Autocrypt:` headers → peer key stored in `peers/<addr>.pgp`
- `pgpMIMEWrapInline` converts inline PGP to RFC 3156 `multipart/encrypted`
- Layer 2 E2E encryption/decryption is entirely client-side (biset-ui)

### Identity Anchor

On provisioning and setup-token claim, jmapsmtp pushes the account name + envelope fingerprint to the identity anchor (`anchor_url/identity/<lp>`). This prevents the same address from being registered with a different key on another relay — i.e. prevents split identities.

---

## Encryption Architecture

| Layer | Responsibility | Owner |
|---|---|---|
| Layer 1 | Storage encryption (stored with recipient's own public key) | jmapsmtp |
| Layer 2 | E2E encryption + signing | biset-ui |

### Key Derivation

```
password
  └─Argon2id(salt)──> wrap_key
        └─AES-GCM-open(wrapped_secret)──> master_secret
              ├─HKDF("biset-jmapsmtp/auth/v1")──> auth_token  → Basic Auth password
              └─HKDF("biset-jmapsmtp/enc/v1")───> KEK         → encrypts privkey.enc
```

master_secret never changes on password rotation. auth_token and KEK are stable across password changes; existing sessions and `privkey.enc` remain valid after a password change.

### Data Flow

```
[Receive]
External MTA → SMTP:25 → ParseMIME → extract Autocrypt peer key
  → already PGP ciphertext → store as-is ($e2e: true)
  → plaintext → [Layer 1] encrypt with recipient pubkey → store
  → buffer → drainBuffer() on Email/query → store.Put()

[Send]
biset-ui: encrypt(body, [recipient, sender]) + sign → JMAP EmailSubmission/set
jmapsmtp:
  → storage limit check (dirSizeMB)
  → reply_only_outbound check (unless sender is exempt)
  → buildRaw → injectAutocrypt → pgpMIMEWrapInline → DKIMsign → SMTP delivery

[Account setup — static]
admin issues setup token → GET /setup?token → client builds envelope → POST /auth/signup
  → anchorClaim pushed to jmapap identity anchor

[Account setup — dynamic]
client → POST /account/provision → provisionDomain() → validations
  → claimIdentity (local anchor check) → writeEnvelope → addDynAccount
```

### What the Server Can Read

| Information | Server holds | Readable? |
|---|---|---|
| Password | Nothing (Argon2id-gated envelope) | No |
| master_secret / auth_token / KEK | sha256(authToken) only | No |
| Private key | AES-GCM ciphertext (privkey.enc) | No |
| Message body (E2E) | OpenPGP ciphertext | No |
| Incoming plaintext SMTP | Plaintext briefly during receive | Technically yes (SMTP constraint) |
