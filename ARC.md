# jmapsmtp アーキテクチャ

SMTP（port 25）と JMAP（RFC 8621）を双方向にブリッジする小さなデーモン。
Postfix 相当の MTA として動作し、ユーザーのメールボックスを管理する。

---

## 役割

- **受信**: 外部から届いた SMTP メールを JMAP Store に格納
- **送信**: JMAP クライアントの `EmailSubmission/set` を受け取り SMTP で配送
- **公開**: RFC 8621 準拠の JMAP HTTP エンドポイントをクライアントに提供
- **アカウント管理**: セットアップ URL によるパスワード設定フロー

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

### フィールド

| フィールド | 用途 |
|---|---|
| `listen_addr` | JMAP HTTP ポート |
| `base_url` | セットアップ URL 生成に使用 |
| `hostname` | SMTP EHLO、送信時の Message-Id ドメイン |
| `relay_host` | 空 = MX 直接配送、設定あり = そのホスト経由 |
| `domain.<d>.dkim_selector` | 空 = "default" にフォールバック |
| `account.<addr>.alias` | このアカウントに届けるエイリアス |

config にパスワード情報は含まれない。認証は `data/<domain>/<localpart>/envelope.json`（cryptenv envelope）で行う。envelope が存在しないアカウントは起動時にセットアップ URL をログに出力する。

---

## ディレクトリ構成（実行時）

```
~/jmapsmtp/
├── jmapsmtp             # バイナリ
├── config.json
├── jmapsmtp.log
└── data/
    └── example.com/
        ├── key.pem          # DKIM RSA 秘密鍵（起動時に自動生成）
        ├── dkim-dns.txt     # DNS に登録する TXT レコード（参照用）
        ├── peers/                # Autocrypt で蓄積した相手の公開鍵（暗号送信の前提）
        │   └── <peer-addr>.pgp
        └── you/             # localpart ごとの JMAP Store
            ├── messages/<id>.json  # メール1件1ファイル
            ├── mailboxes.json      # メールボックス一覧
            ├── identities.json     # Identity 情報
            ├── delta.json          # state カウンタ + 変更履歴
            ├── envelope.json       # cryptenv envelope（認証 + 鍵ラップ、後述）
            ├── pubkey.pgp          # ユーザー公開鍵（WKD で配信）
            ├── privkey.enc         # KEK で暗号化された秘密鍵（クライアント側で復号）
            └── setup.token         # ワンタイムセットアップトークン（envelope 未生成のときのみ）
```

**注意**: 全消去（`rm -rf data/`）は **`peers/` も消す** → 既存ピアとの Autocrypt 状態がリセットされ、次の往復から再構築になる。テスト時以外は避ける。

---

## コンポーネント

### JMAP サーバー（`go-jmapserver`）

- `handler` が `jmapserver.Handler` インターフェースを実装
- アカウントごとに独立した `jmapserver.Store` を保持
- `Handle(method, args)` 内で `accountId` を見て対応する Store にルーティング

対応メソッド：

| メソッド | 実装 |
|---|---|
| `Email/query` | バッファをドレインしてから Store |
| `Email/get`, `Email/changes`, `Email/queryChanges` | Store |
| `Email/set` | 下書き作成（PutPending）・キーワード更新 |
| `EmailSubmission/set` | SMTP 送信 |
| `Thread/get`, `Thread/changes` | Store |
| `Mailbox/get`, `Mailbox/changes` | Store |
| `Identity/get`, `Identity/changes` | Store |

### SMTP サーバー（port 25）

- `github.com/emersion/go-smtp` を使用
- RCPT TO を alias マップで解決 → 対応する primary account を特定
- 受信メールはチャネルバッファ（256件）に積む
- `Email/query` 呼び出し時にバッファをドレインして Store に格納

### 認証（`auth_env.go` + `cryptenv/`）

cryptenv envelope によるゼロ知識認証。サーバはパスワードを一切持たない。

- JMAP HTTP / `/pgp/*` は Basic Auth: `username = email`, `password = base64(auth_token)`（32B のランダム値、master_secret から HKDF 派生）
- 検証: `data/<d>/<lp>/envelope.json` を読み込み、`Envelope.VerifyAuth(authToken)` で sha256 定数時間比較
- `authenticate(r, dataDir) → (domain, localpart, ok)` を全エンドポイントで共用

エンドポイント:

| メソッド・パス | 認証 | 用途 |
|---|---|---|
| `GET /auth/envelope?email=...` | なし | envelope JSON を返す（opaque、pw 知らない攻撃者には無価値） |
| `PUT /auth/envelope` | Basic | rewrap 済み envelope に差し替え（パスワード変更） |
| `POST /auth/signup?token=...` | setup token | envelope を初回登録、トークン削除 |
| `GET /setup?token=...` | setup token | Argon2id でクライアント側 envelope 生成 → `/auth/signup` に POST する HTML |

setup ページは `hash-wasm` (esm.sh CDN) で Argon2id を実行する。サーバは平文パスワードを一度も受信しない。

### DKIM（`dkim.go`）

- ドメインごとに RSA 2048 鍵を管理
- 鍵は `data/<domain>/key.pem` に永続化、起動時に読み込み（なければ生成）
- 送信時に From アドレスのドメインで鍵を選択して署名

### Autocrypt / PGP（`autocrypt.go`）

- 送信メールに `Autocrypt:` ヘッダーと `Chat-Version: 1.0` を付与（送信者の `pubkey.pgp` を広告）
- 受信メールの `Autocrypt:` ヘッダーから相手公開鍵を抽出 → `data/<domain>/peers/<addr>.pgp` に保存
- クライアント（biset-ui）が暗号化済み inline PGP メッセージを送信してきた場合、`pgpMIMEWrapInline` で RFC 3156 multipart/encrypted 形式にラップして SMTP 送信（DeltaChat 互換）
- サーバー側では Layer 2 暗号化・署名は**一切行わない**（秘密鍵を持たないので不可）

### WKD（`wkd.go`）

- `/.well-known/openpgpkey/` でユーザー公開鍵を配信（Web Key Directory）
- ユーザーごとの鍵: `data/<domain>/<localpart>/pubkey.pgp`
- `PUT /pgp/pubkey` — クライアントが自分の公開鍵をアップロード（Basic Auth）
- `GET/PUT /pgp/privkey` — KEK 暗号化された秘密鍵のサーバー保管（Basic Auth）
- `GET/PUT /pgp/peerkey?addr=<email>` — Autocrypt 相手公開鍵の参照・登録（Basic Auth）

すべて `authenticate()` 経由で envelope の `VerifyAuth(authToken)` を呼ぶ。

### cryptenv（`cryptenv/`）

password-derived key envelope の独立パッケージ。jmapsmtp 専用配置だが、将来他 relay で必要になれば外部 module 化可能な設計。

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
(env).Rewrap(oldPw, newPw)    → *Envelope  // master_secret 不変
(env).VerifyAuth(authToken)   → bool       // サーバ側ゼロ知識検証
```

KDF パラメータ既定値: Argon2id, t=3, m=64 MiB, p=4 (OWASP 推奨)。

---



## 暗号化アーキテクチャ

責務を明確に分離した 2 レイヤー構成。

| Layer | 責務 | 担当 |
|---|---|---|
| Layer 1 | Store 暗号化（受信者自身の公開鍵で保存） | **jmapsmtp** |
| Layer 2 | E2E 暗号化＋署名（相手公開鍵で送信、相手から復号） | **biset-ui** |

### Layer 1: ストレージ暗号化（jmapsmtp 担当）

平文がディスクに残らないよう、受信時・送信時を問わずユーザー自身の公開鍵（`data/<domain>/<localpart>/pubkey.pgp`）で暗号化してから Store に保存。

- **受信時**: SMTP で届いた平文メールを受信者の公開鍵で暗号化 → keywords: `$e2e: false`
- **受信時（既に暗号文）**: そのまま保存 → keywords: `$e2e: true`
- **送信時の Sent コピー**: 平文なら送信者の公開鍵で暗号化、暗号文（クライアント E2E）ならそのまま

サーバーは秘密鍵を持たない → 保存後は復号不可。

### Layer 2: E2E 暗号化（biset-ui 担当）

すべての暗号化操作はクライアントブラウザ内で OpenPGP.js を用いて行う。

- **鍵生成**: 初回ログイン時にブラウザでキーペア生成（curve25519Legacy）
- **送信時**: `peers/<toAddr>.pgp` をサーバーから取得 → 相手公開鍵+自分公開鍵で暗号化 → 秘密鍵で署名 → inline PGP メッセージとして JMAP に submit
- **受信時**: ブラウザ内 IndexedDB の秘密鍵で復号 → 内部 Protected Headers をパースして本文だけ表示
- **WKD プリフェッチ**: 新規メッセージ作成時、宛先入力 blur で WKD を叩いて相手公開鍵を取得 → サーバーの `peers/` に保存（送信時の遅延を回避）

jmapsmtp はクライアントから受け取った inline PGP メッセージを `pgpMIMEWrapInline` で multipart/encrypted にラップするだけ（暗号化はしない）。

### データフロー

```
【受信（外部 MTA → ユーザー）】
外部 MTA → SMTP:25 → session.Data()
  → ParseMIMEEmail（multipart/encrypted なら inner PGP ブロックを抽出）
  → Autocrypt ヘッダーから相手公開鍵を抽出 → peers/<addr>.pgp に保存
  → 本文が PGP ブロック → そのまま保存（$e2e: true）
  → 本文が平文        → [Layer 1] 受信者 pubkey.pgp で暗号化 → 保存
  → bufferEmail → [Email/query 時] drainBuffer() → store.Put()

【送信（biset-ui → 外部）】
biset-ui:
  fetchRecipientPublicKey(peers/<to>.pgp from server)
    → encryptText: OpenPGP encrypt(body, [recipient, sender]) + sign(senderPriv)
    → MIME wrapper（Content-Type, Chat-Version）を内包
  → JMAP EmailSubmission/set
jmapsmtp:
  → buildRaw() → injectAutocryptHeader（送信者 pubkey.pgp）+ Chat-Version: 1.0
  → 本文に inline PGP ブロックあれば pgpMIMEWrapInline で multipart/encrypted 化
  → DKIM 署名 → SMTP 送信
  → Sent コピー: 本文が PGP ブロックならそのまま保存（$e2e: true）

【アカウントセットアップ】
管理者: config.json にアカウント追加（envelope なし）
  → 起動時にトークン生成・ログ出力
  → GET /setup?token=xxx → HTML フォーム（hash-wasm CDN ロード）
  → クライアント側で Argon2id + AES-GCM で envelope 構築
  → POST /auth/signup?token=xxx → envelope.json 保存 → トークン削除
  以降のログインは GET /auth/envelope → クライアント側 unseal → authToken
```

### 鍵導出（KEK ラップ）

```
password
  │
  ├─Argon2id(salt, t=3, m=64MiB, p=4)─> wrap_key (32B)
  │     │
  │     └─AES-GCM-open(wrapped_secret)─> master_secret (32B, ランダム生成・envelope に wrapped で保管)
  │           │
  │           ├─HKDF-SHA256("biset-jmapsmtp/auth/v1")─> auth_token (32B)
  │           │     │
  │           │     ├─Basic Auth password = base64(auth_token) としてサーバ送信
  │           │     └─サーバは sha256(auth_token) を envelope.json に保管 (constant-time 比較)
  │           │
  │           └─HKDF-SHA256("biset-jmapsmtp/enc/v1")──> KEK (32B)
  │                 │
  │                 └─AES-GCM 鍵として OpenPGP 秘密鍵 (privkey.enc) を暗号化
```

**設計上の核心**: master_secret はランダム生成された 32B、パスワードが変わっても**変わらない**。`Rewrap(oldPw, newPw)` は `wrapped_secret` と `salt` を作り直すだけで master_secret は同一。結果として:

- `auth_token` 不変 → 既存セッション (localStorage に保管された base64(auth_token)) は失効しない
- `KEK` 不変 → サーバ保管中の `privkey.enc` を再暗号化する必要なし

pw 変更は **`envelope.json` 1 ファイル書き換えのみ**で完了する。

### 鍵ペア管理

```
ブラウザ（初回ログイン）
  │
  ├─→ buildEnvelope(pw) → master_secret 生成 → POST /auth/signup
  │     │                            ↑
  │     └─→ authToken + KEK 取得 (メモリ)
  │
  ├─→ OpenPGP 鍵ペア生成（curve25519Legacy、OpenPGP.js）
  │     │
  │     ├─→ 秘密鍵
  │     │     ├─→ IndexedDB に保存（平文キャッシュ）
  │     │     └─→ AES-GCM(KEK) で暗号化 → PUT /pgp/privkey（サーバー保存）
  │     │
  │     └─→ 公開鍵 → PUT /pgp/pubkey → WKD で配信
  │
  └─→ 2台目以降のデバイス（復元フロー）
        GET /auth/envelope → unsealEnvelope(env, pw) → authToken + KEK
        GET /pgp/privkey → AES-GCM 復号(KEK) → IndexedDB に保存
```

複数デバイスは同じ password から同じ master_secret を導出するため、自然に同じ authToken + KEK を共有する。pw 変更後、旧デバイスの localStorage に保管された authToken は引き続き有効（master_secret 不変のため）。

### 管理者が読めるか

| 情報 | サーバーが持つもの | 読めるか |
|---|---|---|
| パスワード | なし（envelope のみ、Argon2id でゲート） | 不可 |
| master_secret / auth_token / KEK | sha256(authToken) のみ | 不可（pw による Argon2id 解読が必要） |
| 秘密鍵 (privkey.enc) | AES-GCM(KEK) 暗号文のみ | 不可 |
| メール本文 | OpenPGP 暗号文のみ（Layer 1 適用後） | 不可 |
| 外部受信メール（平文の場合） | 受信の一瞬だけ平文 | 技術的には可能（SMTP 制約） |
| 外部受信メール（PGP/MIME の場合） | PGP 暗号文のみ | 不可 |

### 外部互換性

外部との通信は標準 OpenPGP/Autocrypt 準拠。DeltaChat・Thunderbird・K-9 Mail との相互運用を確認済み。Autocrypt 相手公開鍵は `peers/<addr>.pgp` に蓄積され、**初回送信は平文**（Autocrypt ヘッダーで自分の鍵を広告）、相手から返信を受けて初めて peer key を取得し以降は暗号化される。これは Autocrypt 仕様通り。
