package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	stdmail "net/mail"
	"os"
	"path/filepath"
	"strings"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"git.sr.ht/~rockorager/go-jmap/mail/email"
	"git.sr.ht/~rockorager/go-jmap/mail/emailsubmission"
	"git.sr.ht/~rockorager/go-jmap/mail/mailbox"
	gosmtp "github.com/emersion/go-smtp"
	"github.com/ProtonMail/go-crypto/openpgp"
	jmapserver "github.com/yno9/go-jmapserver"
)

// ── config ────────────────────────────────────────────────────────────────────

type AccountConfig struct {
	Alias []string `json:"alias"`
}

// ── auth helpers ──────────────────────────────────────────────────────────────

func tokenFile(dataDir, domain, localpart string) string {
	return filepath.Join(dataDir, domain, localpart, "setup.token")
}

func generateToken() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}

type DomainConfig struct {
	DKIMSelector string                   `json:"dkim_selector"`
	Accounts     map[string]AccountConfig `json:"account"`
}

type Config struct {
	jmapserver.Config
	Hostname  string                  `json:"hostname"`
	SMTPPort  int                     `json:"smtp_port"`
	RelayHost string                  `json:"relay_host"`
	Domains   map[string]DomainConfig `json:"domain"`
}

var cfg Config

// ── message helpers ───────────────────────────────────────────────────────────

func makeMailboxID(addr string) string {
	return "mbx-" + strings.ReplaceAll(addr, "/", "~")
}

func makeMessageID(messageID, addr string, ts time.Time) string {
	if messageID != "" {
		return "msg-" + strings.ReplaceAll(messageID, "/", "_")
	}
	return fmt.Sprintf("msg-%s-%d", strings.ReplaceAll(addr, "/", "-"), ts.UnixMilli())
}

func defaultInbox(addr string) mailbox.Mailbox {
	return mailbox.Mailbox{
		ID:   jmap.ID(makeMailboxID(addr)),
		Name: addr,
		Role: mailbox.RoleInbox,
		Rights: &mailbox.Rights{
			MayReadItems:   true,
			MayAddItems:    true,
			MayRemoveItems: true,
			MaySetSeen:     true,
			MaySetKeywords: true,
			MayCreateChild: false,
			MayRename:      false,
			MayDelete:      false,
			MaySubmit:      true,
		},
		IsSubscribed: true,
	}
}

// ── handler ───────────────────────────────────────────────────────────────────

type handler struct {
	stores  map[string]*jmapserver.Store
	aliases map[string]string
	hub     *jmapserver.Hub
}

func (h *handler) Capabilities() []jmap.URI {
	return []jmap.URI{
		"urn:ietf:params:jmap:mail",
		"urn:ietf:params:jmap:submission",
	}
}

func (h *handler) Accounts() []jmapserver.Account {
	var out []jmapserver.Account
	for domain, domCfg := range cfg.Domains {
		for localpart := range domCfg.Accounts {
			addr := localpart + "@" + domain
			out = append(out, jmapserver.Account{ID: jmap.ID(addr), Name: addr})
		}
	}
	return out
}

func (h *handler) storeFor(args json.RawMessage) (*jmapserver.Store, jmap.ID, error) {
	var base struct {
		AccountID jmap.ID `json:"accountId"`
	}
	if err := json.Unmarshal(args, &base); err != nil {
		return nil, "", err
	}
	store, ok := h.stores[string(base.AccountID)]
	if !ok {
		return nil, "", fmt.Errorf("accountNotFound: %s", base.AccountID)
	}
	return store, base.AccountID, nil
}

func (h *handler) Handle(method string, args json.RawMessage) (any, error) {
	store, accountID, err := h.storeFor(args)
	if err != nil {
		return nil, err
	}
	h.drainBuffer()
	return store.Dispatch(accountID, method, args)
}

// ── incoming buffer ───────────────────────────────────────────────────────────

type incoming struct {
	account string
	msg     email.Email
}

var bufCh = make(chan incoming, 256)

func bufferEmail(account string, e email.Email) {
	select {
	case bufCh <- incoming{account, e}:
	default:
		log.Printf("incoming buffer full, dropping message %s for %s", e.ID, account)
	}
}

func (h *handler) drainBuffer() {
	for {
		select {
		case inc := <-bufCh:
			store, ok := h.stores[inc.account]
			if ok {
				store.Put(inc.msg) //nolint:errcheck
			}
		default:
			return
		}
	}
}

// ── SMTP server ───────────────────────────────────────────────────────────────

type backend struct {
	hub     *jmapserver.Hub
	aliases map[string]string
	dataDir string
}

func (b *backend) NewSession(_ *gosmtp.Conn) (gosmtp.Session, error) {
	return &session{hub: b.hub, aliases: b.aliases, dataDir: b.dataDir}, nil
}

type session struct {
	hub     *jmapserver.Hub
	aliases map[string]string
	dataDir string
	from    string
	to      []string
}

func (s *session) AuthPlain(_, _ string) error { return nil }

func (s *session) Mail(from string, _ *gosmtp.MailOptions) error {
	s.from = from
	return nil
}

func (s *session) Rcpt(to string, _ *gosmtp.RcptOptions) error {
	addr := strings.ToLower(to)
	if _, ok := s.aliases[addr]; ok {
		s.to = append(s.to, addr)
	}
	return nil
}

func (s *session) Data(r io.Reader) error {
	if len(s.to) == 0 {
		return nil
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	os.WriteFile("/tmp/jmapsmtp-last-in.eml", raw, 0600) //nolint:errcheck

	parsed, err := jmapserver.ParseMIMEEmail(raw)
	if err != nil {
		return err
	}

	// Extract and store Autocrypt key from sender.
	if msg, e2 := stdmail.ReadMessage(bytes.NewReader(raw)); e2 == nil {
		acHeader := msg.Header.Get("Autocrypt")
		log.Printf("[autocrypt] header present=%v from=%v to=%v", acHeader != "", s.from, s.to)
		if acHeader != "" {
			if addr, keydata := parseAutocryptHeader(acHeader); addr != "" && keydata != "" {
				for _, rcpt := range s.to {
					if domain := strings.SplitN(s.aliases[rcpt], "@", 2); len(domain) == 2 {
						storePeerKey(s.dataDir, domain[1], addr, keydata)
						break
					}
				}
			}
		}
	}

	delivered := map[string]bool{}
	for _, rcpt := range s.to {
		primary := s.aliases[rcpt]
		if delivered[primary] {
			continue
		}
		delivered[primary] = true

		now := time.Now()
		e := parsed
		rawMsgID := ""
		if len(parsed.MessageID) > 0 {
			rawMsgID = parsed.MessageID[0]
		}
		e.ID = jmap.ID(makeMessageID(rawMsgID, primary, now))
		e.MailboxIDs = map[jmap.ID]bool{jmap.ID(makeMailboxID(primary)): true}
		e.ReceivedAt = &now

		// Encrypt with recipient's public key if available and body is not already PGP.
		if parts := strings.SplitN(primary, "@", 2); len(parts) == 2 {
			body := jmapserver.MessageBody(e)
			if body != "" {
				if strings.Contains(body, "-----BEGIN PGP MESSAGE-----") {
					// Already E2E encrypted by sender — mark as such.
					if e.Keywords == nil {
						e.Keywords = map[string]bool{}
					}
					e.Keywords["$e2e"] = true
				} else if entity := loadUserPubkeyEntity(s.dataDir, parts[1], parts[0]); entity != nil {
					if enc, err := pgpEncryptInline([]byte(body), entity); err == nil {
						encStr := string(enc)
						if e.BodyValues == nil {
							e.BodyValues = map[string]*email.BodyValue{}
						}
						for _, part := range e.TextBody {
							e.BodyValues[part.PartID] = &email.BodyValue{Value: encStr}
						}
						e.HTMLBody = nil
					}
				}
			}
		}

		bufferEmail(primary, e)
	}
	s.hub.Notify()
	return nil
}

func (s *session) Reset()        { s.from = ""; s.to = nil }
func (s *session) Logout() error { return nil }

func startSMTP(hub *jmapserver.Hub, aliases map[string]string, dataDir string) {
	port := cfg.SMTPPort
	if port == 0 {
		port = 25
	}
	srv := gosmtp.NewServer(&backend{hub: hub, aliases: aliases, dataDir: dataDir})
	srv.Addr = fmt.Sprintf(":%d", port)
	srv.Domain = cfg.Hostname
	srv.AllowInsecureAuth = true
	srv.EnableSMTPUTF8 = true
	log.Printf("[smtp] listening on %s", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("smtp: %v", err)
	}
}

// ── send ──────────────────────────────────────────────────────────────────────

// sendEmail returns (generatedMsgID, error). Layer 2 encryption is done client-side by biset-ui.
func sendEmail(e email.Email, env emailsubmission.Envelope, senderEntity *openpgp.Entity, dataDir, senderDomain string) (string, error) {
	from := env.MailFrom.Email
	var toList []string
	for _, r := range env.RcptTo {
		toList = append(toList, r.Email)
	}
	if len(toList) == 0 {
		return "", fmt.Errorf("no recipients")
	}

	raw, generatedMsgID := jmapserver.BuildRFC5322(e, cfg.Hostname)
	if senderEntity != nil {
		raw = injectEntityAutocryptHeader(raw, from, senderEntity)
	} else {
		raw = injectAutocryptHeader(raw, from)
	}
	raw = injectChatVersionHeader(raw)
	// Layer 2 is handled by biset-ui (client encrypts+signs).
	// If body contains an inline PGP block, wrap it in PGP/MIME (RFC 3156) for SMTP transport.
	if bytes.Contains(raw, []byte("-----BEGIN PGP MESSAGE-----")) {
		if wrapped, err := pgpMIMEWrapInline(raw); err == nil {
			raw = wrapped
			log.Printf("[autocrypt] wrapped client-encrypted body as PGP/MIME for %v", toList)
		} else {
			log.Printf("[autocrypt] wrap failed: %v", err)
		}
	}
	fromDomain := ""
	if parts := strings.SplitN(from, "@", 2); len(parts) == 2 {
		fromDomain = parts[1]
	}
	raw = signDKIMForDomain(raw, fromDomain)
	// Dump outgoing message to file for debugging.
	os.WriteFile("/tmp/jmapsmtp-last-out.eml", raw, 0600) //nolint:errcheck

	target := cfg.RelayHost
	if target == "" {
		toDomain := strings.SplitN(toList[0], "@", 2)[1]
		mxs, err := net.LookupMX(toDomain)
		if err != nil || len(mxs) == 0 {
			return "", fmt.Errorf("no MX for %s", toDomain)
		}
		target = strings.TrimSuffix(mxs[0].Host, ".") + ":25"
	}
	conn, err := net.DialTimeout("tcp", target, 30*time.Second)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", target, err)
	}
	c, err := smtp.NewClient(conn, strings.SplitN(target, ":", 2)[0])
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.Hello(cfg.Hostname) //nolint:errcheck
	c.Mail(from)          //nolint:errcheck
	for _, to := range toList {
		c.Rcpt(to) //nolint:errcheck
	}
	w, err := c.Data()
	if err != nil {
		return "", err
	}
	w.Write(raw) //nolint:errcheck
	w.Close()    //nolint:errcheck
	c.Quit()     //nolint:errcheck
	return generatedMsgID, nil
}


// ── setup endpoint ────────────────────────────────────────────────────────────

func registerSetup(mux *http.ServeMux, dataDir string) {
	mux.HandleFunc("/setup", func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "token required", http.StatusBadRequest)
			return
		}

		domain, localpart := "", ""
		for d, domCfg := range cfg.Domains {
			for lp := range domCfg.Accounts {
				tf := tokenFile(dataDir, d, lp)
				b, err := os.ReadFile(tf)
				if err == nil && strings.TrimSpace(string(b)) == token {
					domain, localpart = d, lp
				}
			}
		}
		if domain == "" {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, setupHTMLTemplate,
			localpart, domain, // heading
			localpart, domain, // done message
			localpart, domain, // EMAIL js const
			token,             // TOKEN js const
		)
	})
}

// setupHTMLTemplate: builds a cryptenv envelope client-side (Argon2id +
// AES-GCM + HKDF) and POSTs it to /auth/signup. Argon2id is provided by
// hash-wasm (~30KB), loaded from CDN.
//
// Format args: localpart, domain (for heading), localpart, domain (for HKDF
// info / display), token (for signup endpoint).
const setupHTMLTemplate = `<!DOCTYPE html><html><head><meta charset=utf-8>
<title>パスワード設定</title>
<style>body{font-family:sans-serif;max-width:400px;margin:80px auto;padding:0 16px}
input{width:100%%;box-sizing:border-box;padding:8px;margin:8px 0;font-size:16px}
button{padding:10px 20px;font-size:16px;cursor:pointer}
#err{color:red;display:none}
#done{display:none}</style></head>
<body><h2>%s@%s のパスワード設定</h2>
<form id=f>
<input id=pw1 type=password placeholder="新しいパスワード" required autofocus>
<input id=pw2 type=password placeholder="確認" required>
<button type=submit id=submit>設定する</button>
<p id=err></p>
</form>
<div id=done><h3>設定完了</h3><p>%s@%s でログインできます。</p></div>
<script type="module">
import { argon2id } from 'https://esm.sh/hash-wasm@4.11.0'

const EMAIL = '%s@%s'
const TOKEN = '%s'
const KDF = { t: 3, m: 64 * 1024, p: 4 }

function b64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
}
function rnd(n) { return crypto.getRandomValues(new Uint8Array(n)) }

async function hkdf(secret, info, len) {
  const key = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(info) },
    key, len * 8)
  return new Uint8Array(bits)
}

async function buildEnvelope(password) {
  const salt = rnd(16)
  const masterSecret = rnd(32)
  const wrapKeyBytes = await argon2id({
    password,
    salt,
    iterations: KDF.t,
    memorySize: KDF.m,
    parallelism: KDF.p,
    hashLength: 32,
    outputType: 'binary',
  })
  const wrapKey = await crypto.subtle.importKey('raw', wrapKeyBytes, 'AES-GCM', false, ['encrypt'])
  const nonce = rnd(12)
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce }, wrapKey, masterSecret))
  const wrapped = new Uint8Array(nonce.length + ct.length)
  wrapped.set(nonce, 0); wrapped.set(ct, nonce.length)

  const authToken = await hkdf(masterSecret, 'biset-jmapsmtp/auth/v1', 32)
  const authHash = new Uint8Array(await crypto.subtle.digest('SHA-256', authToken))

  return {
    v: 1,
    salt: b64(salt),
    kdf: KDF,
    wrapped_secret: b64(wrapped),
    auth_token_hash: b64(authHash),
  }
}

document.getElementById('f').addEventListener('submit', async e => {
  e.preventDefault()
  const errEl = document.getElementById('err')
  const submit = document.getElementById('submit')
  const p1 = document.getElementById('pw1').value
  const p2 = document.getElementById('pw2').value
  if (p1 !== p2) { errEl.textContent = 'パスワードが一致しません'; errEl.style.display = 'block'; return }
  if (p1.length < 8) { errEl.textContent = 'パスワードは 8 文字以上'; errEl.style.display = 'block'; return }
  errEl.style.display = 'none'
  submit.disabled = true; submit.textContent = '生成中…'
  try {
    const env = await buildEnvelope(p1)
    const resp = await fetch('/auth/signup?token=' + encodeURIComponent(TOKEN), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(env),
    })
    if (!resp.ok) {
      errEl.textContent = 'サーバエラー: ' + resp.status
      errEl.style.display = 'block'
      submit.disabled = false; submit.textContent = '設定する'
      return
    }
    document.getElementById('f').style.display = 'none'
    document.getElementById('done').style.display = 'block'
  } catch (err) {
    errEl.textContent = '生成失敗: ' + err.message
    errEl.style.display = 'block'
    submit.disabled = false; submit.textContent = '設定する'
  }
})
</script>
</body></html>`

// ── helpers ───────────────────────────────────────────────────────────────────

func newID() jmap.ID {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return jmap.ID(fmt.Sprintf("srv-%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b)))
}

// ── cleanup ───────────────────────────────────────────────────────────────────

func cleanupOrphanedData(dir string) {
	dataDir := filepath.Join(dir, "data")
	domainDirs, err := os.ReadDir(dataDir)
	if err != nil {
		return
	}
	for _, dd := range domainDirs {
		if !dd.IsDir() {
			continue
		}
		domain := dd.Name()
		domCfg, ok := cfg.Domains[domain]
		if !ok {
			os.RemoveAll(filepath.Join(dataDir, domain))
			log.Printf("cleanup: removed data/%s", domain)
			continue
		}
		entries, _ := os.ReadDir(filepath.Join(dataDir, domain))
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			localpart := e.Name()
			if localpart == "peers" {
				continue // reserved for Autocrypt peer key storage
			}
			if _, ok := domCfg.Accounts[localpart]; !ok {
				os.RemoveAll(filepath.Join(dataDir, domain, localpart))
				log.Printf("cleanup: removed data/%s/%s", domain, localpart)
			}
		}
	}
}

// ── entry point ───────────────────────────────────────────────────────────────

func main() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalf("dir: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("config: %v", err)
	}
	if len(cfg.Domains) == 0 {
		log.Fatalf("config: no domains defined")
	}

	loadPGPEntity()
	cleanupOrphanedData(dir)
	loadOrGenerateDKIMKeys(dir)

	dataDir := filepath.Join(dir, "data")

	cfg.AuthFunc = func(username, password string) (jmap.ID, bool) {
		parts := strings.SplitN(strings.ToLower(username), "@", 2)
		if len(parts) != 2 {
			return "", false
		}
		localpart, domain := parts[0], parts[1]
		domCfg, ok := cfg.Domains[domain]
		if !ok {
			return "", false
		}
		if _, ok := domCfg.Accounts[localpart]; !ok {
			return "", false
		}
		env := readEnvelope(dataDir, domain, localpart)
		if env == nil {
			return "", false
		}
		tok, err := decodeAuthToken(password)
		if err != nil {
			return "", false
		}
		if !env.VerifyAuth(tok) {
			return "", false
		}
		return jmap.ID(username), true
	}

	// Generate setup tokens for accounts with no envelope yet.
	for domain, domCfg := range cfg.Domains {
		for localpart := range domCfg.Accounts {
			if readEnvelope(dataDir, domain, localpart) != nil {
				continue
			}
			tf := tokenFile(dataDir, domain, localpart)
			token, _ := os.ReadFile(tf)
			if len(token) == 0 {
				t := generateToken()
				os.MkdirAll(filepath.Dir(tf), 0700) //nolint:errcheck
				os.WriteFile(tf, []byte(t), 0600)   //nolint:errcheck
				token = []byte(t)
			}
			log.Printf("[setup] %s@%s: %s/setup?token=%s", localpart, domain, cfg.BaseURL, string(token))
		}
	}

	// Build alias map and per-account stores
	aliases := map[string]string{}
	stores := map[string]*jmapserver.Store{}
	for domain, domCfg := range cfg.Domains {
		for localpart, acc := range domCfg.Accounts {
			primary := strings.ToLower(localpart) + "@" + domain
			aliases[primary] = primary
			for _, a := range acc.Alias {
				alias := strings.ToLower(a)
				if !strings.Contains(alias, "@") {
					alias = alias + "@" + domain
				}
				aliases[alias] = primary
			}

			store, err := jmapserver.NewStore(filepath.Join(dir, "data", domain, localpart))
			if err != nil {
				log.Fatalf("store %s: %v", primary, err)
			}
			store.PutMailboxes([]mailbox.Mailbox{defaultInbox(primary)}) //nolint:errcheck

			// Email/set create: put draft as pending for later submission
			store.OnCreateEmail(func(raw json.RawMessage) (email.Email, error) {
				var msg email.Email
				if err := json.Unmarshal(raw, &msg); err != nil {
					return email.Email{}, err
				}
				if msg.ID == "" {
					msg.ID = newID()
				}
				now := time.Now().UTC()
				msg.ReceivedAt = &now
				store.PutPending(msg)
				return msg, nil
			})

			// EmailSubmission/set: send via SMTP, store sent message encrypted with sender's key.
			senderLocalpart, senderDomain := localpart, domain
			store.OnSubmitEmail(func(msg email.Email, env emailsubmission.Envelope) error {
				if env.MailFrom == nil {
					builtEnv := jmapserver.BuildEnvelope(msg)
					if builtEnv == nil {
						return fmt.Errorf("no recipients")
					}
					env = *builtEnv
				}
				senderEntity := loadUserPubkeyEntity(dataDir, senderDomain, senderLocalpart)
				sentMsgID, err := sendEmail(msg, env, senderEntity, dataDir, senderDomain)
				if err != nil {
					return err
				}
				delete(msg.Keywords, "$draft")
				if sentMsgID != "" {
					msg.MessageID = []string{strings.Trim(sentMsgID, "<>")}
				}
				body := jmapserver.MessageBody(msg)
				if body != "" {
					if msg.Keywords == nil {
						msg.Keywords = map[string]bool{}
					}
					if strings.Contains(body, "-----BEGIN PGP MESSAGE-----") {
						// Already E2E encrypted by client (Layer 2). Store as-is.
						msg.Keywords["$e2e"] = true
					} else if entity := loadUserPubkeyEntity(dataDir, senderDomain, senderLocalpart); entity != nil {
						// Layer 1: encrypt Sent copy with sender's own pubkey only.
						if enc, err2 := pgpEncryptInline([]byte(body), entity); err2 == nil {
							if msg.BodyValues == nil {
								msg.BodyValues = map[string]*email.BodyValue{}
							}
							for _, part := range msg.TextBody {
								msg.BodyValues[part.PartID] = &email.BodyValue{Value: string(enc)}
							}
							msg.HTMLBody = nil
						}
					}
				}
				return store.Put(msg)
			})

			stores[primary] = store
		}
	}

	hub := jmapserver.NewHub()
	h := &handler{stores: stores, aliases: aliases, hub: hub}

	go startSMTP(hub, aliases, dataDir)

	mux := jmapserver.NewMux(cfg.Config, h, hub)
	registerWKD(mux, dataDir)
	registerSetup(mux, dataDir)
	registerAuthEnv(mux, dataDir)

	addr := cfg.ListenAddr
	if addr == "" {
		addr = "0.0.0.0:8765"
	}
	log.Printf("go-jmap-smtp: jmap listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
