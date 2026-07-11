package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/smtp"
	stdmail "net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	DKIMSelector   string                   `json:"dkim_selector"`
	Accounts       map[string]AccountConfig `json:"account"`
	AllowProvision bool                     `json:"allow_provision"`
}

type Config struct {
	jmapserver.Config
	Hostname    string                  `json:"hostname"`
	SMTPPort    int                     `json:"smtp_port"`
	RelayHost   string                  `json:"relay_host"`
	Domains     map[string]DomainConfig `json:"domain"`
	TLSCertFile string                  `json:"smtp_tls_cert"`
	TLSKeyFile  string                  `json:"smtp_tls_key"`
	RelayLabel  string                  `json:"relay_label"`
	RelayColor  string                  `json:"relay_color"`
	// AnchorURL points at the domain's identity anchor (the apex / jmapap) whose
	// name-claim registry prevents an address from being split across relays.
	// Empty = no anchor (single-relay mode); provisioning proceeds unguarded.
	AnchorURL string `json:"anchor_url"`
	// ReplyOnlyOutbound, when true, blocks outbound mail unless every recipient
	// address has previously sent a message to the sender (i.e. appears as From
	// in the sender's inbox). Prevents spam abuse on open-registration domains.
	ReplyOnlyOutbound bool     `json:"reply_only_outbound"`
	// ReplyOnlyExempt lists domains (e.g. "biset.md") and addresses
	// (e.g. "y@t.biset.md") whose senders bypass the reply_only_outbound check.
	ReplyOnlyExempt   []string `json:"reply_only_exempt"`
	// MaxAccountStorageMB limits per-account disk usage (messages + data).
	// 0 = unlimited.
	MaxAccountStorageMB int `json:"max_account_storage_mb"`
	// InactivePurgeDays removes accounts on allow_provision domains that have
	// had no send/receive activity for this many days. 0 = disabled.
	InactivePurgeDays int `json:"inactive_purge_days"`
	// PeerDataDirs lists sibling relay data directories to check for activity
	// before purging. An account is only purged if all peers are also inactive.
	PeerDataDirs []string `json:"peer_data_dirs"`
}

// registerRelayInfo advertises this relay's display label/color so the biset
// client can tag conversations without hardcoding per-relay knowledge.
func registerRelayInfo(mux *http.ServeMux, label, color string) {
	mux.HandleFunc("/relay-info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"label": label, "color": color}) //nolint:errcheck
	})
}

var cfg Config

// version is overridable at build time: -ldflags "-X main.version=$(git rev-parse --short HEAD)".
var version = "dev"

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
	mu      sync.RWMutex
	stores  map[string]*jmapserver.Store
	aliases map[string]string
	hub     *jmapserver.Hub
	dyn     map[string]bool // dynamically provisioned accounts
}

func (h *handler) Capabilities() []jmap.URI {
	return []jmap.URI{
		"urn:ietf:params:jmap:mail",
		"urn:ietf:params:jmap:submission",
	}
}

func (h *handler) Accounts() []jmapserver.Account {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []jmapserver.Account
	for domain, domCfg := range cfg.Domains {
		for localpart := range domCfg.Accounts {
			addr := localpart + "@" + domain
			out = append(out, jmapserver.Account{ID: jmap.ID(addr), Name: addr})
		}
	}
	for email := range h.dyn {
		out = append(out, jmapserver.Account{ID: jmap.ID(email), Name: email})
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
	h.mu.RLock()
	store, ok := h.stores[string(base.AccountID)]
	h.mu.RUnlock()
	if !ok {
		return nil, "", fmt.Errorf("accountNotFound: %s", base.AccountID)
	}
	return store, base.AccountID, nil
}

// makeStore creates and configures a JMAP store for one account.
func makeStore(localpart, domain, dataDir string, hub *jmapserver.Hub) (*jmapserver.Store, error) {
	primary := localpart + "@" + domain
	store, err := jmapserver.NewStore(filepath.Join(dataDir, domain, localpart))
	if err != nil {
		return nil, err
	}
	store.PutMailboxes([]mailbox.Mailbox{defaultInbox(primary)}) //nolint:errcheck

	store.OnCreateEmail(func(raw json.RawMessage) (email.Email, error) {
		if cfg.MaxAccountStorageMB > 0 {
			if used := dirSizeMB(filepath.Join(dataDir, domain, localpart)); used >= cfg.MaxAccountStorageMB {
				return email.Email{}, fmt.Errorf("storage limit reached (%dMB)", cfg.MaxAccountStorageMB)
			}
		}
		var msg email.Email
		if err := json.Unmarshal(raw, &msg); err != nil {
			return email.Email{}, err
		}
		// Parse JMAP header:X-Foo:asText properties into msg.Headers
		var extra map[string]json.RawMessage
		if err := json.Unmarshal(raw, &extra); err == nil {
			for key, val := range extra {
				if strings.HasPrefix(key, "header:") && strings.HasSuffix(key, ":asText") {
					name := key[len("header:") : len(key)-len(":asText")]
					var s string
					if json.Unmarshal(val, &s) == nil {
						s = strings.TrimSpace(s)
						if s != "" {
							msg.Headers = append(msg.Headers, &email.Header{Name: name, Value: s})
						}
					}
				}
			}
		}
		if msg.ID == "" {
			msg.ID = newID()
		}
		// Pre-assign RFC Message-ID so biset can use it as In-Reply-To immediately.
		if len(msg.MessageID) == 0 || msg.MessageID[0] == "" {
			rnd := make([]byte, 6)
			rand.Read(rnd) //nolint:errcheck
			msgID := fmt.Sprintf("%d.%s@%s", time.Now().UnixNano(), hex.EncodeToString(rnd), domain)
			msg.MessageID = []string{msgID}
		}
		now := time.Now().UTC()
		msg.ReceivedAt = &now
		store.PutPending(msg)
		return msg, nil
	})

	store.OnSubmitEmail(func(msg email.Email, env emailsubmission.Envelope) error {
		if cfg.MaxAccountStorageMB > 0 {
			if used := dirSizeMB(filepath.Join(dataDir, domain, localpart)); used >= cfg.MaxAccountStorageMB {
				return fmt.Errorf("storage limit reached (%dMB)", cfg.MaxAccountStorageMB)
			}
		}
		if env.MailFrom == nil {
			builtEnv := jmapserver.BuildEnvelope(msg)
			if builtEnv == nil {
				return fmt.Errorf("no recipients")
			}
			env = *builtEnv
		}
		if cfg.ReplyOnlyOutbound && !replyOnlyExempt(localpart+"@"+domain) {
			// Build set of addresses that have ever sent to this account.
			known := make(map[string]bool)
			for _, m := range store.All() {
				for _, addr := range m.From {
					if addr.Email != "" {
						known[strings.ToLower(addr.Email)] = true
					}
				}
			}
			for _, rcpt := range env.RcptTo {
				if !known[strings.ToLower(rcpt.Email)] {
					return fmt.Errorf("reply_only_outbound: %s has not sent you a message", rcpt.Email)
				}
			}
		}
		delete(msg.Keywords, "$draft")
		smtpMsg := msg
		body := jmapserver.MessageBody(msg)
		if body != "" {
			if msg.Keywords == nil {
				msg.Keywords = map[string]bool{}
			}
			if strings.Contains(body, "-----BEGIN PGP MESSAGE-----") {
				msg.Keywords["$e2e"] = true
			} else if entity := loadUserPubkeyEntity(dataDir, domain, localpart); entity != nil {
				if enc, err2 := pgpEncryptInline([]byte(body), entity); err2 == nil {
					storedValues := make(map[string]*email.BodyValue, len(msg.BodyValues))
					for k, v := range msg.BodyValues {
						bv := *v
						storedValues[k] = &bv
					}
					for _, part := range msg.TextBody {
						storedValues[part.PartID] = &email.BodyValue{Value: string(enc)}
					}
					msg.BodyValues = storedValues
					msg.HTMLBody = nil
				}
			}
		}
		if err := store.Put(msg); err != nil {
			return err
		}
		hub.Notify()
		senderEntity := loadUserPubkeyEntity(dataDir, domain, localpart)
		go func() {
			sentMsgID, err := sendEmail(smtpMsg, env, senderEntity, dataDir, domain)
			if err != nil {
				smtpOutbound.WithLabelValues("failed").Inc()
				log.Printf("[smtp] send failed: %v", err)
				return
			}
			smtpOutbound.WithLabelValues("sent").Inc()
			if sentMsgID != "" {
				msg.MessageID = []string{strings.Trim(sentMsgID, "<>")}
				store.Put(msg) //nolint:errcheck
				hub.Notify()
			}
		}()
		return nil
	})

	return store, nil
}

// addDynAccount registers a dynamically provisioned account into the running server.
func (h *handler) addDynAccount(localpart, domain, dataDir string) {
	email := localpart + "@" + domain
	store, err := makeStore(localpart, domain, dataDir, h.hub)
	if err != nil {
		log.Printf("[provision] store error for %s: %v", email, err)
		return
	}
	h.mu.Lock()
	h.stores[email] = store
	h.aliases[email] = email
	h.dyn[email] = true
	h.mu.Unlock()
	log.Printf("[provision] registered account %s", email)
}

// scanDynAccounts loads dynamic accounts from disk (for restart recovery).
func scanDynAccounts(h *handler, dataDir string) {
	domain := primaryDomain()
	entries, err := os.ReadDir(filepath.Join(dataDir, domain))
	if err != nil {
		return
	}
	staticAccts := map[string]bool{}
	if domCfg, ok := cfg.Domains[domain]; ok {
		for lp := range domCfg.Accounts {
			staticAccts[lp] = true
		}
	}
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "peers" || staticAccts[e.Name()] {
			continue
		}
		if readEnvelope(dataDir, domain, e.Name()) != nil {
			h.addDynAccount(e.Name(), domain, dataDir)
		}
	}
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
	h       *handler
	dataDir string
}

func (b *backend) NewSession(_ *gosmtp.Conn) (gosmtp.Session, error) {
	return &session{h: b.h, dataDir: b.dataDir}, nil
}

type session struct {
	h       *handler
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
	s.h.mu.RLock()
	_, ok := s.h.aliases[addr]
	s.h.mu.RUnlock()
	if ok {
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
					s.h.mu.RLock()
					primary := s.h.aliases[rcpt]
					s.h.mu.RUnlock()
					if domain := strings.SplitN(primary, "@", 2); len(domain) == 2 {
						storePeerKey(s.dataDir, domain[1], addr, keydata)
						break
					}
				}
			}
		}
	}

	delivered := map[string]bool{}
	for _, rcpt := range s.to {
		s.h.mu.RLock()
		primary := s.h.aliases[rcpt]
		s.h.mu.RUnlock()
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
	s.h.hub.Notify()
	return nil
}

func (s *session) Reset()        { s.from = ""; s.to = nil }
func (s *session) Logout() error { return nil }

func startSMTP(h *handler, dataDir string) {
	port := cfg.SMTPPort
	if port == 0 {
		port = 25
	}
	srv := gosmtp.NewServer(&backend{h: h, dataDir: dataDir})
	srv.Addr = fmt.Sprintf(":%d", port)
	srv.Domain = cfg.Hostname
	srv.AllowInsecureAuth = true
	srv.EnableSMTPUTF8 = true
	// Advertise STARTTLS so TLS-requiring senders (e.g. chatmail) can deliver.
	if tlsCfg := loadInboundTLS(dataDir); tlsCfg != nil {
		srv.TLSConfig = tlsCfg
		log.Printf("[smtp] STARTTLS enabled")
	} else {
		log.Printf("[smtp] STARTTLS disabled (no cert)")
	}
	log.Printf("[smtp] listening on %s", srv.Addr)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("smtp: %v", err)
	}
}

// loadInboundTLS builds the TLS config for inbound SMTP STARTTLS.
//
// If smtp_tls_cert / smtp_tls_key are set in config (e.g. pointing at a
// Caddy-managed Let's Encrypt cert), those are used via a GetCertificate
// callback that re-reads the files so external renewals are picked up without
// a restart. Otherwise a self-signed cert is generated (sufficient for
// opportunistic TLS like chatmail's "encrypt" level).
func loadInboundTLS(dataDir string) *tls.Config {
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		// Verify the pair loads once at startup.
		if _, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil {
			log.Printf("[smtp] configured cert load failed (%v); falling back to self-signed", err)
		} else {
			ldr := &certReloader{certPath: cfg.TLSCertFile, keyPath: cfg.TLSKeyFile}
			log.Printf("[smtp] using managed cert %s", cfg.TLSCertFile)
			return &tls.Config{GetCertificate: ldr.get}
		}
	}

	certPath := dataDir + "/smtp-tls-cert.pem"
	keyPath := dataDir + "/smtp-tls-key.pem"
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		if genErr := generateSelfSignedCert(certPath, keyPath); genErr != nil {
			log.Printf("[smtp] cert generation failed: %v", genErr)
			return nil
		}
		cert, err = tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			log.Printf("[smtp] cert load failed after generation: %v", err)
			return nil
		}
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

// certReloader re-reads a cert/key pair from disk, caching by file modtime so
// renewals (e.g. by Caddy) are picked up automatically without a restart.
type certReloader struct {
	certPath, keyPath string
	mu                sync.Mutex
	cached            *tls.Certificate
	modTime           time.Time
}

func (r *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fi, err := os.Stat(r.certPath)
	if err == nil && r.cached != nil && fi.ModTime().Equal(r.modTime) {
		return r.cached, nil
	}
	cert, err := tls.LoadX509KeyPair(r.certPath, r.keyPath)
	if err != nil {
		if r.cached != nil {
			return r.cached, nil // serve stale rather than fail the handshake
		}
		return nil, err
	}
	r.cached = &cert
	if fi != nil {
		r.modTime = fi.ModTime()
	}
	return r.cached, nil
}

func generateSelfSignedCert(certPath, keyPath string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cfg.Hostname},
		DNSNames:     []string{cfg.Hostname},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return err
	}
	certOut, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer keyOut.Close()
	return pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
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

	if cfg.RelayHost != "" {
		// Relay mode: send all recipients in one connection.
		if err := smtpSend(cfg.RelayHost, from, toList, raw); err != nil {
			return "", err
		}
		return generatedMsgID, nil
	}

	// Direct mode: group recipients by domain and open one SMTP connection per MX.
	byDomain := map[string][]string{}
	for _, to := range toList {
		parts := strings.SplitN(to, "@", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid recipient address: %q", to)
		}
		byDomain[parts[1]] = append(byDomain[parts[1]], to)
	}
	var firstErr error
	for domain, addrs := range byDomain {
		mxs, err := net.LookupMX(domain)
		if err != nil || len(mxs) == 0 {
			e := fmt.Errorf("no MX for %s", domain)
			log.Printf("[smtp] send failed: %v", e)
			if firstErr == nil {
				firstErr = e
			}
			continue
		}
		target := strings.TrimSuffix(mxs[0].Host, ".") + ":25"
		if err := smtpSend(target, from, addrs, raw); err != nil {
			log.Printf("[smtp] send failed to %s: %v", domain, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	if firstErr != nil {
		return "", firstErr
	}
	return generatedMsgID, nil
}

func smtpSend(target, from string, to []string, raw []byte) error {
	log.Printf("[smtp] connecting to %s for %v", target, to)
	conn, err := net.DialTimeout("tcp", target, 30*time.Second)
	if err != nil {
		return fmt.Errorf("dial %s: %w", target, err)
	}
	c, err := smtp.NewClient(conn, strings.SplitN(target, ":", 2)[0])
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello(cfg.Hostname); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		cfg2 := &tls.Config{ServerName: strings.SplitN(target, ":", 2)[0]}
		if err := c.StartTLS(cfg2); err != nil {
			log.Printf("[smtp] STARTTLS failed for %s: %v (continuing plaintext)", target, err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			log.Printf("[smtp] RCPT TO %s rejected: %v", addr, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(raw); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("end DATA: %w", err)
	}
	c.Quit() //nolint:errcheck
	log.Printf("[smtp] sent to %v via %s", to, target)
	return nil
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
				// Skip dynamic accounts (they have an envelope.json but no static config entry).
				if readEnvelope(filepath.Join(dir, "data"), domain, localpart) != nil {
					continue
				}
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

	// Create handler early so AuthFunc can reference it.
	h := &handler{
		stores:  map[string]*jmapserver.Store{},
		aliases: map[string]string{},
		hub:     jmapserver.NewHub(),
		dyn:     map[string]bool{},
	}
	h.hub.SetPersistDir(dataDir)

	cfg.AuthFunc = func(username, password string) (jmap.ID, bool) {
		parts := strings.SplitN(strings.ToLower(username), "@", 2)
		if len(parts) != 2 {
			return "", false
		}
		localpart, domain := parts[0], parts[1]

		// Accept if in static config or dynamic accounts.
		staticOK := false
		if domCfg, ok := cfg.Domains[domain]; ok {
			if _, ok := domCfg.Accounts[localpart]; ok {
				staticOK = true
			}
		}
		if !staticOK {
			h.mu.RLock()
			_, dynOK := h.dyn[username]
			h.mu.RUnlock()
			if !dynOK {
				return "", false
			}
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

	// Build alias map and per-account stores.
	for domain, domCfg := range cfg.Domains {
		for localpart, acc := range domCfg.Accounts {
			primary := strings.ToLower(localpart) + "@" + domain
			h.aliases[primary] = primary
			for _, a := range acc.Alias {
				alias := strings.ToLower(a)
				if !strings.Contains(alias, "@") {
					alias = alias + "@" + domain
				}
				h.aliases[alias] = primary
			}
			store, err := makeStore(localpart, domain, dataDir, h.hub)
			if err != nil {
				log.Fatalf("store %s: %v", primary, err)
			}
			h.stores[primary] = store
		}
	}

	// Recover dynamic accounts from previous runs.
	scanDynAccounts(h, dataDir)

	// Push existing accounts' fingerprints to the identity anchor (best-effort,
	// off the startup path); logs any pre-existing split it detects.
	go backfillAnchorPush(h, dataDir)
	startMaintenance(h, dataDir)

	go startSMTP(h, dataDir)

	mux := jmapserver.NewMux(cfg.Config, h, h.hub)
	registerWKD(mux, dataDir)
	registerSetup(mux, dataDir)
	registerAuthEnv(mux, dataDir)
	registerProvision(mux, h, dataDir)
	{
		label, color := cfg.RelayLabel, cfg.RelayColor
		if label == "" {
			label = "Mail"
		}
		if color == "" {
			color = "#64748b"
		}
		registerRelayInfo(mux, label, color)
	}
	jmapserver.RegisterMetrics(mux, jmapserver.MetricsOptions{
		DataDir:    dataDir,
		RelayLabel: cfg.RelayLabel,
		Version:    version,
		Token:      os.Getenv("METRICS_TOKEN"),
	}, relayCollectors()...)

	addr := cfg.ListenAddr
	if addr == "" {
		addr = "0.0.0.0:8765"
	}
	log.Printf("go-jmap-smtp: jmap listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
