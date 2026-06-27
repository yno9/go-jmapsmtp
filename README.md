# go-jmapsmtp

JMAP mail server with SMTP relay. Bridges incoming SMTP and outgoing SMTP delivery to a JMAP API consumed by [biset](https://github.com/yno9/biset) or any JMAP client.

## Features

- JMAP Core + Mail + Submission (`urn:ietf:params:jmap:*`)
- Multi-account, multi-domain
- Incoming SMTP server (port 25)
- Outgoing SMTP delivery (MX lookup or fixed relay host)
- DKIM signing per domain
- Autocrypt key exchange (peer key storage and injection)
- PGP encryption at rest (Layer 1: server-side; Layer 2: client E2E via biset-ui)
- KEK-based auth: Argon2id + AES-GCM + HKDF (`cryptenv/`)
- WKD (Web Key Directory) for public key discovery
- Password setup flow via one-time token (`/setup?token=…`)

## Build

```sh
go build -o jmapsmtp .
```

## Config

Copy `config.example.json` to `config.json` next to the binary and edit:

```json
{
  "listen_addr": "0.0.0.0:8767",
  "base_url": "https://mail.example.com",
  "relayname": "jmap-smtp",
  "password": "changeme",
  "hostname": "mail.example.com",
  "smtp_port": 25,
  "relay_host": "",
  "domain": {
    "example.com": {
      "dkim_selector": "mail",
      "account": {
        "you": {
          "alias": ["alias@example.com"]
        }
      }
    }
  }
}
```

- `relay_host`: fixed SMTP relay (e.g. `smtp.sendgrid.net:587`). Empty = MX lookup.
- `dkim_selector`: DKIM selector. Keys are auto-generated in `data/<domain>/dkim.pem` on first run. Publish the public key as a DNS TXT record at `<selector>._domainkey.<domain>`.
- `password`: JMAP Basic Auth password for [biset](https://github.com/yno9/biset) relay connections.

## First run

On startup, accounts with no password envelope get a one-time setup token logged:

```
[setup] you@example.com: https://mail.example.com/setup?token=abc123
```

Open the URL to set a password (KEK envelope is built client-side in the browser).

## Data layout

```
data/
  <domain>/
    dkim.pem          DKIM private key
    peers/            Autocrypt peer public keys
    <localpart>/
      setup.token     one-time setup token (deleted after first login)
      envelope.json   KEK envelope (Argon2id-wrapped master secret)
      messages.json   JMAP email store
      …
```

## Dependencies

- [go-jmap](https://git.sr.ht/~rockorager/go-jmap) — JMAP types
- [go-jmapserver](https://github.com/yno9/go-jmapserver) — JMAP server library
- [go-smtp](https://github.com/emersion/go-smtp) — SMTP server
- [go-crypto](https://github.com/ProtonMail/go-crypto) — PGP
- [go-msgauth](https://github.com/emersion/go-msgauth) — DKIM
