package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// dirSizeMB returns the total size of a directory tree in megabytes.
func dirSizeMB(dir string) int {
	var total int64
	filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error { //nolint:errcheck
		if err == nil && !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return int(total / (1024 * 1024))
}

// lastActivity returns the most recent file modification time under dir.
func lastActivity(dir string) time.Time {
	var latest time.Time
	filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error { //nolint:errcheck
		if err == nil && !info.IsDir() {
			if t := info.ModTime(); t.After(latest) {
				latest = t
			}
		}
		return nil
	})
	return latest
}

// startMaintenance runs periodic tasks: inactive account purge.
func startMaintenance(h *handler, dataDir string) {
	if cfg.InactivePurgeDays <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(6 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			purgeInactiveAccounts(h, dataDir)
		}
	}()
}

func purgeInactiveAccounts(h *handler, dataDir string) {
	threshold := time.Duration(cfg.InactivePurgeDays) * 24 * time.Hour
	cutoff := time.Now().Add(-threshold)

	for domain, domCfg := range cfg.Domains {
		if !domCfg.AllowProvision {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(dataDir, domain))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			lp := e.Name()
			email := lp + "@" + domain

			// Never purge static accounts.
			if _, static := domCfg.Accounts[lp]; static {
				continue
			}

			acctDir := filepath.Join(dataDir, domain, lp)
			if lastActivity(acctDir).After(cutoff) {
				continue
			}
			// Also check peer relay dirs — only purge if all are inactive.
			peerActive := false
			for _, peer := range cfg.PeerDataDirs {
				if lastActivity(filepath.Join(peer, domain, lp)).After(cutoff) {
					peerActive = true
					break
				}
			}
			if peerActive {
				continue
			}

			log.Printf("[maintenance] purging inactive account %s (last active before %s)", email, cutoff.Format("2006-01-02"))

			h.mu.Lock()
			delete(h.stores, email)
			delete(h.dyn, email)
			// Remove all aliases pointing to this account.
			for alias, target := range h.aliases {
				if target == email || strings.EqualFold(alias, email) {
					delete(h.aliases, alias)
				}
			}
			h.mu.Unlock()

			if err := os.RemoveAll(acctDir); err != nil {
				log.Printf("[maintenance] failed to remove %s: %v", acctDir, err)
			}
		}
	}
}
