// Package db provides a persistent, zero-dependency credential store backed
// by a JSON file.  Thread-safe; deduplicates on username@domain.
package db

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Entry is one captured credential.
type Entry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"ts"`
	Protocol  string    `json:"protocol"`
	Source    string    `json:"source"`
	Username  string    `json:"username"`
	Domain    string    `json:"domain"`
	Version   string    `json:"version"` // NTLMv1, NTLMv2, CLEARTEXT, KRB5PA
	Hash      string    `json:"hash"`    // hashcat-ready string or cleartext password
}

// DB is a persistent credential store.
type DB struct {
	path    string
	mu      sync.Mutex
	entries []Entry
	seen    map[string]bool // key: lowercase "username@domain"
}

// Open loads (or creates) a DB at path.  A missing file is not an error; a
// corrupt file is, so that Add() can never silently overwrite existing
// captures with an empty list.
func Open(path string) (*DB, error) {
	d := &DB{path: path, seen: make(map[string]bool)}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if len(data) > 0 {
			if err := json.Unmarshal(data, &d.entries); err != nil {
				return nil, fmt.Errorf("credential DB %s is corrupt: %w", path, err)
			}
		}
		for _, e := range d.entries {
			d.seen[userKey(e.Username, e.Domain)] = true
		}
	case os.IsNotExist(err):
		// fresh DB
	default:
		return nil, err
	}
	return d, nil
}

// HasUser reports whether a credential for username@domain is already stored.
func (d *DB) HasUser(username, domain string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.seen[userKey(username, domain)]
}

// Add appends e to the DB and flushes to disk.
func (d *DB) Add(e Entry) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	e.ID = int64(len(d.entries) + 1)
	e.Timestamp = time.Now()
	d.entries = append(d.entries, e)
	d.seen[userKey(e.Username, e.Domain)] = true
	return d.flush()
}

// All returns a snapshot of all entries.
func (d *DB) All() []Entry {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]Entry, len(d.entries))
	copy(out, d.entries)
	return out
}

// Count returns the total number of stored entries.
func (d *DB) Count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.entries)
}

// UniqueUsers returns the number of distinct username@domain pairs stored.
func (d *DB) UniqueUsers() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}

func userKey(username, domain string) string {
	// NUL separator: "@" would let ("a@b","c") and ("a","b@c") collide.
	return strings.ToLower(username) + "\x00" + strings.ToLower(domain)
}

func (d *DB) flush() error {
	data, err := json.MarshalIndent(d.entries, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(d.path, data, 0600)
}
