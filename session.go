package iam

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"time"
)

// SessionStore keeps the server-side state of the built-in local session:
// the sessions themselves and the one-time state of sign-ins in progress.
// Values are opaque: the SDK encrypts them with the session key before they
// reach the store, and the keys carry no meaning.
//
// The default store lives in the memory of one process. An application that
// runs several instances supplies a shared store. Its CompareAndSwap must be
// atomic across instances: the SDK relies on it to let only one instance
// redeem a session's refresh token, because IAM revokes the whole chain when
// a rotated refresh token is presented twice.
type SessionStore interface {
	// Get returns the value stored under key, or nil when there is none or
	// it has expired.
	Get(ctx context.Context, key string) ([]byte, error)
	// Set stores value under key for ttl, replacing any previous value.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Delete removes key. Deleting a missing key is not an error.
	Delete(ctx context.Context, key string) error
	// CompareAndSwap stores value under key for ttl only if the current
	// value equals old, and reports whether it did.
	CompareAndSwap(ctx context.Context, key string, old, value []byte, ttl time.Duration) (bool, error)
}

const (
	sessionKeyPrefix = "iam-go-sdk:session:"
	pendingKeyPrefix = "iam-go-sdk:login:"
	memoryStoreLimit = 100000
)

// memoryStore is the default SessionStore: a map in process memory.
type memoryStore struct {
	mu        sync.Mutex
	items     map[string]memoryItem
	now       func() time.Time
	lastSweep time.Time
}

type memoryItem struct {
	value   []byte
	expires time.Time
}

func newMemoryStore() *memoryStore {
	return &memoryStore{items: map[string]memoryItem{}, now: time.Now}
}

func (s *memoryStore) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(key), nil
}

func (s *memoryStore) getLocked(key string) []byte {
	item, ok := s.items[key]
	if !ok {
		return nil
	}
	if !s.now().Before(item.expires) {
		delete(s.items, key)
		return nil
	}
	return item.value
}

func (s *memoryStore) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setLocked(key, value, ttl)
	return nil
}

func (s *memoryStore) setLocked(key string, value []byte, ttl time.Duration) {
	now := s.now()
	if len(s.items) >= memoryStoreLimit || now.Sub(s.lastSweep) > time.Minute {
		s.sweepLocked(now)
	}
	s.items[key] = memoryItem{value: bytes.Clone(value), expires: now.Add(ttl)}
}

// sweepLocked removes expired items. If the store is still full it drops
// the items that expire soonest: those are sign-ins in progress, which are
// short-lived and can simply be started again, before any session.
func (s *memoryStore) sweepLocked(now time.Time) {
	s.lastSweep = now
	for k, item := range s.items {
		if !now.Before(item.expires) {
			delete(s.items, k)
		}
	}
	for len(s.items) >= memoryStoreLimit {
		cutoff := now.Add(pendingLoginTTL)
		removed := 0
		for k, item := range s.items {
			if item.expires.Before(cutoff) {
				delete(s.items, k)
				removed++
			}
		}
		if removed == 0 {
			// Only sessions are left: drop an arbitrary tenth.
			n := len(s.items) / 10
			for k := range s.items {
				if n--; n < 0 {
					break
				}
				delete(s.items, k)
			}
		}
	}
}

func (s *memoryStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, key)
	return nil
}

func (s *memoryStore) CompareAndSwap(_ context.Context, key string, old, value []byte, ttl time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !bytes.Equal(s.getLocked(key), old) || old == nil {
		return false, nil
	}
	s.setLocked(key, value, ttl)
	return true, nil
}

// sealer protects the local session with the session keys: it signs cookie
// values and encrypts what goes into the store. The first key is used for
// new data; every key is accepted for existing data, which allows the key
// to be replaced without ending sessions.
type sealer struct {
	keys func(context.Context) ([][]byte, error)

	mu      sync.Mutex
	derived map[string][]byte
}

func (s *sealer) current(ctx context.Context) ([][]byte, error) {
	if s.keys == nil {
		return nil, configError("SessionKey", "is required to use the built-in local session")
	}
	keys, err := s.keys(ctx)
	if err != nil {
		return nil, configError("SessionKey", "the session key source failed: "+err.Error())
	}
	if len(keys) == 0 {
		return nil, configError("SessionKey", "is required to use the built-in local session")
	}
	for _, k := range keys {
		if len(k) < minSessionKeyLen {
			return nil, configError("SessionKey", "must be at least 32 bytes of high entropy")
		}
	}
	return keys, nil
}

// derive returns the 32-byte key for one purpose, derived from a session key.
func (s *sealer) derive(key []byte, purpose string) ([]byte, error) {
	id := purpose + "\x00" + string(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.derived[id]; ok {
		return d, nil
	}
	d, err := hkdf.Key(sha256.New, key, nil, "iam-go-sdk/v1/"+purpose, 32)
	if err != nil {
		return nil, err
	}
	if s.derived == nil || len(s.derived) > 16 {
		s.derived = map[string][]byte{}
	}
	s.derived[id] = d
	return d, nil
}

// seal encrypts plaintext for the given store key (AES-256-GCM, the store
// key is authenticated so that a value cannot be moved to another key).
func (s *sealer) seal(ctx context.Context, storeKey string, plaintext []byte) ([]byte, error) {
	keys, err := s.current(ctx)
	if err != nil {
		return nil, err
	}
	aead, err := s.aead(keys[0])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, []byte(storeKey)), nil
}

func (s *sealer) open(ctx context.Context, storeKey string, sealed []byte) ([]byte, error) {
	keys, err := s.current(ctx)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		aead, err := s.aead(key)
		if err != nil {
			return nil, err
		}
		if len(sealed) < aead.NonceSize() {
			break
		}
		if plain, err := aead.Open(nil, sealed[:aead.NonceSize()], sealed[aead.NonceSize():], []byte(storeKey)); err == nil {
			return plain, nil
		}
	}
	return nil, errors.New("iam: stored session data cannot be decrypted with the session key")
}

func (s *sealer) aead(key []byte) (cipher.AEAD, error) {
	derived, err := s.derive(key, "store")
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sign returns the cookie value for id: the id and a MAC over the cookie
// name and the id.
func (s *sealer) sign(ctx context.Context, name, id string) (string, error) {
	keys, err := s.current(ctx)
	if err != nil {
		return "", err
	}
	mac, err := s.mac(keys[0], name, id)
	if err != nil {
		return "", err
	}
	return id + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

// verify returns the id of a cookie value if its MAC is genuine.
func (s *sealer) verify(ctx context.Context, name, value string) (string, bool) {
	id, sig, ok := strings.Cut(value, ".")
	if !ok || id == "" {
		return "", false
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil {
		return "", false
	}
	keys, err := s.current(ctx)
	if err != nil {
		return "", false
	}
	for _, key := range keys {
		if want, err := s.mac(key, name, id); err == nil && hmac.Equal(got, want) {
			return id, true
		}
	}
	return "", false
}

func (s *sealer) mac(key []byte, name, id string) ([]byte, error) {
	derived, err := s.derive(key, "cookie")
	if err != nil {
		return nil, err
	}
	h := hmac.New(sha256.New, derived)
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write([]byte(id))
	return h.Sum(nil), nil
}

// keyedMutex serialises work per key within this process.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

type keyedLock struct {
	mu   sync.Mutex
	refs int
}

// lock acquires the mutex of key and returns the function that releases it.
func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*keyedLock{}
	}
	l := k.locks[key]
	if l == nil {
		l = &keyedLock{}
		k.locks[key] = l
	}
	l.refs++
	k.mu.Unlock()
	l.mu.Lock()
	return func() {
		l.mu.Unlock()
		k.mu.Lock()
		if l.refs--; l.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}

func secondsDuration(seconds int64) time.Duration { return time.Duration(seconds) * time.Second }
