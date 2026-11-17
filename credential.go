package iam

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
)

const (
	assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
	// assertionLifetime is well inside the five minutes IAM accepts.
	assertionLifetime = 60 * time.Second
)

// Credential is how a client proves its identity to IAM. IAM accepts exactly
// two methods, and each client is registered for one of them:
//
//   - client_secret_basic: ClientSecret or ClientSecretFunc
//   - private_key_jwt: PrivateKeyJWT or PrivateKeyJWTFunc
//
// The Func variants are asked for the current value on every request to IAM,
// so a secret or key can be replaced without restarting the process (to
// follow IAM's overlapping rotation). The SDK never writes credentials to
// disk, logs or error messages.
type Credential interface {
	// authenticate adds the client authentication to a request for an IAM
	// endpoint. It returns a fingerprint of the secret material that was
	// used, so that a later change of the material can be noticed.
	authenticate(ctx context.Context, clientID, audience string, form url.Values, header http.Header) (fingerprint string, err error)
	// fingerprint returns the fingerprint of the current secret material.
	// It also serves as the configuration check at construction time.
	fingerprint(ctx context.Context) (string, error)
}

// ClientSecret authenticates with a fixed client secret (client_secret_basic).
func ClientSecret(secret string) Credential {
	return &secretCredential{get: func(context.Context) (string, error) { return secret, nil }}
}

// ClientSecretFunc authenticates with the client secret returned by get
// (client_secret_basic). get is called for every request to IAM and should
// return quickly; it is where a secret manager or a reloaded file is read.
func ClientSecretFunc(get func(ctx context.Context) (string, error)) Credential {
	return &secretCredential{get: get}
}

type secretCredential struct {
	get func(context.Context) (string, error)
}

func (c *secretCredential) secret(ctx context.Context) (string, error) {
	if c.get == nil {
		return "", configError("Credential", "the client secret source is nil")
	}
	s, err := c.get(ctx)
	if err != nil {
		return "", configError("Credential", "the client secret source failed: "+err.Error())
	}
	if s == "" {
		return "", configError("Credential", "the client secret is empty")
	}
	return s, nil
}

func (c *secretCredential) fingerprint(ctx context.Context) (string, error) {
	s, err := c.secret(ctx)
	if err != nil {
		return "", err
	}
	return digest("secret", []byte(s)), nil
}

func (c *secretCredential) authenticate(ctx context.Context, clientID, _ string, _ url.Values, header http.Header) (string, error) {
	s, err := c.secret(ctx)
	if err != nil {
		return "", err
	}
	// RFC 6749 §2.3.1: both parts are form-encoded before Base64.
	raw := url.QueryEscape(clientID) + ":" + url.QueryEscape(s)
	header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(raw)))
	return digest("secret", []byte(s)), nil
}

// SigningKey is a private key together with the kid of the public key
// registered in IAM.
type SigningKey struct {
	// KeyID is the kid of the registered public key.
	KeyID string
	// Key signs the client assertions with RS256. It must be an RSA key of
	// at least 2048 bits: an *rsa.PrivateKey, or any crypto.Signer backed by
	// one (KMS, HSM).
	Key crypto.Signer
}

// PrivateKeyJWT authenticates with a signed client assertion
// (private_key_jwt, RFC 7523). A fresh assertion with a new jti is signed for
// every request to IAM.
func PrivateKeyJWT(kid string, key crypto.Signer) Credential {
	return &keyCredential{get: func(context.Context) (SigningKey, error) { return SigningKey{KeyID: kid, Key: key}, nil }}
}

// PrivateKeyJWTFunc is PrivateKeyJWT with a key that can change at run time.
// get is called for every request to IAM and returns the key to sign with
// and its kid; switch both together when rotating.
func PrivateKeyJWTFunc(get func(ctx context.Context) (SigningKey, error)) Credential {
	return &keyCredential{get: get}
}

type keyCredential struct {
	get func(context.Context) (SigningKey, error)
}

func (c *keyCredential) key(ctx context.Context) (SigningKey, *rsa.PublicKey, error) {
	if c.get == nil {
		return SigningKey{}, nil, configError("Credential", "the private key source is nil")
	}
	k, err := c.get(ctx)
	if err != nil {
		return SigningKey{}, nil, configError("Credential", "the private key source failed: "+err.Error())
	}
	if k.KeyID == "" {
		return SigningKey{}, nil, configError("Credential", "the kid of the registered public key is required")
	}
	if k.Key == nil {
		return SigningKey{}, nil, configError("Credential", "the private key is missing")
	}
	pub, ok := k.Key.Public().(*rsa.PublicKey)
	if !ok {
		return SigningKey{}, nil, configError("Credential", "the private key must be an RSA key (IAM only accepts RS256)")
	}
	if pub.N.BitLen() < minRSABits {
		return SigningKey{}, nil, configError("Credential", "the RSA key must have at least 2048 bits")
	}
	return k, pub, nil
}

func (c *keyCredential) fingerprint(ctx context.Context) (string, error) {
	k, pub, err := c.key(ctx)
	if err != nil {
		return "", err
	}
	return digest("key:"+k.KeyID, pub.N.Bytes()), nil
}

func (c *keyCredential) authenticate(ctx context.Context, clientID, audience string, form url.Values, _ http.Header) (string, error) {
	k, pub, err := c.key(ctx)
	if err != nil {
		return "", err
	}
	var signingKey any = k.Key
	if _, isRSA := k.Key.(*rsa.PrivateKey); !isRSA {
		signingKey = cryptosigner.Opaque(k.Key)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: signingKey},
		(&jose.SignerOptions{}).WithHeader(jose.HeaderKey("kid"), k.KeyID).WithType("JWT"))
	if err != nil {
		return "", configError("Credential", "the private key cannot sign with RS256")
	}
	jti, err := randomHex(16)
	if err != nil {
		return "", err
	}
	now := time.Now()
	payload, err := json.Marshal(map[string]any{
		"iss": clientID, "sub": clientID, "aud": audience,
		"iat": now.Unix(), "exp": now.Add(assertionLifetime).Unix(), "jti": jti,
	})
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("iam: signing the client assertion failed: %w", err)
	}
	assertion, err := jws.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("iam: signing the client assertion failed: %w", err)
	}
	form.Set("client_assertion_type", assertionType)
	form.Set("client_assertion", assertion)
	return digest("key:"+k.KeyID, pub.N.Bytes()), nil
}

// ParsePrivateKeyPEM parses a PEM encoded RSA private key (PKCS #1
// "RSA PRIVATE KEY" or PKCS #8 "PRIVATE KEY") for use with PrivateKeyJWT.
func ParsePrivateKeyPEM(data []byte) (crypto.Signer, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, errors.New("iam: no RSA private key found in the PEM data")
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.New("iam: the PKCS #1 private key cannot be parsed")
			}
			return key, nil
		case "PRIVATE KEY":
			parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, errors.New("iam: the PKCS #8 private key cannot be parsed")
			}
			key, ok := parsed.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("iam: the private key is not an RSA key")
			}
			return key, nil
		}
	}
}

// digest fingerprints secret material. Only a short prefix of the hash is
// kept, and it never leaves the process.
func digest(kind string, material []byte) string {
	sum := sha256.Sum256(material)
	return kind + ":" + hex.EncodeToString(sum[:8])
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("iam: reading random bytes failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("iam: reading random bytes failed: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
