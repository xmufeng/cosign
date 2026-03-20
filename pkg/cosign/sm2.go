package cosign

import (
	"crypto"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/tjfoc/gmsm/sm2"
)

const (
	SM2PrivateKeyPemType = "SM2 PRIVATE KEY"
	SM2PublicKeyPemType  = "SM2 PUBLIC KEY"
)

// SM2SignerVerifier is a wrapper around sm2.PrivateKey that implements signature.SignerVerifier interface.
type SM2SignerVerifier struct {
	priv *sm2.PrivateKey
	pub  *sm2.PublicKey
}

// PublicKey returns the public key that can be used to verify signatures created by this signer.
func (s *SM2SignerVerifier) PublicKey(opts ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return s.pub, nil
}

// SignMessage signs the provided message using SM2 with SM3 hash.
func (s *SM2SignerVerifier) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	if s.priv == nil {
		return nil, errors.New("SM2 private key not initialized")
	}

	// Read the message
	msg, err := io.ReadAll(message)
	if err != nil {
		return nil, fmt.Errorf("reading message: %w", err)
	}

	// Get signing options
	var signerOpts crypto.SignerOpts
	var randReader io.Reader = rand.Reader
	for _, opt := range opts {
		if r, ok := opt.(interface {
			ApplyRand(*io.Reader)
		}); ok {
			r.ApplyRand(&randReader)
		}
		if o, ok := opt.(interface {
			ApplyCryptoSignerOpts(*crypto.SignerOpts)
		}); ok {
			o.ApplyCryptoSignerOpts(&signerOpts)
		}
	}

	// SM2签名使用默认的用户ID（1234567812345678）
	return s.priv.Sign(randReader, msg, signerOpts)
}

// VerifySignature verifies the signature against the message using SM2 with SM3 hash.
func (s *SM2SignerVerifier) VerifySignature(sig, message io.Reader, opts ...signature.VerifyOption) error {
	if s.pub == nil {
		return errors.New("SM2 public key not initialized")
	}

	// Read the signature
	sigBytes, err := io.ReadAll(sig)
	if err != nil {
		return fmt.Errorf("reading signature: %w", err)
	}

	// Read the message
	msgBytes, err := io.ReadAll(message)
	if err != nil {
		return fmt.Errorf("reading message: %w", err)
	}

	// Verify the signature
	if !s.pub.Verify(msgBytes, sigBytes) {
		return errors.New("SM2 signature verification failed")
	}

	return nil
}

// GenerateSM2KeyPair generates an SM2 key pair and returns it as KeysBytes.
func GenerateSM2KeyPair(pf PassFunc) (*KeysBytes, error) {
	priv, err := GenerateSM2PrivateKey()
	if err != nil {
		return nil, err
	}
	// Emit SIGSTORE keys by default with SM2 type
	return marshalKeyPair(SM2PrivateKeyPemType, Keys{priv, priv.Public()}, pf)
}

// PemToSM2Key marshals and returns the PEM-encoded SM2 public key.
func PemToSM2Key(pemBytes []byte) (*sm2.PublicKey, error) {
	pub, err := cryptoutils.UnmarshalPEMToPublicKey(pemBytes)
	if err != nil {
		return nil, err
	}
	sm2Pub, ok := pub.(*sm2.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key: was %T, require *sm2.PublicKey", pub)
	}
	return sm2Pub, nil
}

// ParseSM2PrivateKey parses an SM2 private key from DER-encoded bytes.
// SM2 private key is typically stored as an ASN.1 INTEGER representing the private value D.
func ParseSM2PrivateKey(der []byte) (*sm2.PrivateKey, error) {
	// Try to parse as ASN.1 INTEGER
	var dBigInt big.Int
	rest, err := asn1.Unmarshal(der, &dBigInt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SM2 private key as ASN.1 INTEGER: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("trailing bytes after SM2 private key")
	}

	// Create SM2 private key
	priv := &sm2.PrivateKey{}
	priv.PublicKey.Curve = sm2.P256Sm2()
	priv.D = &dBigInt

	// Compute public key from private key
	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(dBigInt.Bytes())

	return priv, nil
}

// GenerateSM2PrivateKey generates an SM2 private key using P-256 curve (SM2 curve).
func GenerateSM2PrivateKey() (*sm2.PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

// MarshalSM2PrivateKey marshals an SM2 private key to DER-encoded bytes.
// SM2 private key is stored as an ASN.1 INTEGER representing the private value D.
func MarshalSM2PrivateKey(priv *sm2.PrivateKey) ([]byte, error) {
	if priv == nil || priv.D == nil {
		return nil, fmt.Errorf("invalid SM2 private key")
	}
	return asn1.Marshal(priv.D)
}

// NewSM2Verifier creates a new SM2SignerVerifier from a public key for verification only.
func NewSM2Verifier(pub *sm2.PublicKey) (*SM2SignerVerifier, error) {
	if pub == nil {
		return nil, errors.New("SM2 public key is nil")
	}
	return &SM2SignerVerifier{
		priv: nil,
		pub:  pub,
	}, nil
}

// LoadSM2Verifier loads an SM2 verifier from PEM-encoded public key.
func LoadSM2Verifier(pemBytes []byte) (*SM2SignerVerifier, error) {
	pub, err := PemToSM2Key(pemBytes)
	if err != nil {
		return nil, err
	}
	return NewSM2Verifier(pub)
}
