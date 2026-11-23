// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

// #include <openssl/evp.h>
// #include <openssl/rsa.h>
// #include <openssl/pem.h>
// #include <openssl/x509v3.h>
import "C"

import (
	"crypto"
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"unsafe"
)

var (
	ErrEmptyBlock = errors.New("empty block")
	ErrLoadingKey = errors.New("failed loading private key")
	// pkeySerialize serialises finaliser-driven EVP_PKEY_CTX frees against
	// in-flight key generation. Freeing an EVP_PKEY_CTX from the GC's
	// finaliser thread while another goroutine is inside EVP_PKEY_generate
	// corrupts the provider dispatch (observed as jumps through destroyed
	// dispatch tables / SIGSEGV and as key material corruption), so frees and
	// generates must not overlap.
	pkeySerialize sync.Mutex
)

type KeyType int

// Constants for the various key types.
const (
	KeyTypeNone     KeyType = C.EVP_PKEY_NONE
	KeyTypeRSA      KeyType = C.EVP_PKEY_RSA
	KeyTypeRSA2     KeyType = C.EVP_PKEY_RSA2
	KeyTypeRSAPSS   KeyType = C.EVP_PKEY_RSA_PSS
	KeyTypeDSA      KeyType = C.EVP_PKEY_DSA
	KeyTypeDSA1     KeyType = C.EVP_PKEY_DSA1
	KeyTypeDSA2     KeyType = C.EVP_PKEY_DSA2
	KeyTypeDSA3     KeyType = C.EVP_PKEY_DSA3
	KeyTypeDSA4     KeyType = C.EVP_PKEY_DSA4
	KeyTypeDH       KeyType = C.EVP_PKEY_DH
	KeyTypeDHX      KeyType = C.EVP_PKEY_DHX
	KeyTypeEC       KeyType = C.EVP_PKEY_EC
	KeyTypeSM2      KeyType = C.EVP_PKEY_SM2
	KeyTypeHMAC     KeyType = C.EVP_PKEY_HMAC
	KeyTypeCMAC     KeyType = C.EVP_PKEY_CMAC
	KeyTypeScrypt   KeyType = C.EVP_PKEY_SCRYPT
	KeyTypeTLS1PRF  KeyType = C.EVP_PKEY_TLS1_PRF
	KeyTypeHKDF     KeyType = C.EVP_PKEY_HKDF
	KeyTypePoly1305 KeyType = C.EVP_PKEY_POLY1305
	KeyTypeSIPHash  KeyType = C.EVP_PKEY_SIPHASH
	KeyTypeX25519   KeyType = C.EVP_PKEY_X25519
	KeyTypeED25519  KeyType = C.EVP_PKEY_ED25519
	KeyTypeX448     KeyType = C.EVP_PKEY_X448
	KeyTypeED448    KeyType = C.EVP_PKEY_ED448
)

// Note: Sign and Verify functions assume pre-signed data, if you want to sign and verify raw data, use the WithDigest functions.
type PublicKey interface {
	// Verify and VerifyWithDigest verify a signature without and with given digest (PCKS v1.5 for now only)
	Verify(digest, sig []byte, opts crypto.SignerOpts) error
	VerifyWithDigest(digest *Digest, data, sig []byte) error

	// MarshalPKIXPublicKeyPEM converts the public key to PEM-encoded PKIX format
	MarshalPKIXPublicKeyPEM() (pemBlock []byte, err error)

	// MarshalPKIXPublicKeyDER converts the public key to DER-encoded PKIX format
	MarshalPKIXPublicKeyDER() (derBlock []byte, err error)

	// KeyType returns an identifier for what kind of key is represented by this object.
	KeyType() KeyType

	// BaseType returns an identifier for what kind of key is represented
	// by this object.
	// Keys that share same algorithm but use different legacy formats
	// will have the same BaseType.
	//
	// For example, a key with a `KeyType() == KeyTypeRSA` and a key with a
	// `KeyType() == KeyTypeRSA2` would both have `BaseType() == KeyTypeRSA`.
	BaseType() NID

	// Equal compares the key with the passed in key.
	Equal(key PublicKey) bool

	// Size returns the size (in bytes) of signatures created with this key.
	Size() int

	evpPKey() *C.EVP_PKEY
}

type PrivateKey interface {
	PublicKey
	Public() crypto.PublicKey

	// Sign and SignWithDigest signs the data using PKCS1.15 (for now)
	Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error)
	SignWithDigest(digest *Digest, data []byte) (signature []byte, err error)

	// MarshalPKCS1PrivateKeyPEM converts the private key to PEM-encoded PKCS1 format
	MarshalPKCS1PrivateKeyPEM() (pemBlock []byte, err error)

	// MarshalPKCS1PrivateKeyDER converts the private key to DER-encoded PKCS1 format
	MarshalPKCS1PrivateKeyDER() (derBlock []byte, err error)
}

type pKey struct {
	key *C.EVP_PKEY
}

func pKeyFromKey(key *C.EVP_PKEY) *pKey {
	pkey := &pKey{key: key}
	runtime.SetFinalizer(pkey, func(p *pKey) {
		pkeySerialize.Lock()
		C.EVP_PKEY_free(p.key)
		pkeySerialize.Unlock()
	})
	return pkey
}

// Public returns the public key corresponding to the private key.
// TODO: add testcases
func (key *pKey) Public() crypto.PublicKey {
	der, err := key.MarshalPKIXPublicKeyDER()
	if err != nil {
		return nil
	}
	pub, err := LoadPublicKeyFromDER(der)
	if err != nil {
		return nil
	}
	return pub
}

func (key *pKey) evpPKey() *C.EVP_PKEY { return key.key }

func (key *pKey) Equal(other PublicKey) bool {
	return C.EVP_PKEY_eq(key.key, other.evpPKey()) == 1
}

func (key *pKey) KeyType() KeyType {
	return KeyType(C.EVP_PKEY_get_id(key.key))
}

func (key *pKey) Size() int {
	return int(C.EVP_PKEY_get_size(key.key))
}

func (key *pKey) Bits() int {
	return int(C.EVP_PKEY_get_bits(key.key))
}

func (key *pKey) SecurityBits() int {
	return int(C.EVP_PKEY_get_security_bits(key.key))
}

func (key *pKey) BaseType() NID {
	return NID(C.EVP_PKEY_get_base_id(key.key))
}

// getAlgorithmInfo returns if it uses a digest function.
//func (key *pKey) getAlgorithmInfo() (bool, int) {
//
//}

// Sign signs a digest with the private key, possibly using entropy from
// rand. It satisfies the crypto.Signer interface. rand is currently
// ignored; opts is only used to select the digest function.
// Currently only support for PKCS V1.5.
func (key *pKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return key.signPKCS1v15(rand, digest, opts)
}

// signPKCS1v15 signs the digest using PKCS1.15. rand is currently
// ignored. If opts indicates a hash function, the digest is treated as
// pre-hashed output of that function (as per the crypto.Signer contract);
// otherwise the digest is treated as the raw message, which is used by
// signature schemes without an intermediate digest (e.g. ED25519).
func (key *pKey) signPKCS1v15(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("signPKCS1v15: 0-length digest")
	}
	if key.signsPrehashedInput() {
		md, err := digestMethodFromCryptoHash(opts)
		if err != nil {
			return nil, err
		}
		if md == nil {
			return nil, errors.New("signPKCS1v15: digest scheme requires opts with a hash function")
		}
		return key.signPrehashed(digest, md)
	}
	return key.signMessage(digest)
}

// signsPrehashedInput reports whether the key's signature scheme signs an
// already-computed digest.
func (key *pKey) signsPrehashedInput() bool {
	switch key.KeyType() {
	case KeyTypeRSA, KeyTypeRSA2, KeyTypeRSAPSS,
		KeyTypeDSA, KeyTypeDSA1, KeyTypeDSA2, KeyTypeDSA3, KeyTypeDSA4,
		KeyTypeEC:
		return true
	}
	return false
}

// signMessage signs the raw input with the one-shot EVP_DigestSign, the
// only sign operation supported by message-based schemes such as ED25519
// and FALCON.
func (key *pKey) signMessage(digest []byte) ([]byte, error) {
	ctx := C.EVP_MD_CTX_new()
	defer C.EVP_MD_CTX_free(ctx)

	if C.EVP_DigestSignInit(ctx, nil, nil, nil, key.key) != 1 {
		return nil, fmt.Errorf("failed to initialize digest signing context: %w", errorFromErrorQueue())
	}

	var siglen C.size_t = C.size_t(C.EVP_PKEY_get_size(key.key))
	sig := make([]byte, siglen)
	if C.EVP_DigestSign(ctx,
		(*C.uchar)(unsafe.Pointer(&sig[0])),
		&siglen,
		(*C.uchar)(unsafe.Pointer(&digest[0])),
		C.size_t(len(digest))) != 1 {
		return nil, fmt.Errorf("failed to sign with key: %w", errorFromErrorQueue())
	}

	return sig[:siglen], nil
}

// signPrehashed signs an already-computed digest with EVP_PKEY_sign,
// identifying the digest method so the scheme can wrap it appropriately
// (e.g. a DigestInfo for RSA, DER-serialisation for ECDSA).
func (key *pKey) signPrehashed(digest []byte, md *C.EVP_MD) ([]byte, error) {
	ctx := C.EVP_PKEY_CTX_new(key.key, nil)
	defer C.EVP_PKEY_CTX_free(ctx)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create pkey context: %w", errorFromErrorQueue())
	}

	if C.EVP_PKEY_sign_init(ctx) != 1 {
		return nil, fmt.Errorf("failed to initialization signing context: %w", errorFromErrorQueue())
	}

	if C.EVP_PKEY_CTX_set_signature_md(ctx, md) != 1 {
		return nil, fmt.Errorf("failed to set signature digest: %w", errorFromErrorQueue())
	}

	var siglen C.size_t = C.size_t(C.EVP_PKEY_get_size(key.key))
	sig := make([]byte, siglen)
	if C.EVP_PKEY_sign(ctx,
		(*C.uchar)(unsafe.Pointer(&sig[0])),
		&siglen,
		(*C.uchar)(unsafe.Pointer(&digest[0])),
		C.size_t(len(digest))) != 1 {
		return nil, fmt.Errorf("failed to sign with key: %w", errorFromErrorQueue())
	}

	return sig[:siglen], nil
}

// SignWithDigest signs the data using PKCS1.15, hashing the data with the
// provided digest.
func (key *pKey) SignWithDigest(digest *Digest, data []byte) ([]byte, error) {
	return key.signPKCS1v15WithDigest(digest, data)
}

// signPKCS1v15WithDigest signs the data using PKCS1.15, hashing the data
// with the provided digest.
func (key *pKey) signPKCS1v15WithDigest(digest *Digest, data []byte) ([]byte, error) {
	if digest == nil {
		return key.signPKCS1v15(nil, data, nil)
	}

	job, err := NewDigestJob(*digest)
	if err != nil {
		return nil, err
	}
	if err = job.Update(data); err != nil {
		return nil, err
	}
	return job.SignFinal(key)
}

func (key *pKey) Verify(digest, sig []byte, opts crypto.SignerOpts) error {
	return key.verifyPKCS1v15(digest, sig, opts)
}

// verifyPKCS1v15 verifies the signature using PKCS1.5. The verification
// assumes that data is pre-hashed
func (key *pKey) verifyPKCS1v15(digest, sig []byte, opts crypto.SignerOpts) error {
	if len(sig) == 0 {
		return errors.New("verifyPKCS1v15: 0-length sig")
	}
	if key.signsPrehashedInput() {
		if len(digest) == 0 {
			return errors.New("verifyPKCS1v15: 0-length digest")
		}
		md, err := digestMethodFromCryptoHash(opts)
		if err != nil {
			return err
		}
		if md == nil {
			return errors.New("verifyPKCS1v15: digest scheme requires opts with a hash function")
		}
		return key.verifyPrehashed(digest, sig, md)
	}
	if len(digest) == 0 {
		return errors.New("verifyPKCS1v15: 0-length data")
	}
	return key.verifyMessage(digest, sig)
}

// verifyMessage verifies the signature over the raw data with the one-shot
// EVP_DigestVerify, the only verify operation supported by message-based
// schemes such as ED25519 and FALCON.
func (key *pKey) verifyMessage(digest, sig []byte) error {
	ctx := C.EVP_MD_CTX_new()
	defer C.EVP_MD_CTX_free(ctx)

	if C.EVP_DigestVerifyInit(ctx, nil, nil, nil, key.key) != 1 {
		return fmt.Errorf("failed to initialize digest verification context: %w", errorFromErrorQueue())
	}

	if C.EVP_DigestVerify(ctx,
		(*C.uchar)(unsafe.Pointer(&sig[0])),
		C.size_t(len(sig)),
		(*C.uchar)(unsafe.Pointer(&digest[0])),
		C.size_t(len(digest))) != 1 {
		return fmt.Errorf("failed to verify data with key (without digest): %w", errorFromErrorQueue())
	}

	return nil
}

// verifyPrehashed verifies a signature over an already-computed digest
// with EVP_PKEY_verify, identifying the digest method so the scheme can
// check the appropriate wrapping (e.g. a DigestInfo for RSA,
// DER-serialisation for ECDSA).
func (key *pKey) verifyPrehashed(data, sig []byte, md *C.EVP_MD) error {
	ctx := C.EVP_PKEY_CTX_new(key.key, nil)
	defer C.EVP_PKEY_CTX_free(ctx)
	if ctx == nil {
		return fmt.Errorf("failed to create pkey context: %w", errorFromErrorQueue())
	}

	if C.EVP_PKEY_verify_init(ctx) != 1 {
		return fmt.Errorf("failed to initialize verification context: %w", errorFromErrorQueue())
	}

	if C.EVP_PKEY_CTX_set_signature_md(ctx, md) != 1 {
		return fmt.Errorf("failed to set signature digest: %w", errorFromErrorQueue())
	}

	if C.EVP_PKEY_verify(ctx,
		(*C.uchar)(unsafe.Pointer(&sig[0])),
		C.size_t(len(sig)),
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.size_t(len(data))) != 1 {
		return fmt.Errorf("failed to verify with key: %w", errorFromErrorQueue())
	}

	return nil
}

func (key *pKey) VerifyWithDigest(digest *Digest, data, sig []byte) error {
	return key.verifyPKCS1v15WithDigest(digest, data, sig)
}

func (key *pKey) verifyPKCS1v15WithDigest(digest *Digest, data, sig []byte) error {

	if digest == nil {
		return key.Verify(data, sig, nil)
	}

	job, err := NewDigestJob(*digest)
	if err != nil {
		return err
	}
	if err = job.Update(data); err != nil {
		return err
	}
	return job.VerifyFinal(sig, key)

}

func (key *pKey) MarshalPKCS1PrivateKeyPEM() (pemBlock []byte, err error) {
	bio, err := newBio(nil)
	if err != nil {
		return nil, err
	}

	// PEM_write_bio_PrivateKey_traditional will use the key-specific PKCS1
	// format if one is available for that key type, otherwise it will encode
	// to a PKCS8 key.
	if int(C.PEM_write_bio_PrivateKey_traditional(
		bio.ptr, key.key, nil, nil, C.int(0), nil, nil,
	)) != 1 {
		return nil, errors.New("failed dumping private key")
	}

	pemBlock, err = io.ReadAll(bio.asAnyBio())
	runtime.KeepAlive(bio)
	return
}

func (key *pKey) MarshalPKCS1PrivateKeyDER() (derBlock []byte, err error) {
	bio, err := newBio(nil)
	if err != nil {
		return nil, err
	}

	if int(C.i2d_PrivateKey_bio(bio.ptr, key.key)) != 1 {
		return nil, errors.New("failed dumping private key der")
	}

	derBlock, err = io.ReadAll(bio.asAnyBio())
	runtime.KeepAlive(bio)
	return
}

func (key *pKey) MarshalPKIXPublicKeyPEM() (pemBlock []byte, err error) {
	bio, err := newBio(nil)
	if err != nil {
		return nil, err
	}

	if int(C.PEM_write_bio_PUBKEY(bio.ptr, key.key)) != 1 {
		return nil, errors.New("failed dumping public key pem")
	}

	pemBlock, err = io.ReadAll(bio.asAnyBio())
	runtime.KeepAlive(bio)
	return
}

func (key *pKey) MarshalPKIXPublicKeyDER() (derBlock []byte, err error) {
	bio, err := newBio(nil)
	if err != nil {
		return nil, err
	}

	if int(C.i2d_PUBKEY_bio(bio.ptr, key.key)) != 1 {
		return nil, errors.New("failed dumping public key der")
	}

	derBlock, err = io.ReadAll(bio.asAnyBio())
	runtime.KeepAlive(bio)
	return
}

// LoadPrivateKeyFromPEM loads a private key from a PEM-encoded block.
func LoadPrivateKeyFromPEM(pemBlock []byte) (PrivateKey, error) {
	if len(pemBlock) == 0 {
		return nil, ErrEmptyBlock
	}
	bio, err := newBio(pemBlock)
	if err != nil {
		return nil, err
	}
	key := C.PEM_read_bio_PrivateKey(bio.ptr, nil, nil, nil)
	runtime.KeepAlive(bio)
	if key == nil {
		return nil, ErrLoadingKey
	}

	return pKeyFromKey(key), nil
}

// LoadPrivateKeyFromPEMWithPassword loads a private key from a PEM-encoded block.
func LoadPrivateKeyFromPEMWithPassword(pemBlock []byte, password string) (PrivateKey, error) {
	if len(pemBlock) == 0 {
		return nil, ErrEmptyBlock
	}
	bio, err := newBio(pemBlock)
	if err != nil {
		return nil, err
	}
	cs := unsafe.Pointer(C.CString(password))
	defer C.free(cs)
	key := C.PEM_read_bio_PrivateKey(bio.ptr, nil, nil, cs)
	runtime.KeepAlive(bio)
	if key == nil {
		return nil, ErrLoadingKey
	}

	return pKeyFromKey(key), nil
}

// LoadPrivateKeyFromDER loads a private key from a DER-encoded block.
func LoadPrivateKeyFromDER(derBlock []byte) (PrivateKey, error) {
	if len(derBlock) == 0 {
		return nil, ErrEmptyBlock
	}
	bio, err := newBio(derBlock)
	if err != nil {
		return nil, err
	}

	key := C.d2i_PrivateKey_bio(bio.ptr, nil)
	runtime.KeepAlive(bio)
	if key == nil {
		return nil, ErrLoadingKey
	}

	return pKeyFromKey(key), nil
}

// LoadPublicKeyFromPEM loads a public key from a PEM-encoded block.
func LoadPublicKeyFromPEM(pemBlock []byte) (PublicKey, error) {
	if len(pemBlock) == 0 {
		return nil, ErrEmptyBlock
	}
	bio, err := newBio(pemBlock)
	if err != nil {
		return nil, err
	}

	key := C.PEM_read_bio_PUBKEY(bio.ptr, nil, nil, nil)
	runtime.KeepAlive(bio)
	if key == nil {
		return nil, ErrLoadingKey
	}

	return pKeyFromKey(key), nil
}

// LoadPublicKeyFromDER loads a public key from a DER-encoded block.
func LoadPublicKeyFromDER(derBlock []byte) (PublicKey, error) {
	if len(derBlock) == 0 {
		return nil, ErrEmptyBlock
	}
	bio, err := newBio(derBlock)
	if err != nil {
		return nil, err
	}

	key := C.d2i_PUBKEY_bio(bio.ptr, nil)
	runtime.KeepAlive(bio)
	if key == nil {
		return nil, ErrLoadingKey
	}

	return pKeyFromKey(key), nil
}

type PrivateKeyContext interface {
	evpCtx() *C.EVP_PKEY_CTX
	SetRSAKeygenBits(bits int) error
	SetRSAKeygenPubExp(exponent int) error
}
type PrivateKeyGenerationContext interface {
	PrivateKeyContext
	Generate() (PrivateKey, error)
}
type PrivateKeyParamGenerationContext interface {
	PrivateKeyContext
	Generate() (PrivateKey, error)
	SetECParamGenCurveNID(curve EllipticCurve) error
}
type PrivateKeyDeriveContext interface {
	PrivateKeyContext
	SetPeer(peer PublicKey) error
	Derive() ([]byte, error)
}

type pkeyCtx struct {
	ctx   *C.EVP_PKEY_CTX
	keyID KeyType
}
type pkeyGenCtx struct {
	*pkeyCtx
}
type pkeyParamGenCtx struct {
	*pkeyCtx
}
type pkeyDeriveCtx struct {
	*pkeyCtx
}

func (p *pkeyCtx) evpCtx() *C.EVP_PKEY_CTX {
	return p.ctx
}

func (p *pkeyCtx) SetRSAKeygenBits(bits int) error {
	if err := ensureErrorQueueIsClear(); err != nil {
		return fmt.Errorf("failed setting RSA keygen bits: %w", err)
	}
	if int(C.EVP_PKEY_CTX_set_rsa_keygen_bits(p.ctx, C.int(bits))) != 1 {
		return fmt.Errorf("failed setting RSA keygen bits: %w", errorFromErrorQueue())
	}
	return nil
}
func (p *pkeyCtx) SetRSAKeygenPubExp(exponent int) error {
	exponentBn, err := newBignumFromInt(exponent)
	if err != nil {
		return fmt.Errorf("failed creating RSA public exponent BN: %w", err)
	}
	if err := ensureErrorQueueIsClear(); err != nil {
		return fmt.Errorf("failed setting RSA keygen public exponent: %w", err)
	}
	if int(C.EVP_PKEY_CTX_set1_rsa_keygen_pubexp(p.ctx, exponentBn.bn)) != 1 {
		return fmt.Errorf("failed setting RSA keygen public exponent: %w", errorFromErrorQueue())
	}
	runtime.KeepAlive(exponentBn)
	return nil
}
func (p *pkeyCtx) generate() (PrivateKey, error) {
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed generating PrivateKey: %w", err)
	}
	pkeySerialize.Lock()
	defer pkeySerialize.Unlock()
	var key *C.EVP_PKEY
	if int(C.EVP_PKEY_generate(p.ctx, &key)) != 1 {
		return nil, fmt.Errorf("failing generating PrivateKey: %w", errorFromErrorQueue())
	}
	return pKeyFromKey(key), nil
}

func (p *pkeyParamGenCtx) SetECParamGenCurveNID(curve EllipticCurve) error {
	if err := ensureErrorQueueIsClear(); err != nil {
		return fmt.Errorf("failed setting EC paramgen curve NID: %w", err)
	}
	if int(C.EVP_PKEY_CTX_set_ec_paramgen_curve_nid(p.ctx, C.int(curve))) != 1 {
		return fmt.Errorf("failed setting EC paramgen curve NID: %w", errorFromErrorQueue())
	}
	return nil
}
func (p *pkeyParamGenCtx) Generate() (PrivateKey, error) {
	return p.generate()
}

func (p *pkeyGenCtx) Generate() (PrivateKey, error) {
	return p.generate()
}

func (p *pkeyDeriveCtx) SetPeer(peer PublicKey) error {
	if err := ensureErrorQueueIsClear(); err != nil {
		return fmt.Errorf("failed setting derive peer: %w", err)
	}
	if int(C.EVP_PKEY_derive_set_peer(p.ctx, peer.evpPKey())) != 1 {
		return fmt.Errorf("failed setting derive peer: %w", errorFromErrorQueue())
	}
	return nil
}
func (p *pkeyDeriveCtx) Derive() ([]byte, error) {
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed deriving: %w", err)
	}
	var bufferLen C.size_t
	if int(C.EVP_PKEY_derive(p.ctx, nil, &bufferLen)) != 1 {
		return nil, fmt.Errorf("failed deriving: %w", errorFromErrorQueue())
	}
	buffer := make([]byte, bufferLen)
	if int(C.EVP_PKEY_derive(
		p.ctx, (*C.uchar)(unsafe.Pointer(&buffer[0])), &bufferLen),
	) != 1 {
		return nil, fmt.Errorf("failed deriving: %w", errorFromErrorQueue())
	}
	return buffer[:bufferLen], nil
}

func newPKeyContextFromKey(key PrivateKey) (*pkeyCtx, error) {
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed creating new pKeyContext from key: %w", err)
	}
	ctx := C.EVP_PKEY_CTX_new(key.evpPKey(), nil)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create pKeyCtx: %w", errorFromErrorQueue())
	}
	return &pkeyCtx{ctx: ctx, keyID: key.KeyType()}, nil
}
func newPKeyContextFromKeyType(keyType KeyType) (*pkeyCtx, error) {
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed creating new pKeyContext from type: %w", err)
	}
	ctx := C.EVP_PKEY_CTX_new_id(C.int(keyType), nil)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create pKeyCtx: %w", errorFromErrorQueue())
	}
	keyCtx := &pkeyCtx{ctx: ctx}
	runtime.SetFinalizer(keyCtx, func(c *pkeyCtx) {
		if c.ctx != nil {
			pkeySerialize.Lock()
			C.EVP_PKEY_CTX_free(c.ctx)
			pkeySerialize.Unlock()
			c.ctx = nil
		}
	})
	return keyCtx, nil
}

func NewPKeyGenerationContextFromKey(key PrivateKey) (PrivateKeyGenerationContext, error) {
	ctx, err := newPKeyContextFromKey(key)
	if err != nil {
		return nil, err
	}
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed initialise keygen: %w", err)
	}
	if int(C.EVP_PKEY_keygen_init(ctx.evpCtx())) != 1 {
		return nil, fmt.Errorf("failed initialise keygen: %w", errorFromErrorQueue())
	}
	return &pkeyGenCtx{ctx}, nil
}
func NewPKeyGenerationContextFromKeyType(keyType KeyType) (PrivateKeyGenerationContext, error) {
	ctx, err := newPKeyContextFromKeyType(keyType)
	if err != nil {
		return nil, err
	}
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed initialise keygen: %w", err)
	}
	if int(C.EVP_PKEY_keygen_init(ctx.evpCtx())) != 1 {
		return nil, fmt.Errorf("failed initialise keygen: %w", errorFromErrorQueue())
	}
	return &pkeyGenCtx{ctx}, nil
}

func NewPKeyParamGenerationCtx(keyID KeyType) (PrivateKeyParamGenerationContext, error) {
	ctx, err := newPKeyContextFromKeyType(keyID)
	if err != nil {
		return nil, err
	}
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed initialise paramgen: %w", err)
	}
	if int(C.EVP_PKEY_paramgen_init(ctx.evpCtx())) != 1 {
		return nil, fmt.Errorf("failed initialise paramgen: %w", errorFromErrorQueue())
	}
	return &pkeyParamGenCtx{ctx}, nil
}

func NewPKeyDeriveContextFromKey(key PrivateKey) (PrivateKeyDeriveContext, error) {
	ctx, err := newPKeyContextFromKey(key)
	if err != nil {
		return nil, err
	}
	if err := ensureErrorQueueIsClear(); err != nil {
		return nil, fmt.Errorf("failed initialise derive: %w", err)
	}
	if int(C.EVP_PKEY_derive_init(ctx.evpCtx())) != 1 {
		return nil, fmt.Errorf("failed initialise derive: %w", errorFromErrorQueue())
	}
	return &pkeyDeriveCtx{ctx}, nil
}

// GenerateRSAKey generates a new RSA private key with an exponent of 3.
func GenerateRSAKey(bits int) (PrivateKey, error) {
	return GenerateRSAKeyWithExponent(bits, 3)
}

// GenerateRSAKeyWithExponent generates a new RSA private key.
func GenerateRSAKeyWithExponent(bits int, exponent int) (PrivateKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	ctx, err := NewPKeyGenerationContextFromKeyType(KeyTypeRSA)
	if err != nil {
		return nil, err
	}
	if err = ctx.SetRSAKeygenBits(bits); err != nil {
		return nil, err
	}
	if err = ctx.SetRSAKeygenPubExp(exponent); err != nil {
		return nil, err
	}
	p, err := ctx.Generate()
	if err != nil {
		return nil, err
	}
	return p, nil
}

// GenerateECKey generates a new elliptic curve private key on the specified curve.
func GenerateECKey(curve EllipticCurve) (PrivateKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	paramCtx, err := NewPKeyParamGenerationCtx(KeyTypeEC)
	if err != nil {
		return nil, err
	}
	if err = paramCtx.SetECParamGenCurveNID(curve); err != nil {
		return nil, err
	}
	params, err := paramCtx.Generate()
	if err != nil {
		return nil, err
	}

	keyCtx, err := NewPKeyGenerationContextFromKey(params)
	if err != nil {
		return nil, err
	}
	key, err := keyCtx.Generate()
	if err != nil {
		return nil, err
	}
	return key, nil
}

// GenerateED25519Key generates a Ed25519 key
func GenerateED25519Key() (PrivateKey, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	keyCtx, err := NewPKeyGenerationContextFromKeyType(KeyTypeED25519)
	if err != nil {
		return nil, err
	}
	key, err := keyCtx.Generate()
	if err != nil {
		return nil, err
	}
	return key, nil
}
