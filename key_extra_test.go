package openssl

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// Note: AI generated and not checked in detail.
// More focused on parallel execution.

type zeroHashOpts struct{}

func (zeroHashOpts) HashFunc() crypto.Hash { return 0 }

// TestSignRequiresHashForDigestSchemes pins the fail-fast behavior: digest
// schemes (RSA, EC) must reject signing when opts carries no hash function,
// while message schemes (ED25519, ED448) sign fine without opts.
func TestSignRequiresHashForDigestSchemes(t *testing.T) {
	t.Parallel()

	hashed := sha256.Sum256([]byte("the quick brown fox"))

	rsaKey, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = rsaKey.Sign(rand.Reader, hashed[:], nil); err == nil {
		t.Fatal("expected error for RSA key signed without hash opts")
	}
	if _, err = rsaKey.Sign(rand.Reader, hashed[:], crypto.SignerOpts(zeroHashOpts{})); err == nil {
		t.Fatal("expected error for RSA key signed with zero-hash opts")
	}

	ecKey, err := GenerateECKey(Prime256v1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ecKey.Sign(rand.Reader, hashed[:], nil); err == nil {
		t.Fatal("expected error for EC key signed without hash opts")
	}

	edKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = edKey.Sign(rand.Reader, []byte("message"), nil); err != nil {
		t.Fatalf("message scheme should not require opts: %v", err)
	}
}

// TestVerifyRequiresHashForDigestSchemes pins the verify-side fail-fast.
func TestVerifyRequiresHashForDigestSchemes(t *testing.T) {
	t.Parallel()

	hashed := sha256.Sum256([]byte("the quick brown fox"))

	rsaKey, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsaKey.Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pub := rsaKey.Public().(PublicKey)
	if err = pub.Verify(hashed[:], sig, nil); err == nil {
		t.Fatal("expected error for RSA verify without hash opts")
	}

	// VerifyWithDigest with a nil digest must not silently rehash the data
	// for digest schemes either.
	if err = pub.VerifyWithDigest(nil, []byte("some data"), sig); err == nil {
		t.Fatal("expected error for RSA VerifyWithDigest with nil digest")
	}

	ecKey, err := GenerateECKey(Prime256v1)
	if err != nil {
		t.Fatal(err)
	}
	ecSig, err := ecKey.Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err = ecKey.Public().(PublicKey).Verify(hashed[:], ecSig, nil); err == nil {
		t.Fatal("expected error for EC verify without hash opts")
	}
}

// TestPrehashedNegativeMatrix proves the md from opts is actually used in
// the signature math, and that mismatches are rejected in every direction.
func TestPrehashedNegativeMatrix(t *testing.T) {
	t.Parallel()

	data := []byte("the quick brown fox jumps over the lazy dog")
	digest256 := sha256.Sum256(data)
	digest384 := sha512.Sum384(data)

	rsaKey, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsaKey.Sign(rand.Reader, digest256[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pub := rsaKey.Public().(PublicKey)

	// wrong hash in opts -> the DigestInfo mismatch must be rejected
	if err = pub.Verify(digest384[:], sig, crypto.SHA384); err == nil {
		t.Fatal("expected verify with mismatched hash opts + digest to fail")
	}
	// correct opts but digest from a different hash
	if err = pub.Verify(digest384[:], sig, crypto.SHA256); err == nil {
		t.Fatal("expected verify with wrong digest to fail")
	}
	// tampered signature
	tampered := bytes.Clone(sig)
	tampered[len(tampered)-1] ^= 0xFF
	if err = pub.Verify(digest256[:], tampered, crypto.SHA256); err == nil {
		t.Fatal("expected verify of tampered signature to fail")
	}
	// signature from a different key
	otherKey, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	if err = otherKey.Public().(PublicKey).Verify(digest256[:], sig, crypto.SHA256); err == nil {
		t.Fatal("expected verify with wrong key to fail")
	}

	ecKey, err := GenerateECKey(Prime256v1)
	if err != nil {
		t.Fatal(err)
	}
	ecSig, err := ecKey.Sign(rand.Reader, digest256[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if err = ecKey.Public().(PublicKey).Verify(digest384[:], ecSig, crypto.SHA256); err == nil {
		t.Fatal("expected ECDSA verify with wrong digest to fail")
	}

	edKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatal(err)
	}
	edSig, err := edKey.Sign(rand.Reader, data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = edKey.Public().(PublicKey).Verify([]byte("different message"), edSig, nil); err == nil {
		t.Fatal("expected ED25519 verify of different message to fail")
	}
}

// TestSignPrehashedMatchesSignWithDigest: RSA PKCS1v15 is deterministic, so
// the pre-hashed path and the raw-data path must yield identical bytes —
// and each verify path must accept the other's signature.
func TestSignPrehashedMatchesSignWithDigest(t *testing.T) {
	t.Parallel()

	key, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := GetDigestByName("sha256", false)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("the quick brown fox jumps over the lazy dog")

	hashed := sha256.Sum256(data)
	preHashed, err := key.Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	withDigest, err := key.SignWithDigest(digest, data)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(preHashed, withDigest) {
		t.Fatal("pre-hashed signature does not match SignWithDigest signature (RSA PKCS1v15 is deterministic)")
	}

	pub := key.Public().(PublicKey)
	if err = pub.Verify(hashed[:], withDigest, crypto.SHA256); err != nil {
		t.Fatalf("pre-hashed verify rejected raw-data signature: %v", err)
	}
	if err = pub.VerifyWithDigest(digest, data, preHashed); err != nil {
		t.Fatalf("raw-data verify rejected pre-hashed signature: %v", err)
	}
}

// TestPrehashedAllHashes runs the pre-hashed path for the full SHA family
// in both directions for RSA, and SHA-256/384 for ECDSA.
func TestPrehashedAllHashes(t *testing.T) {
	t.Parallel()

	data := []byte("the quick brown fox jumps over the lazy dog")

	rsaKey, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := rsaKey.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	rsaGoPub := rsaPub.(*rsa.PublicKey)

	// std-lib key for the reverse direction (go/crypto signs, openssl verifies)
	stdRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	stdRSAOsslPubDER, err := x509.MarshalPKIXPublicKey(&stdRSA.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	stdRSAOsslPub, err := LoadPublicKeyFromDER(stdRSAOsslPubDER)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		hash crypto.Hash
		dg   []byte
	}{
		{crypto.SHA1, func() []byte { s := sha1.Sum(data); return s[:] }()},
		{crypto.SHA224, func() []byte { s := sha256.Sum224(data); return s[:] }()},
		{crypto.SHA256, func() []byte { s := sha256.Sum256(data); return s[:] }()},
		{crypto.SHA384, func() []byte { s := sha512.Sum384(data); return s[:] }()},
		{crypto.SHA512, func() []byte { s := sha512.Sum512(data); return s[:] }()},
	} {
		t.Run(tc.hash.String(), func(t *testing.T) {
			t.Parallel()
			sig, err := rsaKey.Sign(rand.Reader, tc.dg, tc.hash)
			if err != nil {
				t.Fatal(err)
			}
			if err = rsa.VerifyPKCS1v15(rsaGoPub, tc.hash, tc.dg, sig); err != nil {
				t.Fatalf("openssl sign -> std verify: %v", err)
			}
			stdSig, err := rsa.SignPKCS1v15(rand.Reader, stdRSA, tc.hash, tc.dg)
			if err != nil {
				t.Fatal(err)
			}
			if err = stdRSAOsslPub.Verify(tc.dg, stdSig, tc.hash); err != nil {
				t.Fatalf("std sign -> openssl verify: %v", err)
			}
		})
	}

	ecKey, err := GenerateECKey(Prime256v1)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		hash crypto.Hash
		dg   []byte
	}{
		{crypto.SHA256, func() []byte { s := sha256.Sum256(data); return s[:] }()},
		{crypto.SHA384, func() []byte { s := sha512.Sum384(data); return s[:] }()},
	} {
		t.Run("ECDSA/"+tc.hash.String(), func(t *testing.T) {
			t.Parallel()
			sig, err := ecKey.Sign(rand.Reader, tc.dg, tc.hash)
			if err != nil {
				t.Fatal(err)
			}
			ecDER, err := ecKey.MarshalPKIXPublicKeyDER()
			if err != nil {
				t.Fatal(err)
			}
			goPub, err := x509.ParsePKIXPublicKey(ecDER)
			if err != nil {
				t.Fatal(err)
			}
			if !ecdsa.VerifyASN1(goPub.(*ecdsa.PublicKey), tc.dg, sig) {
				t.Fatal("openssl sign -> std verify failed")
			}
			stdSig, err := ecdsa.SignASN1(rand.Reader, ecKeyToStd(t, ecKey), tc.dg)
			if err != nil {
				t.Fatal(err)
			}
			if err = ecKey.Public().(PublicKey).Verify(tc.dg, stdSig, tc.hash); err != nil {
				t.Fatalf("std sign -> openssl verify: %v", err)
			}
		})
	}
}

func ecKeyToStd(t *testing.T, key PrivateKey) *ecdsa.PrivateKey {
	t.Helper()
	pemBlock, err := key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBlock)
	if block == nil {
		t.Fatal("failed decoding private key pem")
	}
	std, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return std
}

// TestKeyEncodingRoundtrips checks the public/private serialization paths
// still work with the new API and reproduce identical key material.
func TestKeyEncodingRoundtrips(t *testing.T) {
	t.Parallel()

	key, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("the quick brown fox")
	hashed := sha256.Sum256(data)

	der, err := key.MarshalPKCS1PrivateKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadPrivateKeyFromDER(der)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.Equal(key) {
		t.Fatal("reloaded private key is not equal to the original")
	}
	// deterministic: reloaded key produces the identical RSA signature
	sigA, err := key.Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sigB, err := reloaded.Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sigA, sigB) {
		t.Fatal("reloaded private key produces different signature")
	}

	pubDER, err := key.MarshalPKIXPublicKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	pubLoaded, err := LoadPublicKeyFromDER(pubDER)
	if err != nil {
		t.Fatal(err)
	}
	if err = pubLoaded.Verify(hashed[:], sigA, crypto.SHA256); err != nil {
		t.Fatal(err)
	}
	if !pubLoaded.Equal(key.Public().(PublicKey)) {
		t.Fatal("reloaded public key is not equal to Public()")
	}

	edKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatal(err)
	}
	edPEM, err := edKey.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	edLoaded, err := LoadPublicKeyFromPEM(edPEM)
	if err != nil {
		t.Fatal(err)
	}
	edSig, err := edKey.Sign(rand.Reader, data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = edLoaded.Verify(data, edSig, nil); err != nil {
		t.Fatal(err)
	}
}

// TestPublicForAllKeyTypes fills the "TODO: add testcases" on Public().
func TestPublicForAllKeyTypes(t *testing.T) {
	t.Parallel()

	data := []byte("the quick brown fox")
	hashed := sha256.Sum256(data)

	rsaKey, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsaKey.Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub := rsaKey.Public().(PublicKey)
	if rsaPub.KeyType() != KeyTypeRSA {
		t.Fatalf("expected KeyTypeRSA, got %v", rsaPub.KeyType())
	}
	if err = rsaPub.Verify(hashed[:], sig, crypto.SHA256); err != nil {
		t.Fatal(err)
	}
	pemBlock, err := rsaPub.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(pemBlock, []byte("PRIVATE")) {
		t.Fatal("public key PEM contains private key material")
	}

	ecKey, err := GenerateECKey(Prime256v1)
	if err != nil {
		t.Fatal(err)
	}
	if ecKey.Public().(PublicKey).KeyType() != KeyTypeEC {
		t.Fatal("expected KeyTypeEC")
	}

	edKey, err := GenerateED25519Key()
	if err != nil {
		t.Fatal(err)
	}
	edPub := edKey.Public().(PublicKey)
	if edPub.KeyType() != KeyTypeED25519 {
		t.Fatal("expected KeyTypeED25519")
	}
	edSig, err := edKey.Sign(rand.Reader, data, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = edPub.Verify(data, edSig, nil); err != nil {
		t.Fatal(err)
	}

	pub1 := rsaKey.Public().(PublicKey)
	pub2 := rsaKey.Public().(PublicKey)
	if !pub1.Equal(pub2) {
		t.Fatal("Public() is not stable across calls")
	}
}

// TestED448SignVerify exercises the ED448 message path end to end.
func TestED448SignVerify(t *testing.T) {
	t.Parallel()

	ctx, err := NewPKeyGenerationContextFromKeyType(KeyTypeED448)
	if err != nil {
		t.Skipf("cannot create ED448 context: %v", err)
	}
	key, err := ctx.Generate()
	if err != nil {
		t.Skipf("cannot generate ED448 key: %v", err)
	}
	msg := []byte("the quick brown fox")
	sig, err := key.Sign(rand.Reader, msg, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 114 {
		t.Fatalf("expected 114 byte ED448 signature, got %d", len(sig))
	}
	pub := key.Public().(PublicKey)
	if err = pub.Verify(msg, sig, nil); err != nil {
		t.Fatal(err)
	}
	if err = pub.Verify([]byte("tampered"), sig, nil); err == nil {
		t.Fatal("expected tampered message verification to fail")
	}
}

// TestRSAPSSPaddingBehavior documents a sharp edge: RSA-PSS keys route
// through the pre-hashed path but produce PSS signatures (randomized salt),
// NOT PKCS1v15 signatures, because the key enforces PSS padding in OpenSSL.
// If you decide to fail-fast on RSA-PSS instead, replace the internals of
// this test with an assertion of the error.
func TestRSAPSSPaddingBehavior(t *testing.T) {
	t.Parallel()

	ctx, err := NewPKeyGenerationContextFromKeyType(KeyTypeRSAPSS)
	if err != nil {
		t.Skipf("cannot create RSA-PSS context: %v", err)
	}
	if err = ctx.SetRSAKeygenBits(2048); err != nil {
		t.Fatal(err)
	}
	key, err := ctx.Generate()
	if err != nil {
		t.Skipf("cannot generate RSA-PSS key: %v", err)
	}

	hashed := sha256.Sum256([]byte("the quick brown fox"))
	sig1, err := key.Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := key.Sign(rand.Reader, hashed[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	// PKCS1v15 is deterministic; PSS randomizes the salt.
	if bytes.Equal(sig1, sig2) {
		t.Fatal("RSA-PSS signatures are deterministic: expected PSS (randomized) semantics")
	}
	pub := key.Public().(PublicKey)
	if err = pub.Verify(hashed[:], sig1, crypto.SHA256); err != nil {
		t.Fatalf("self-consistent PSS verify failed: %v", err)
	}
}
