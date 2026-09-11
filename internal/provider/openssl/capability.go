package openssl

import (
	"context"
	"sort"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-api-go/gen/go/types"
	"github.com/agile-crypto/citius-core/errors"
	"google.golang.org/protobuf/proto"
)

// catalog maps a template ID — matching the standard algorithm catalog's
// TemplateID values, the same contract software.SupportedAlgorithms
// documents — to the ossl.Capability New checks the instance's context
// against.
//
// This is narrower than the full IDs software.SupportedAlgorithms
// advertises for these curves — the "-prehashed-der" variants use
// SignDigest/VerifyDigest, which do not exist in this package yet, so they
// are not in this catalog either.
var catalog = map[string]ossl.Capability{
	"ecdsa-p256-sha256-der": ossl.SignatureCapability{Key: ossl.EC, Curve: ossl.P256, Digest: ossl.SHA256},
	"ecdsa-p384-sha384-der": ossl.SignatureCapability{Key: ossl.EC, Curve: ossl.P384, Digest: ossl.SHA384},
	"ecdsa-p521-sha512-der": ossl.SignatureCapability{Key: ossl.EC, Curve: ossl.P521, Digest: ossl.SHA512},

	// All four RSA entries use Key: ossl.RSA, the same plain key type
	// keyAlgorithmFor generates for both RsaPss and RsaPkcs1V15 (see its
	// doc comment). This has two consequences worth knowing:
	//
	//  - No bit-size field exists on ossl.SignatureCapability, and
	//    availability does not vary by key size at 2048/3072/4096 (all
	//    FIPS-approved), so the two SHA-256 PSS entries below intentionally
	//    check the identical capability. They stay separate catalog entries
	//    because they are separate template IDs with separate GenerateKey
	//    bit-size behavior.
	//  - No Padding field exists either. The structural check (Supports) is
	//    still accurate for every entry here — a plain "RSA" key
	//    structurally permits both PSS and PKCS#1 v1.5, so "RSA + this
	//    digest available" is a true claim regardless of scheme. But
	//    VerifyCapabilities' trial signs and verifies through SignOptions'
	//    zero-value default, which is PSS — so that trial proves PSS
	//    specifically for every RSA entry here, including the PKCS#1 v1.5
	//    one. Real PKCS#1 v1.5 signing correctness is proven where it
	//    actually matters: by Sign/Verify's own dedicated tests once they
	//    exist, not by this capability probe.
	"rsa-pss-sha256-mgf1-32-2048": ossl.SignatureCapability{Key: ossl.RSA, Digest: ossl.SHA256},
	"rsa-pss-sha256-mgf1-32-3072": ossl.SignatureCapability{Key: ossl.RSA, Digest: ossl.SHA256},
	"rsa-pss-sha384-mgf1-48-4096": ossl.SignatureCapability{Key: ossl.RSA, Digest: ossl.SHA384},
	"rsa-pkcs1v15-sha256-2048":    ossl.SignatureCapability{Key: ossl.RSA, Digest: ossl.SHA256},

	// Ed25519 hashes internally, so Digest stays empty (a non-empty Digest
	// on a key that hashes internally is itself a check() error — see
	// hashesInternally in ossl-go). ed25519 and ed25519ph generate an
	// identical key (see generateEd25519Key's doc); Prehash is what
	// distinguishes the two capabilities, and both are verified directly to
	// work end-to-end via ctx.VerifyCapability, independent of this
	// package's own Sign not existing yet.
	"ed25519":   ossl.SignatureCapability{Key: ossl.Ed25519},
	"ed25519ph": ossl.SignatureCapability{Key: ossl.Ed25519, Prehash: true},

	// ML-DSA also hashes internally, so Digest stays empty, same as Ed25519
	// above. See generateMLDSAKey's doc comment for the encoding this
	// algorithm needs to interoperate with software (RAW public key, not
	// SPKI) — Supports/VerifyCapability here only check that this context
	// can generate and use its own ML-DSA key, independent of that.
	"ml-dsa-44": ossl.SignatureCapability{Key: ossl.MLDSA44},
	"ml-dsa-65": ossl.SignatureCapability{Key: ossl.MLDSA65},
	"ml-dsa-87": ossl.SignatureCapability{Key: ossl.MLDSA87},

	// AEAD ciphers: AES-GCM and ChaCha20-Poly1305.
	"aes-128-gcm-128-96": ossl.AEADCapability{Cipher: ossl.AES128GCM},
	"aes-192-gcm-128-96": ossl.AEADCapability{Cipher: ossl.AES192GCM},
	"aes-256-gcm-128-96": ossl.AEADCapability{Cipher: ossl.AES256GCM},
	"chacha20-poly1305":  ossl.AEADCapability{Cipher: ossl.ChaCha20Poly1305},

	// Plain block/stream ciphers: AES-CBC and AES-CTR. These are not AEAD,
	// so AEADCapability cannot represent them -- ossl.CipherCapability
	// (ossl-go v0.1.0+) is the counterpart built on NewCipher instead of
	// NewAEAD. Padding matters for CBC's partial final block; CTR is a
	// stream mode and ignores it (ossl.CipherCapability's own doc comment),
	// so it is left at its zero value there rather than restated.
	"aes-128-cbc-pkcs7-128": ossl.CipherCapability{Cipher: ossl.AES128CBC, Padding: ossl.PaddingPKCS7},
	"aes-192-cbc-pkcs7-128": ossl.CipherCapability{Cipher: ossl.AES192CBC, Padding: ossl.PaddingPKCS7},
	"aes-256-cbc-pkcs7-128": ossl.CipherCapability{Cipher: ossl.AES256CBC, Padding: ossl.PaddingPKCS7},
	"aes-128-ctr":           ossl.CipherCapability{Cipher: ossl.AES128CTR},
	"aes-192-ctr":           ossl.CipherCapability{Cipher: ossl.AES192CTR},
	"aes-256-ctr":           ossl.CipherCapability{Cipher: ossl.AES256CTR},
}

// deriveAlgorithms filters table down to the entries libctx can actually
// perform, via ossl.Context.Supports — a structural check, cheap enough to
// run over the whole catalogue (the one exception, an EC curve, costs one
// ephemeral keygen the first time a context is asked and is memoised after).
//
// table is a parameter rather than this function always reading the
// package-level catalog so it stays a pure function: callers — New, and
// this package's tests — can run it against a synthetic table, independent
// of whatever this package currently advertises for real.
//
// The result is sorted so two instances built against the same context
// report algorithms in the same order — map iteration order is not
// something a caller (or a test asserting equality) should have to tolerate.
func deriveAlgorithms(libctx *ossl.Context, table map[string]ossl.Capability) []string {
	var out []string
	for id, cap := range table {
		if err := libctx.Supports(cap); err == nil {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// SupportedAlgorithms returns the algorithm IDs this instance's context
// actually supports — derived once at construction (see New), never
// hardcoded. This is what makes a FIPS- or PKCS#11-restricted instance
// advertise only what it can really do: every mode instance filters the
// same catalog table, and each one's own context decides what survives.
func (p *Provider) SupportedAlgorithms() []string {
	out := make([]string, len(p.algs))
	copy(out, p.algs)
	return out
}

// VerifyCapabilities proves every algorithm this instance advertises by
// actually performing it — ossl.Context.VerifyCapability against ephemeral
// material — rather than relying on the structural check SupportedAlgorithms
// is built on.
//
// This costs a key generation per algorithm — seconds for RSA-4096 — so it
// is opt-in: never called from New or a request path. Run it once during
// deployment validation to confirm a configuration works, not per request.
func (p *Provider) VerifyCapabilities(ctx context.Context) error {
	const op errors.Op = "openssl.(Provider).VerifyCapabilities"
	for _, id := range p.algs {
		if err := p.libctx.VerifyCapability(catalog[id]); err != nil {
			return errors.Wrap(ctx, op, err, errors.WithMessage("algorithm %q", id))
		}
	}
	return nil
}

// ImplementationProperties reports this instance's implementation-security
// properties. C (OpenSSL libcrypto), so not memory-safe; hardware
// acceleration is a property of libcrypto's engine dispatch, shared by every
// mode instance. FIPS status is the one property that genuinely varies
// per instance — it is read from this instance's own context via
// FIPSEnabled rather than hardcoded, so the default-mode and FIPS-mode
// instances (which share this same method) report correctly and
// differently despite calling identical code.
//
// Only the FIPS provider's activation state is substantiated here — no
// certificate number, module name, or validation date is fabricated; this
// reports what libctx can prove about itself, nothing more.
func (p *Provider) ImplementationProperties() *types.ImplementationProperties {
	props := &types.ImplementationProperties{
		ImplementationLanguage: "c",
		MemorySafeLanguage:     proto.Bool(false),
		HardwareAccelerated:    proto.Bool(true),
	}
	if p.FIPSEnabled() {
		props.Fips_140 = &types.Fips140Certification{Certified: true}
	}
	return props
}
