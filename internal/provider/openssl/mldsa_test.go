package openssl_test

import (
	"context"
	"testing"

	"github.com/agile-crypto/ossl-go/ossl"

	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	providerpb "github.com/agile-crypto/citius-server/gen/go/server/provider"
	"github.com/agile-crypto/citius-server/internal/errors"
	"github.com/agile-crypto/citius-server/internal/provider/openssl"
	"github.com/agile-crypto/citius-server/internal/provider/software"
)

func mlDSADetails(ps types.MlDsaParameterSet) *types.AlgorithmDetails {
	return &types.AlgorithmDetails{
		Algorithm: &types.AlgorithmDetails_MlDsa{MlDsa: &types.MlDsaParams{ParameterSet: ps}},
	}
}

func TestGenerateKey_MLDSA_happyPath(t *testing.T) {
	tests := []struct {
		name string
		alg  *types.AlgorithmDetails
	}{
		{"ml-dsa-44", mlDSADetails(types.MlDsaParameterSet_ML_DSA_44)},
		{"ml-dsa-65", mlDSADetails(types.MlDsaParameterSet_ML_DSA_65)},
		{"ml-dsa-87", mlDSADetails(types.MlDsaParameterSet_ML_DSA_87)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := openssl.New(context.Background())
			if err != nil {
				t.Fatalf("openssl.New: %v", err)
			}
			defer p.Close()

			resp, err := p.GenerateKey(context.Background(), &providerpb.GenerateKeyRequest{Algorithm: tt.alg})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			if len(resp.GetPublicKeyBytes()) == 0 {
				t.Error("expected non-empty public key bytes")
			}
			if len(resp.GetKeyMaterial()) == 0 {
				t.Error("expected non-empty key material")
			}
			if got := resp.GetKeyMaterialEncoding(); got != providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8 {
				t.Errorf("KeyMaterialEncoding: got %v want PKCS8", got)
			}
			// RAW, not SPKI -- see generateMLDSAKey's doc comment for why
			// this one algorithm's public key encoding differs from every
			// other case in this package.
			if got := resp.GetPublicKeyEncoding(); got != providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_RAW {
				t.Errorf("PublicKeyEncoding: got %v want RAW", got)
			}
		})
	}
}

func TestGenerateKey_MLDSA_keysAreUnique(t *testing.T) {
	p, err := openssl.New(context.Background())
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	ctx := context.Background()
	alg := mlDSADetails(types.MlDsaParameterSet_ML_DSA_65)
	r1, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey (1st): %v", err)
	}
	r2, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey (2nd): %v", err)
	}

	if string(r1.GetPublicKeyBytes()) == string(r2.GetPublicKeyBytes()) {
		t.Error("two generated keys should not be identical")
	}
}

// TestGenerateKey_MLDSA_sameProviderRoundTrip proves openssl-generated
// material parses back through openssl's own ossl-go parsers, independent
// of the cross-provider question TestGenerateKey_MLDSA_crossProviderInterop
// covers separately.
func TestGenerateKey_MLDSA_sameProviderRoundTrip(t *testing.T) {
	ctx := context.Background()

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	resp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: mlDSADetails(types.MlDsaParameterSet_ML_DSA_65)})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	libctx, err := ossl.NewContext()
	if err != nil {
		t.Fatalf("ossl.NewContext: %v", err)
	}
	defer libctx.Close()

	privKey, err := libctx.ParsePKCS8PrivateKey(resp.GetKeyMaterial())
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey could not parse openssl's own ML-DSA PKCS8 material: %v", err)
	}
	defer privKey.Close()
	if got := privKey.Type(); got != ossl.MLDSA65 {
		t.Errorf("parsed private key type: got %q want %q", got, ossl.MLDSA65)
	}

	pubKey, err := libctx.ParseRawPublicKey(ossl.MLDSA65, resp.GetPublicKeyBytes())
	if err != nil {
		t.Fatalf("ParseRawPublicKey could not parse openssl's own ML-DSA raw public material: %v", err)
	}
	defer pubKey.Close()
	if got := pubKey.Type(); got != ossl.MLDSA65 {
		t.Errorf("parsed public key type: got %q want %q", got, ossl.MLDSA65)
	}
}

// TestGenerateKey_MLDSA_crossProviderInterop
// Bidirectional interop, verified with a real
// sign-then-verify round trip, not just byte-length label comparison.
//
// This needed two things this package's other algorithms don't: OpenSSL's
// PKCS8 output for ML-DSA looks nothing like software's by byte length
// (4098 bytes vs software's ~54), but that is because OpenSSL uses the
// draft-ietf-lamps-dilithium-certificates "both seed and expanded key"
// CHOICE rather than an incompatible encoding — CIRCL's parser (what
// software uses) explicitly supports that CHOICE, deriving the same key
// from the embedded seed. And the public key must be declared RAW, not
// SPKI like every other algorithm here, because software's ML-DSA verify
// path has no SPKI parser at all, only CIRCL's raw packed format — see
// generateMLDSAKey's doc comment for the full explanation.
func TestGenerateKey_MLDSA_crossProviderInterop(t *testing.T) {
	ctx := context.Background()
	alg := mlDSADetails(types.MlDsaParameterSet_ML_DSA_65)
	msg := []byte("cross-provider interop probe")

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()
	sw := software.New()

	// Direction 1: openssl generates the key; software signs and verifies
	// with it. This is a genuine end-to-end round trip, not just a parse
	// check, because software's Sign/Verify already exist.
	osslResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("openssl GenerateKey: %v", err)
	}
	signResp, err := sw.Sign(ctx, &providerpb.SignRequest{
		Algorithm:           alg,
		KeyMaterial:         osslResp.GetKeyMaterial(),
		KeyMaterialEncoding: providerpb.PrivateKeyEncoding_PRIVATE_KEY_ENCODING_PKCS8,
		Input:               msg,
	})
	if err != nil {
		t.Fatalf("software.Sign using openssl-generated ML-DSA key: %v", err)
	}
	verifyResp, err := sw.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           alg,
		KeyMaterial:         osslResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: providerpb.PublicKeyEncoding_PUBLIC_KEY_ENCODING_RAW,
		Input:               msg,
		Signature:           signResp.GetSignature(),
	})
	if err != nil {
		t.Fatalf("software.Verify using openssl-generated ML-DSA public key: %v", err)
	}
	if !verifyResp.GetValid() {
		t.Error("software rejected a genuinely valid signature over an openssl-generated ML-DSA key")
	}

	// Direction 2: software generates the key; ossl-go's generic parsers
	// (what openssl's own Sign/Verify will use once they exist) accept it.
	swResp, err := sw.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("software GenerateKey: %v", err)
	}
	libctx, err := ossl.NewContext()
	if err != nil {
		t.Fatalf("ossl.NewContext: %v", err)
	}
	defer libctx.Close()

	privKey, err := libctx.ParsePKCS8PrivateKey(swResp.GetKeyMaterial())
	if err != nil {
		t.Errorf("ossl-go ParsePKCS8PrivateKey could not parse software-generated seed-only PKCS8 material: %v", err)
	} else {
		defer privKey.Close()
	}
	pubKey, err := libctx.ParseRawPublicKey(ossl.MLDSA65, swResp.GetPublicKeyBytes())
	if err != nil {
		t.Errorf("ossl-go ParseRawPublicKey could not parse software-generated raw public material: %v", err)
	} else {
		defer pubKey.Close()
	}
}

// TestSign_MLDSA_verifiesWithSoftware is the sign-side cross-check the plan
// requires, over every advertised parameter set, with no domain context --
// proving the signature is genuinely valid, not just that Sign returned
// without an error.
func TestSign_MLDSA_verifiesWithSoftware(t *testing.T) {
	tests := []struct {
		name string
		ps   types.MlDsaParameterSet
	}{
		{"ml-dsa-44", types.MlDsaParameterSet_ML_DSA_44},
		{"ml-dsa-65", types.MlDsaParameterSet_ML_DSA_65},
		{"ml-dsa-87", types.MlDsaParameterSet_ML_DSA_87},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			alg := mlDSADetails(tt.ps)

			p, err := openssl.New(ctx)
			if err != nil {
				t.Fatalf("openssl.New: %v", err)
			}
			defer p.Close()

			keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}

			message := []byte("sign with openssl, verify with software")
			signResp, err := p.Sign(ctx, &providerpb.SignRequest{
				Algorithm:           alg,
				KeyMaterial:         keyResp.GetKeyMaterial(),
				KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
				Input:               message,
				ScopeParams:         signRequestNoContext(),
			})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}

			sw := software.New()
			verifyResp, err := sw.Verify(ctx, &providerpb.VerifyRequest{
				Algorithm:           alg,
				KeyMaterial:         keyResp.GetPublicKeyBytes(),
				KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
				Input:               message,
				Signature:           signResp.GetSignature(),
				ScopeParams:         verifyRequestNoContext(),
			})
			if err != nil {
				t.Fatalf("software Verify: %v", err)
			}
			if !verifyResp.GetValid() {
				t.Error("software rejected a signature openssl produced")
			}
		})
	}
}

// TestSign_MLDSA_honorsDomainContext proves signMLDSA genuinely threads
// req.GetDomainContext().GetContext() into the signature rather than
// ignoring it: software must accept the signature when verifying with the
// same context, and reject it -- a different signature entirely, not a
// verification-time filter -- when verifying with a different one.
func TestSign_MLDSA_honorsDomainContext(t *testing.T) {
	ctx := context.Background()
	alg := mlDSADetails(types.MlDsaParameterSet_ML_DSA_65)

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	message := []byte("message signed under a specific domain context")
	domainContext := []byte("citius-test-context")

	signResp, err := p.Sign(ctx, &providerpb.SignRequest{
		Algorithm:           alg,
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Input:               message,
		ScopeParams:         signRequestDomainContext(domainContext),
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	sw := software.New()

	matchResp, err := sw.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           alg,
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               message,
		Signature:           signResp.GetSignature(),
		ScopeParams:         verifyRequestDomainContext(domainContext),
	})
	if err != nil {
		t.Fatalf("software Verify (matching context): %v", err)
	}
	if !matchResp.GetValid() {
		t.Error("software rejected a signature verified with the same domain context it was signed under")
	}

	mismatchResp, err := sw.Verify(ctx, &providerpb.VerifyRequest{
		Algorithm:           alg,
		KeyMaterial:         keyResp.GetPublicKeyBytes(),
		KeyMaterialEncoding: keyResp.GetPublicKeyEncoding(),
		Input:               message,
		Signature:           signResp.GetSignature(),
		ScopeParams:         verifyRequestDomainContext([]byte("a-different-context")),
	})
	if err != nil {
		t.Fatalf("software Verify (mismatched context): %v", err)
	}
	if mismatchResp.GetValid() {
		t.Error("software accepted a signature under a domain context it was never signed with -- signMLDSA is not threading the context")
	}
}

// TestSign_MLDSA_contextTooLong is the negative control for
// checkMLDSAContextLength: a domain separation context over the FIPS 204
// §3.2 255-byte maximum must be rejected with CodeInvalidArgument.
func TestSign_MLDSA_contextTooLong(t *testing.T) {
	ctx := context.Background()
	alg := mlDSADetails(types.MlDsaParameterSet_ML_DSA_65)

	p, err := openssl.New(ctx)
	if err != nil {
		t.Fatalf("openssl.New: %v", err)
	}
	defer p.Close()

	keyResp, err := p.GenerateKey(ctx, &providerpb.GenerateKeyRequest{Algorithm: alg})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	overLong := make([]byte, 256)
	_, err = p.Sign(ctx, &providerpb.SignRequest{
		Algorithm:           alg,
		KeyMaterial:         keyResp.GetKeyMaterial(),
		KeyMaterialEncoding: keyResp.GetKeyMaterialEncoding(),
		Input:               []byte("message"),
		ScopeParams:         signRequestDomainContext(overLong),
	})
	if !errors.IsInvalidArgument(err) {
		t.Errorf("expected CodeInvalidArgument for a 256-byte domain context, got: %v", err)
	}
}
