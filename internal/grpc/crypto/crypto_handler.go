package cryptogrpc

import (
	"context"

	messagespb "github.com/agile-crypto/citius-server/gen/go/api/messages"
	servicespb "github.com/agile-crypto/citius-server/gen/go/api/services"
	"github.com/agile-crypto/citius-server/internal/crypto"
	engerr "github.com/agile-crypto/citius-server/internal/errors"
	grpcstatus "github.com/agile-crypto/citius-server/internal/grpc/status"
	"github.com/agile-crypto/citius-server/internal/service"
)

// CryptoHandler serves services.CryptoService — the one-shot data-plane RPCs
// that operate with an existing key.
//
// It depends only on a CryptoOrchestratorFactory; key lifecycle and policy management live
// in their own handlers with their own dependencies. Immutable after
// construction, safe for concurrent use.
//
// The authorization check is supplied by the wiring — an always-allow closure
// when the deployment runs without authorization — which is why this package
// does not import internal/auth.
type CryptoHandler struct {
	crypto       service.CryptoOrchestratorFactory
	authorizeKey grpcstatus.AuthorizeKeyName
	servicespb.UnimplementedCryptoServiceServer
}

var _ servicespb.CryptoServiceServer = (*CryptoHandler)(nil)

const cryptoHandlerOp = engerr.Op("grpc.(CryptoHandler)")

// Encrypt handles the Encrypt RPC. The provider output (IV/nonce/tag) is
// returned in the response metadata and must be echoed back on Decrypt.
func (h *CryptoHandler) Encrypt(ctx context.Context, req *messagespb.EncryptRequest) (*messagespb.EncryptResponse, error) {
	const encryptOp engerr.Op = cryptoHandlerOp + ".Encrypt"

	if err := h.authorizeKey(ctx, encryptOp, req.GetKeyName()); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}

	ops, err := h.crypto(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, encryptOp, err))
	}

	encryptReq := crypto.EncryptRequest{
		KeyName:   req.GetKeyName(),
		Plaintext: req.GetPlaintext(),
	}
	extractEncryptScopeParams(req.GetScopeParams(), &encryptReq)

	result, err := ops.Encrypt(ctx, encryptReq)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, encryptOp, err))
	}

	return &messagespb.EncryptResponse{
		Ciphertext: result.Ciphertext,
		Metadata: &messagespb.OperationMetadata{
			KeyVersion:     result.KeyVersion,
			ProviderOutput: result.Output,
		},
	}, nil
}

// Decrypt handles the Decrypt RPC, consuming the key version and provider
// output that Encrypt returned.
func (h *CryptoHandler) Decrypt(ctx context.Context, req *messagespb.DecryptRequest) (*messagespb.DecryptResponse, error) {
	const decryptOp engerr.Op = cryptoHandlerOp + ".Decrypt"

	if err := h.authorizeKey(ctx, decryptOp, req.GetKeyName()); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}

	ops, err := h.crypto(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, decryptOp, err))
	}

	decryptReq := crypto.DecryptRequest{
		KeyName:    req.GetKeyName(),
		KeyVersion: req.GetMetadata().GetKeyVersion(),
		Ciphertext: req.GetCiphertext(),
		Output:     req.GetMetadata().GetProviderOutput(),
	}
	extractDecryptScopeParams(req.GetScopeParams(), &decryptReq)

	result, err := ops.Decrypt(ctx, decryptReq)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, decryptOp, err))
	}

	return &messagespb.DecryptResponse{
		Plaintext: result.Plaintext,
		Metadata: &messagespb.OperationMetadata{
			ProviderOutput: result.Output,
		},
	}, nil
}

// Sign handles the Sign RPC: hash-then-sign over the supplied message.
//
//	messages.SignRequest.scope_params => crypto.SignRequest.{NoContext,DomainContext,VendorContext}
func (h *CryptoHandler) Sign(ctx context.Context, req *messagespb.SignRequest) (*messagespb.SignResponse, error) {
	const signOp engerr.Op = cryptoHandlerOp + ".Sign"

	if err := h.authorizeKey(ctx, signOp, req.GetKeyName()); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}

	ops, err := h.crypto(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, signOp, err))
	}

	signReq := crypto.SignRequest{
		KeyName: req.GetKeyName(),
		Payload: req.GetInput(),
	}
	extractSigningScopeParams(req.GetScopeParams(), &signReq)

	result, err := ops.Sign(ctx, signReq)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, signOp, err))
	}

	// Wrap ProviderOutput into OperationMetadata.
	return &messagespb.SignResponse{
		Signature: result.Signature,
		Metadata: &messagespb.OperationMetadata{
			KeyVersion:     result.KeyVersion,
			ProviderOutput: result.Output,
			//TODO: Add user context and API version
		},
	}, nil
}

// Verify handles the Verify RPC. An invalid signature is not an error: it
// returns Valid=false with a nil error.
func (h *CryptoHandler) Verify(ctx context.Context, req *messagespb.VerifyRequest) (*messagespb.VerifyResponse, error) {
	const verifyOp engerr.Op = cryptoHandlerOp + ".Verify"

	if err := h.authorizeKey(ctx, verifyOp, req.GetKeyName()); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}

	ops, err := h.crypto(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, verifyOp, err))
	}

	//TODO: Check API version in req.GetMetadata() and reject if unsupported.

	verifyReq := crypto.VerifyRequest{
		KeyName:    req.GetKeyName(),
		Payload:    req.GetInput(),
		Signature:  req.GetSignature(),
		KeyVersion: req.GetMetadata().GetKeyVersion(),
		Output:     req.GetMetadata().GetProviderOutput(),
	}
	extractVerifyScopeParams(req.GetScopeParams(), &verifyReq)

	result, err := ops.Verify(ctx, verifyReq)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, verifyOp, err))
	}

	return &messagespb.VerifyResponse{
		Valid: result.Valid,
		Metadata: &messagespb.OperationMetadata{
			ProviderOutput: result.Output,
		},
	}, nil
}

// DigestSign handles the DigestSign RPC — signing a pre-computed digest
// rather than hashing the message here.
func (h *CryptoHandler) DigestSign(ctx context.Context, req *messagespb.DigestSignRequest) (*messagespb.DigestSignResponse, error) {
	const digestSignOp engerr.Op = cryptoHandlerOp + ".DigestSign"

	if err := h.authorizeKey(ctx, digestSignOp, req.GetKeyName()); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}

	ops, err := h.crypto(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, digestSignOp, err))
	}

	digestSignReq := crypto.DigestSignRequest{
		KeyName:          req.GetKeyName(),
		Digest:           req.GetDigest(),
		HashAlgorithm:    req.GetHashAlgorithm(),
		HashAlgorithmOID: req.GetHashAlgorithmOid(),
	}
	extractDigestSignScopeParams(req.GetScopeParams(), &digestSignReq)

	result, err := ops.DigestSign(ctx, digestSignReq)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, digestSignOp, err))
	}

	return &messagespb.DigestSignResponse{
		Signature: result.Signature,
		Metadata: &messagespb.OperationMetadata{
			KeyVersion:     result.KeyVersion,
			ProviderOutput: result.Output,
		},
	}, nil
}

// DigestVerify handles the DigestVerify RPC, the mirror of DigestSign. An
// invalid signature returns Valid=false with a nil error.
func (h *CryptoHandler) DigestVerify(ctx context.Context, req *messagespb.DigestVerifyRequest) (*messagespb.DigestVerifyResponse, error) {
	const digestVerifyOp engerr.Op = cryptoHandlerOp + ".DigestVerify"

	if err := h.authorizeKey(ctx, digestVerifyOp, req.GetKeyName()); err != nil {
		return nil, grpcstatus.ToStatusError(err)
	}

	ops, err := h.crypto(ctx)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, digestVerifyOp, err))
	}

	digestVerifyReq := crypto.DigestVerifyRequest{
		KeyName:          req.GetKeyName(),
		KeyVersion:       req.GetMetadata().GetKeyVersion(),
		Digest:           req.GetDigest(),
		Signature:        req.GetSignature(),
		HashAlgorithm:    req.GetHashAlgorithm(),
		HashAlgorithmOID: req.GetHashAlgorithmOid(),
		Output:           req.GetMetadata().GetProviderOutput(),
	}
	extractDigestVerifyScopeParams(req.GetScopeParams(), &digestVerifyReq)

	result, err := ops.DigestVerify(ctx, digestVerifyReq)
	if err != nil {
		return nil, grpcstatus.ToStatusError(engerr.Wrap(ctx, digestVerifyOp, err))
	}

	return &messagespb.DigestVerifyResponse{
		Valid: result.Valid,
		Metadata: &messagespb.OperationMetadata{
			ProviderOutput: result.Output,
		},
	}, nil
}

// GenerateMAC handles the GenerateMAC RPC.
func (h *CryptoHandler) GenerateMAC(ctx context.Context, req *messagespb.GenerateMACRequest) (*messagespb.GenerateMACResponse, error) {
	return h.UnimplementedCryptoServiceServer.GenerateMAC(ctx, req)
}

// VerifyMAC handles the VerifyMAC RPC.
func (h *CryptoHandler) VerifyMAC(ctx context.Context, req *messagespb.VerifyMACRequest) (*messagespb.VerifyMACResponse, error) {
	return h.UnimplementedCryptoServiceServer.VerifyMAC(ctx, req)
}

// Digest handles the Digest RPC.
func (h *CryptoHandler) Digest(ctx context.Context, req *messagespb.DigestRequest) (*messagespb.DigestResponse, error) {
	return h.UnimplementedCryptoServiceServer.Digest(ctx, req)
}

// Xof handles the Xof RPC.
func (h *CryptoHandler) Xof(ctx context.Context, req *messagespb.XofRequest) (*messagespb.XofResponse, error) {
	return h.UnimplementedCryptoServiceServer.Xof(ctx, req)
}

// GenerateRandom handles the GenerateRandom RPC.
func (h *CryptoHandler) GenerateRandom(ctx context.Context, req *messagespb.GenerateRandomRequest) (*messagespb.GenerateRandomResponse, error) {
	return h.UnimplementedCryptoServiceServer.GenerateRandom(ctx, req)
}

// SeedRandom handles the SeedRandom RPC.
func (h *CryptoHandler) SeedRandom(ctx context.Context, req *messagespb.SeedRandomRequest) (*messagespb.SeedRandomResponse, error) {
	return h.UnimplementedCryptoServiceServer.SeedRandom(ctx, req)
}

// extractSigningScopeParams maps the proto scope_params oneof to Go pointer fields.
// The proto oneof interface (isSignRequest_ScopeParams) is unexported, so we accept any.
// Concrete wrapper types SignRequest_NoContext / _DomainContext / _VendorContext are exported.
func extractSigningScopeParams(sp any, req *crypto.SignRequest) {
	switch v := sp.(type) {
	case *messagespb.SignRequest_NoContext:
		req.NoContext = v.NoContext
	case *messagespb.SignRequest_DomainContext:
		req.DomainContext = v.DomainContext
	case *messagespb.SignRequest_VendorContext:
		req.VendorContext = v.VendorContext
	default:
		// nil or unrecognised variant — downstream validation will report the issue.
	}
}

// extractVerifyScopeParams maps the proto scope_params oneof for VerifyRequest.
// Same pattern as extractSigningScopeParams but uses VerifyRequest_* wrapper types.
func extractVerifyScopeParams(sp any, req *crypto.VerifyRequest) {
	switch v := sp.(type) {
	case *messagespb.VerifyRequest_NoContext:
		req.NoContext = v.NoContext
	case *messagespb.VerifyRequest_DomainContext:
		req.DomainContext = v.DomainContext
	case *messagespb.VerifyRequest_VendorContext:
		req.VendorContext = v.VendorContext
	default:
		// nil or unrecognised variant.
	}
}

// extractEncryptScopeParams maps the proto scope_params oneof for EncryptRequest
// onto crypto.EncryptionScopeFields. Same pattern as extractSigningScopeParams but
// uses EncryptRequest_* wrapper types.
func extractEncryptScopeParams(sp any, req *crypto.EncryptRequest) {
	switch v := sp.(type) {
	case *messagespb.EncryptRequest_NoParams:
		req.NoParams = v.NoParams
	case *messagespb.EncryptRequest_AeadParams:
		req.AeadParams = v.AeadParams
	case *messagespb.EncryptRequest_XtsParams:
		req.XtsParams = v.XtsParams
	case *messagespb.EncryptRequest_AsymmetricParams:
		req.AsymmetricParams = v.AsymmetricParams
	case *messagespb.EncryptRequest_VendorParams:
		req.VendorParams = v.VendorParams
	default:
		// nil or unrecognised variant — downstream validation will report the issue.
	}
}

// extractDecryptScopeParams maps the proto scope_params oneof for DecryptRequest
// onto crypto.EncryptionScopeFields. Same pattern as extractEncryptScopeParams but
// uses DecryptRequest_* wrapper types.
func extractDecryptScopeParams(sp any, req *crypto.DecryptRequest) {
	switch v := sp.(type) {
	case *messagespb.DecryptRequest_NoParams:
		req.NoParams = v.NoParams
	case *messagespb.DecryptRequest_AeadParams:
		req.AeadParams = v.AeadParams
	case *messagespb.DecryptRequest_XtsParams:
		req.XtsParams = v.XtsParams
	case *messagespb.DecryptRequest_AsymmetricParams:
		req.AsymmetricParams = v.AsymmetricParams
	case *messagespb.DecryptRequest_VendorParams:
		req.VendorParams = v.VendorParams
	default:
		// nil or unrecognised variant — downstream validation will report the issue.
	}
}

// extractDigestSignScopeParams maps the proto scope_params oneof for
// DigestSignRequest onto crypto.SignatureScopeFields. Same pattern as
// extractSigningScopeParams but uses DigestSignRequest_* wrapper types.
func extractDigestSignScopeParams(sp any, req *crypto.DigestSignRequest) {
	switch v := sp.(type) {
	case *messagespb.DigestSignRequest_NoContext:
		req.NoContext = v.NoContext
	case *messagespb.DigestSignRequest_DomainContext:
		req.DomainContext = v.DomainContext
	case *messagespb.DigestSignRequest_VendorContext:
		req.VendorContext = v.VendorContext
	default:
		// nil or unrecognised variant — downstream validation will report the issue.
	}
}

// extractDigestVerifyScopeParams maps the proto scope_params oneof for
// DigestVerifyRequest onto crypto.SignatureScopeFields. Same pattern as
// extractDigestSignScopeParams but uses DigestVerifyRequest_* wrapper types.
func extractDigestVerifyScopeParams(sp any, req *crypto.DigestVerifyRequest) {
	switch v := sp.(type) {
	case *messagespb.DigestVerifyRequest_NoContext:
		req.NoContext = v.NoContext
	case *messagespb.DigestVerifyRequest_DomainContext:
		req.DomainContext = v.DomainContext
	case *messagespb.DigestVerifyRequest_VendorContext:
		req.VendorContext = v.VendorContext
	default:
		// nil or unrecognised variant — downstream validation will report the issue.
	}
}
