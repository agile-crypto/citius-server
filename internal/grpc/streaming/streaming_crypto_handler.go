package streamgrpc

import (
	"context"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
	servicespb "github.com/agile-crypto/citius-api-go/gen/go/services"
	"github.com/agile-crypto/citius-core/service"
)

// StreamingCryptoHandler serves services.StreamingCryptoService — the
// multi-part (Init/Update/Final) and message-oriented forms of every operation
// in CryptoService.
//
// Despite the name, every RPC is unary: the "stream" is the caller's data, held
// across calls by a server-side session that the Init RPCs open and the Final
// RPCs close.
//
// That session state is the open question for this handler's wiring. A session
// outlives the request that created it, so it cannot come from a per-request
// capability the way an orchestrator does; it needs a process-wide, concurrency-
// safe session manager whose entries are bound to the scope that opened them.
// No such core type exists yet, so this handler currently declares only its
// CryptoOrchestratorFactory dependency and the session manager is left as a TODO — to be
// settled when we decide the per-service bundles.
//
// Immutable after construction, safe for concurrent use.
type StreamingCryptoHandler struct {
	crypto service.CryptoOrchestratorFactory
	servicespb.UnimplementedStreamingCryptoServiceServer
}

var _ servicespb.StreamingCryptoServiceServer = (*StreamingCryptoHandler)(nil)

// const streamingCryptoHandlerOp = engerr.Op("grpc.(StreamingCryptoHandler)")

// EncryptInit handles the EncryptInit RPC.
func (h *StreamingCryptoHandler) EncryptInit(ctx context.Context, req *messagespb.EncryptInitRequest) (*messagespb.EncryptInitResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.EncryptInit(ctx, req)
}

// EncryptUpdate handles the EncryptUpdate RPC.
func (h *StreamingCryptoHandler) EncryptUpdate(ctx context.Context, req *messagespb.EncryptUpdateRequest) (*messagespb.EncryptUpdateResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.EncryptUpdate(ctx, req)
}

// EncryptFinal handles the EncryptFinal RPC.
func (h *StreamingCryptoHandler) EncryptFinal(ctx context.Context, req *messagespb.EncryptFinalRequest) (*messagespb.EncryptFinalResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.EncryptFinal(ctx, req)
}

// DecryptInit handles the DecryptInit RPC.
func (h *StreamingCryptoHandler) DecryptInit(ctx context.Context, req *messagespb.DecryptInitRequest) (*messagespb.DecryptInitResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DecryptInit(ctx, req)
}

// DecryptUpdate handles the DecryptUpdate RPC.
func (h *StreamingCryptoHandler) DecryptUpdate(ctx context.Context, req *messagespb.DecryptUpdateRequest) (*messagespb.DecryptUpdateResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DecryptUpdate(ctx, req)
}

// DecryptFinal handles the DecryptFinal RPC.
func (h *StreamingCryptoHandler) DecryptFinal(ctx context.Context, req *messagespb.DecryptFinalRequest) (*messagespb.DecryptFinalResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DecryptFinal(ctx, req)
}

// EncryptMessageInit handles the EncryptMessageInit RPC.
func (h *StreamingCryptoHandler) EncryptMessageInit(ctx context.Context, req *messagespb.EncryptMessageInitRequest) (*messagespb.EncryptMessageInitResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.EncryptMessageInit(ctx, req)
}

// EncryptMessage handles the EncryptMessage RPC.
func (h *StreamingCryptoHandler) EncryptMessage(ctx context.Context, req *messagespb.EncryptMessageRequest) (*messagespb.EncryptMessageResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.EncryptMessage(ctx, req)
}

// EncryptMessageBegin handles the EncryptMessageBegin RPC.
func (h *StreamingCryptoHandler) EncryptMessageBegin(ctx context.Context, req *messagespb.EncryptMessageBeginRequest) (*messagespb.EncryptMessageBeginResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.EncryptMessageBegin(ctx, req)
}

// EncryptMessageNext handles the EncryptMessageNext RPC.
func (h *StreamingCryptoHandler) EncryptMessageNext(ctx context.Context, req *messagespb.EncryptMessageNextRequest) (*messagespb.EncryptMessageNextResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.EncryptMessageNext(ctx, req)
}

// EncryptMessageFinal handles the EncryptMessageFinal RPC.
func (h *StreamingCryptoHandler) EncryptMessageFinal(ctx context.Context, req *messagespb.EncryptMessageFinalRequest) (*messagespb.EncryptMessageFinalResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.EncryptMessageFinal(ctx, req)
}

// DecryptMessageInit handles the DecryptMessageInit RPC.
func (h *StreamingCryptoHandler) DecryptMessageInit(ctx context.Context, req *messagespb.DecryptMessageInitRequest) (*messagespb.DecryptMessageInitResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DecryptMessageInit(ctx, req)
}

// DecryptMessage handles the DecryptMessage RPC.
func (h *StreamingCryptoHandler) DecryptMessage(ctx context.Context, req *messagespb.DecryptMessageRequest) (*messagespb.DecryptMessageResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DecryptMessage(ctx, req)
}

// DecryptMessageBegin handles the DecryptMessageBegin RPC.
func (h *StreamingCryptoHandler) DecryptMessageBegin(ctx context.Context, req *messagespb.DecryptMessageBeginRequest) (*messagespb.DecryptMessageBeginResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DecryptMessageBegin(ctx, req)
}

// DecryptMessageNext handles the DecryptMessageNext RPC.
func (h *StreamingCryptoHandler) DecryptMessageNext(ctx context.Context, req *messagespb.DecryptMessageNextRequest) (*messagespb.DecryptMessageNextResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DecryptMessageNext(ctx, req)
}

// DecryptMessageFinal handles the DecryptMessageFinal RPC.
func (h *StreamingCryptoHandler) DecryptMessageFinal(ctx context.Context, req *messagespb.DecryptMessageFinalRequest) (*messagespb.DecryptMessageFinalResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DecryptMessageFinal(ctx, req)
}

// SignInit handles the SignInit RPC.
func (h *StreamingCryptoHandler) SignInit(ctx context.Context, req *messagespb.SignInitRequest) (*messagespb.SignInitResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.SignInit(ctx, req)
}

// SignUpdate handles the SignUpdate RPC.
func (h *StreamingCryptoHandler) SignUpdate(ctx context.Context, req *messagespb.SignUpdateRequest) (*messagespb.SignUpdateResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.SignUpdate(ctx, req)
}

// SignFinal handles the SignFinal RPC.
func (h *StreamingCryptoHandler) SignFinal(ctx context.Context, req *messagespb.SignFinalRequest) (*messagespb.SignFinalResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.SignFinal(ctx, req)
}

// VerifyInit handles the VerifyInit RPC.
func (h *StreamingCryptoHandler) VerifyInit(ctx context.Context, req *messagespb.VerifyInitRequest) (*messagespb.VerifyInitResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.VerifyInit(ctx, req)
}

// VerifyUpdate handles the VerifyUpdate RPC.
func (h *StreamingCryptoHandler) VerifyUpdate(ctx context.Context, req *messagespb.VerifyUpdateRequest) (*messagespb.VerifyUpdateResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.VerifyUpdate(ctx, req)
}

// VerifyFinal handles the VerifyFinal RPC.
func (h *StreamingCryptoHandler) VerifyFinal(ctx context.Context, req *messagespb.VerifyFinalRequest) (*messagespb.VerifyFinalResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.VerifyFinal(ctx, req)
}

// SignMessageInit handles the SignMessageInit RPC.
func (h *StreamingCryptoHandler) SignMessageInit(ctx context.Context, req *messagespb.SignMessageInitRequest) (*messagespb.SignMessageInitResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.SignMessageInit(ctx, req)
}

// SignMessage handles the SignMessage RPC.
func (h *StreamingCryptoHandler) SignMessage(ctx context.Context, req *messagespb.SignMessageRequest) (*messagespb.SignMessageResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.SignMessage(ctx, req)
}

// SignMessageBegin handles the SignMessageBegin RPC.
func (h *StreamingCryptoHandler) SignMessageBegin(ctx context.Context, req *messagespb.SignMessageBeginRequest) (*messagespb.SignMessageBeginResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.SignMessageBegin(ctx, req)
}

// SignMessageNext handles the SignMessageNext RPC.
func (h *StreamingCryptoHandler) SignMessageNext(ctx context.Context, req *messagespb.SignMessageNextRequest) (*messagespb.SignMessageNextResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.SignMessageNext(ctx, req)
}

// SignMessageFinal handles the SignMessageFinal RPC.
func (h *StreamingCryptoHandler) SignMessageFinal(ctx context.Context, req *messagespb.SignMessageFinalRequest) (*messagespb.SignMessageFinalResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.SignMessageFinal(ctx, req)
}

// VerifyMessageInit handles the VerifyMessageInit RPC.
func (h *StreamingCryptoHandler) VerifyMessageInit(ctx context.Context, req *messagespb.VerifyMessageInitRequest) (*messagespb.VerifyMessageInitResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.VerifyMessageInit(ctx, req)
}

// VerifyMessage handles the VerifyMessage RPC.
func (h *StreamingCryptoHandler) VerifyMessage(ctx context.Context, req *messagespb.VerifyMessageRequest) (*messagespb.VerifyMessageResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.VerifyMessage(ctx, req)
}

// VerifyMessageBegin handles the VerifyMessageBegin RPC.
func (h *StreamingCryptoHandler) VerifyMessageBegin(ctx context.Context, req *messagespb.VerifyMessageBeginRequest) (*messagespb.VerifyMessageBeginResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.VerifyMessageBegin(ctx, req)
}

// VerifyMessageNext handles the VerifyMessageNext RPC.
func (h *StreamingCryptoHandler) VerifyMessageNext(ctx context.Context, req *messagespb.VerifyMessageNextRequest) (*messagespb.VerifyMessageNextResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.VerifyMessageNext(ctx, req)
}

// VerifyMessageFinal handles the VerifyMessageFinal RPC.
func (h *StreamingCryptoHandler) VerifyMessageFinal(ctx context.Context, req *messagespb.VerifyMessageFinalRequest) (*messagespb.VerifyMessageFinalResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.VerifyMessageFinal(ctx, req)
}

// DigestInit handles the DigestInit RPC.
func (h *StreamingCryptoHandler) DigestInit(ctx context.Context, req *messagespb.DigestInitRequest) (*messagespb.DigestInitResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DigestInit(ctx, req)
}

// DigestUpdate handles the DigestUpdate RPC.
func (h *StreamingCryptoHandler) DigestUpdate(ctx context.Context, req *messagespb.DigestUpdateRequest) (*messagespb.DigestUpdateResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DigestUpdate(ctx, req)
}

// DigestKey handles the DigestKey RPC.
func (h *StreamingCryptoHandler) DigestKey(ctx context.Context, req *messagespb.DigestKeyRequest) (*messagespb.DigestKeyResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DigestKey(ctx, req)
}

// DigestFinal handles the DigestFinal RPC.
func (h *StreamingCryptoHandler) DigestFinal(ctx context.Context, req *messagespb.DigestFinalRequest) (*messagespb.DigestFinalResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DigestFinal(ctx, req)
}

// XofInit handles the XofInit RPC.
func (h *StreamingCryptoHandler) XofInit(ctx context.Context, req *messagespb.XofInitRequest) (*messagespb.XofInitResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.XofInit(ctx, req)
}

// XofUpdate handles the XofUpdate RPC.
func (h *StreamingCryptoHandler) XofUpdate(ctx context.Context, req *messagespb.XofUpdateRequest) (*messagespb.XofUpdateResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.XofUpdate(ctx, req)
}

// XofFinal handles the XofFinal RPC.
func (h *StreamingCryptoHandler) XofFinal(ctx context.Context, req *messagespb.XofFinalRequest) (*messagespb.XofFinalResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.XofFinal(ctx, req)
}

// DigestEncryptUpdate handles the DigestEncryptUpdate RPC.
func (h *StreamingCryptoHandler) DigestEncryptUpdate(ctx context.Context, req *messagespb.DigestEncryptUpdateRequest) (*messagespb.DigestEncryptUpdateResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DigestEncryptUpdate(ctx, req)
}

// DecryptDigestUpdate handles the DecryptDigestUpdate RPC.
func (h *StreamingCryptoHandler) DecryptDigestUpdate(ctx context.Context, req *messagespb.DecryptDigestUpdateRequest) (*messagespb.DecryptDigestUpdateResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DecryptDigestUpdate(ctx, req)
}

// SignEncryptUpdate handles the SignEncryptUpdate RPC.
func (h *StreamingCryptoHandler) SignEncryptUpdate(ctx context.Context, req *messagespb.SignEncryptUpdateRequest) (*messagespb.SignEncryptUpdateResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.SignEncryptUpdate(ctx, req)
}

// DecryptVerifyUpdate handles the DecryptVerifyUpdate RPC.
func (h *StreamingCryptoHandler) DecryptVerifyUpdate(ctx context.Context, req *messagespb.DecryptVerifyUpdateRequest) (*messagespb.DecryptVerifyUpdateResponse, error) {
	return h.UnimplementedStreamingCryptoServiceServer.DecryptVerifyUpdate(ctx, req)
}
