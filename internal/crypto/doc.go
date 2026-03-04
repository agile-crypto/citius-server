// Package crypto contains the Session domain type and the CryptoOrchestrator
// implementation that coordinates key retrieval, policy validation, and
// provider dispatch for all cryptographic operations.
//
// Session represents a multi-part streaming session (e.g., streaming
// sign/verify/encrypt/decrypt). It embeds *storepb.StoredSession and is
// a stub in M1 -- streaming operations are not yet implemented.
package crypto
