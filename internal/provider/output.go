package provider

import (
	metapb "github.com/agile-crypto/citius-server/gen/go/api/messages"
)

// NoOutput builds a ProviderOutput with the no_output arm set and the given
// artifact encoding recorded ("der", "p1363", "raw", ...).
//
// metadata.proto requires every provider response to set algorithm_output
// explicitly — an unset oneof means the provider forgot to set it, and the
// core MUST reject the response.  Signature, asymmetric-encryption, key-wrap,
// and MAC operations have no system-generated parameters to report, so they
// use this helper to make that "nothing to report" state explicit rather than
// leaving the field nil.
//
// Use this only when the operation PRODUCES a new serialized artifact whose
// encoding a later consumer needs — Sign, DigestSign, Encrypt, GenerateKey,
// ExportPublicKey.  Operations that only check or consume an existing
// artifact (Verify, DigestVerify, Decrypt) have nothing to encode; use
// NoOutputUnencoded for those instead of guessing a value here.
func NoOutput(encoding string) *metapb.ProviderOutput {
	return &metapb.ProviderOutput{
		AlgorithmOutput: &metapb.ProviderOutput_NoOutput{
			NoOutput: &metapb.NoAlgorithmOutput{},
		},
		Encoding: encoding,
	}
}

// NoOutputUnencoded builds a ProviderOutput with the no_output arm set and no
// encoding declared.
//
// encoding documents "how the cryptographic output (ciphertext, signature,
// wrapped key) is serialized" (metadata.proto).  Verify, DigestVerify, and
// Decrypt don't produce one of those — Verify/DigestVerify return a bool, and
// Decrypt's recovered plaintext is application data, not a serialized crypto
// artifact.  The proto places no required/min_len constraint on encoding, so
// leaving it empty is a valid, meaningful "not applicable" — not a value the
// provider forgot to set.
func NoOutputUnencoded() *metapb.ProviderOutput {
	return NoOutput("")
}
