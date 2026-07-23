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
func NoOutput(encoding string) *metapb.ProviderOutput {
	return &metapb.ProviderOutput{
		AlgorithmOutput: &metapb.ProviderOutput_NoOutput{
			NoOutput: &metapb.NoAlgorithmOutput{},
		},
		Encoding: encoding,
	}
}
