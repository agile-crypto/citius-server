package provider

import (
	types "github.com/agile-crypto/citius-server/gen/go/api/types"
	"github.com/agile-crypto/citius-server/internal/core"
)

// score computes a provider's match score against required security
// properties, in two distinct steps:
//
//  1. Hard filter (the returned bool): a required property the provider
//     cannot satisfy eliminates it outright. Today this checks only
//     required.FipsApproved — a provider whose ImplementationProperties (or
//     the lack of an ImplementationDescriber at all) cannot substantiate an
//     active FIPS module fails the filter. When required has no hard
//     requirement (nil, or FipsApproved false), every provider passes
//     regardless of what it can report.
//  2. Soft score (the returned int) ranks survivors against each other. The
//     weights are a judgement call, not a derived truth: FIPS certification
//     (+2) outweighs the rest because it is itself a hard-filterable
//     requirement elsewhere in this function and the strongest
//     externally-auditable signal available; constant-time (+1),
//     hardware-accelerated (+1), and memory-safe language (+1) are weighted
//     equally as independent, non-competing quality signals with no
//     comparable external certification behind them. A provider with no
//     ImplementationDescriber — props is then nil — or one that reports
//     nothing scores 0: neutral, not penalised, per
//     ImplementationDescriber's own doc comment.
//
// props is nil for a provider that does not implement
// ImplementationDescriber; every accessor below is a nil-safe proto getter,
// so a nil props reports every property as unset rather than panicking.
// required is nil when the caller has no security requirement at all.
//
// This is a pure function — no registry, no provider — specifically so it
// stays table-testable on its own. Ranking a template's full candidate set
// and breaking ties by registration order is a caller's job, not this
// function's.
func score(props *types.ImplementationProperties, required *core.SecurityProperties) (int, bool) {
	if required != nil && required.FipsApproved && !props.GetFips_140().GetCertified() {
		return 0, false
	}

	s := 0
	if props.GetFips_140().GetCertified() {
		s += 2
	}
	if props.GetConstantTime() {
		s++
	}
	if props.GetHardwareAccelerated() {
		s++
	}
	if props.GetMemorySafeLanguage() {
		s++
	}
	return s, true
}
