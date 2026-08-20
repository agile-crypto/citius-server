package openssl

// config accumulates Option values applied by New.
type config struct {
	name           string
	fipsConfigPath string
}

// Option configures a Provider at construction.
type Option func(*config)

// WithName overrides the provider.Registry identity New would otherwise
// default to. Every mode instance needs a distinct name to coexist in the
// same registry — the name is also what KeyVersion.ProviderId records, so
// it is what later routes an operation back to this exact context.
func WithName(name string) Option {
	return func(c *config) { c.name = name }
}

// WithFIPS makes the constructed Provider's context FIPS-only, restricting
// every fetch through it to the validated module.
//
// configPath must name an OpenSSL config that itself `.include`s
// fipsmodule.cnf (the file `openssl fipsinstall` writes) and declares the
// fips provider active — for example:
//
//	openssl_conf = openssl_init
//	.include /path/to/fipsmodule.cnf
//	[openssl_init]
//	providers = provider_sect
//	[provider_sect]
//	default = default_sect
//	fips = fips_sect
//	[default_sect]
//	activate = 1
//
// There is deliberately no default here. ossl.DefaultFIPSModuleConfig
// returns the path to fipsmodule.cnf itself, which has no openssl_conf
// directive and cannot be loaded on its own: passing it
// alone activates nothing. The wrapper config above is a deployment-specific
// artifact (which providers besides fips are active, property-query
// details) that this package has no basis to fabricate. The caller supplies
// it, the same way ossl.NewFIPSContext requires it.
//
// # A wrong configPath does not fail cleanly
//
// ossl-go's EnableFIPS doc warns that a bare LoadProvider("fips") with
// no config in scope poisons the FIPS module process-wide and permanently.
// A configPath that is syntactically valid and
// loads without error, but omits the fipsmodule.cnf include (a missing
// path, a typo, a config meant for something else), produces the identical
// "missing config data" / "fips module entering error state" error — and
// afterward, a *correct* configPath in a brand-new context, in the same
// process, fails the same way. There is no in-process recovery once this
// happens; the process must restart. New does not retry or fall back on a
// WithFIPS failure for exactly this reason — silently falling back to an
// unrestricted context would be worse than failing loudly.
func WithFIPS(configPath string) Option {
	return func(c *config) { c.fipsConfigPath = configPath }
}
