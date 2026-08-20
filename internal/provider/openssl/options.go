package openssl

// config accumulates Option values applied by New.
type config struct {
	name string
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
