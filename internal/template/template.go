package template

// Template is the read-only domain representation of an algorithm template.
// Templates are loaded from YAML at startup and are never written to storage.
// Templates are immutable after load.
type Template struct {
	ID                  string
	Algorithm           string
	Scopes              []string
	AlgorithmProperties map[string]string
	SecurityLevel       string
	FIPSApproved        bool
	QuantumSafe         bool
	Status              string
}
