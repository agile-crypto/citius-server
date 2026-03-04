// Package template contains the Template domain type, the in-memory registry,
// and the YAML loader for algorithm template definitions.
//
// Templates are plain Go structs -- they do NOT embed a storage proto.
// They are loaded from YAML configuration files at startup via LoadFromYAML()
// and are never persisted to the database. Templates define which algorithms
// are available, their security properties, and selection criteria.
package template
