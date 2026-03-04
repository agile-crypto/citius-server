// Package provider contains the ProviderInstance storage type, the provider
// registry, and concrete provider implementations (software, loopback).
//
// A ProviderInstance is the persisted record of a registered crypto backend.
// The provider registry maps provider names to runtime ProviderInstance
// implementations for key generation, signing, verification, and other
// cryptographic operations.
package provider
