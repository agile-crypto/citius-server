// Package vaultstorage is the Vault adapter tier of the storage layer.
//
// The repositories live in citius-server/internal/storage and depend only on
// storage.Storage. This module holds the Vault side: vaultlogical adapts a
// logical.Storage to storage.Storage, and the key, policy, provider and
// template packages expose NewVaultRepository / NewVaultRegistry
// constructors that take a logical.Storage, wrap it and delegate.
package vaultstorage
