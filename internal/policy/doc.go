// Package policy contains the Policy domain type and its repository/evaluator
// implementations.
//
// Policies define governance rules that control what the CaaS system allows:
// which algorithms, operations, and providers are permitted. Authorization
// (RBAC/ACL) is the transport layer's responsibility and is NOT mixed here.
//
// Policy embeds *storepb.StoredPolicy and adds VetForWrite validation.
package policy
