package policy

import (
	"fmt"
	"slices"

	"github.ibm.com/citius/citius-server/internal/core"
)

// SimpleRulesEvaluator implements RulesEvaluator for JSON schema v1.
// It uses Rules (from rules.go) internally and has no state.
//
// Evaluation rules:
//   - Absent section (nil) = no restriction (allow all)
//   - Present but empty array/object = deny all (hard deny)
//   - Comparison is direct string equality (zero conversion)
type SimpleRulesEvaluator struct{}

// NewSimpleRulesEvaluator creates a SimpleRulesEvaluator.
func NewSimpleRulesEvaluator() *SimpleRulesEvaluator { return &SimpleRulesEvaluator{} }

var _ RulesEvaluator = (*SimpleRulesEvaluator)(nil)

// Validate parses rulesJSON and validates field values.
func (e *SimpleRulesEvaluator) Validate(rulesJSON []byte) error {
	rules, err := ParseRules(rulesJSON)
	if err != nil {
		return err
	}
	return rules.Validate()
}

// AllowsOperation checks if op is in allowed_operations.key_operations.
// Absent section => allow all. Empty [] => deny all.
func (e *SimpleRulesEvaluator) AllowsOperation(rulesJSON []byte, op core.Operation) (bool, error) {
	rules, err := ParseRules(rulesJSON)
	if err != nil {
		return false, err
	}
	// No AllowedOperations section => no restriction
	if rules.AllowedOperations == nil {
		return true, nil
	}
	// KeyOperations is nil => no restriction on key operations
	if rules.AllowedOperations.KeyOperations == nil {
		return true, nil
	}
	// Empty [] => deny all. Non-empty => must contain op.
	return slices.Contains(rules.AllowedOperations.KeyOperations, string(op)), nil
}

// AllowsTemplate checks if templateID is in allowed_templates.
// Absent (nil) => allow all. Empty [] => deny all.
func (e *SimpleRulesEvaluator) AllowsTemplate(rulesJSON []byte, templateID string) (bool, error) {
	rules, err := ParseRules(rulesJSON)
	if err != nil {
		return false, err
	}
	// Absent section => no restriction
	if rules.AllowedTemplates == nil {
		return true, nil
	}
	// Empty [] => deny all. Non-empty => must contain templateID.
	return slices.Contains(rules.AllowedTemplates, templateID), nil
}

// MeetsSecurityRequirements checks the following security floor: fips_approved, block_deprecated.
// Returns nil if met, error if denied.
func (e *SimpleRulesEvaluator) MeetsSecurityRequirements(rulesJSON []byte, info TemplateSecurityInfo) error {
	rules, err := ParseRules(rulesJSON)
	if err != nil {
		return err
	}
	if rules.SecurityRequirements == nil {
		return nil // no security floor
	}
	sec := rules.SecurityRequirements

	// fips_approved check
	if sec.FIPSApproved != nil && *sec.FIPSApproved && !info.FIPSApproved {
		return fmt.Errorf("policy requires FIPS-approved algorithms; template %q is not FIPS-approved", info.TemplateID)
	}

	// block_deprecated check
	if sec.BlockDeprecated != nil && *sec.BlockDeprecated {
		if info.TemplateStatus == "deprecated" || info.TemplateStatus == "forbidden" {
			return fmt.Errorf("policy blocks deprecated/forbidden algorithms; template %q has status %q", info.TemplateID, info.TemplateStatus)
		}
	}

	return nil
}

// AllowedTemplateIDs returns the allowed_templates slice, or nil if absent.
// nil = no restriction. Empty non-nil [] = deny all.
func (e *SimpleRulesEvaluator) AllowedTemplateIDs(rulesJSON []byte) ([]string, error) {
	rules, err := ParseRules(rulesJSON)
	if err != nil {
		return nil, err
	}
	// Absent => nil (no restriction)
	if rules.AllowedTemplates == nil {
		return nil, nil
	}
	// Return a copy to prevent caller mutation
	out := make([]string, len(rules.AllowedTemplates))
	copy(out, rules.AllowedTemplates)
	return out, nil
}
