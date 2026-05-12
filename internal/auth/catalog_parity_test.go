package auth

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"testing"
)

// TestCatalogParity_BootstrapMatchesAuth asserts that the permission
// catalog hard-coded in bootstrap/zitadel/setup-sdk/operations.go is the
// same set of strings as auth.AllPermissions(). The two live in
// different Go modules so we cannot import the constants directly;
// instead we parse the source file with go/parser and compare values.
//
// If this test fails, you almost certainly added a permission to one
// side without touching the other. Update both AllPermissions() in
// internal/auth/permissions.go and the perm* constants +
// allCitiusPermissions() in bootstrap/zitadel/setup-sdk/operations.go.
func TestCatalogParity_BootstrapMatchesAuth(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	opsPath := filepath.Join(repoRoot, "bootstrap", "zitadel", "setup-sdk", "operations.go")

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, opsPath, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", opsPath, err)
	}

	bootstrap := map[string]struct{}{}
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if !startsWith(name.Name, "perm") {
					continue
				}
				bl, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					continue
				}
				val, err := strconv.Unquote(bl.Value)
				if err != nil {
					t.Fatalf("unquote %s: %v", bl.Value, err)
				}
				bootstrap[val] = struct{}{}
			}
		}
	}
	if len(bootstrap) == 0 {
		t.Fatalf("no perm* constants found in %s; parser logic stale?", opsPath)
	}

	authSet := map[string]struct{}{}
	for _, p := range AllPermissions() {
		authSet[p] = struct{}{}
	}

	if missing := diff(authSet, bootstrap); len(missing) > 0 {
		t.Errorf("permissions in auth.AllPermissions() but not in bootstrap setup-sdk: %v", missing)
	}
	if extra := diff(bootstrap, authSet); len(extra) > 0 {
		t.Errorf("permissions in bootstrap setup-sdk but not in auth.AllPermissions(): %v", extra)
	}
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func diff(a, b map[string]struct{}) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}
