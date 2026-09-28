package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// serverPolicy reads the method → permission table the server enforces from
// the internal/auth sources. This module can't import internal/auth, so the
// test parses the three files that define it.
func serverPolicy(t *testing.T) map[string]string {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "internal", "auth")
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return string(b)
	}
	methods := read("methods.go")
	policies := read("policies.go")
	permissions := read("permissions.go")

	paths := map[string]string{}
	for _, m := range regexp.MustCompile(`(Method\w+)\s*=\s*methodPrefix \+ "([\w/]+)"`).FindAllStringSubmatch(methods, -1) {
		paths[m[1]] = methodPrefix + m[2]
	}
	perms := map[string]string{}
	for _, m := range regexp.MustCompile(`(Perm\w+)\s*=\s*"([^"]+)"`).FindAllStringSubmatch(permissions, -1) {
		perms[m[1]] = m[2]
	}
	groups := map[string]string{}
	for _, m := range regexp.MustCompile(`(\w+) := \[\]PolicyFunc\{requirePerm\((Perm\w+)\)\}`).FindAllStringSubmatch(policies, -1) {
		groups[m[1]] = perms[m[2]]
	}

	out := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(Method\w+):\s*(\w+),`).FindAllStringSubmatch(policies, -1) {
		path, ok := paths[m[1]]
		if !ok {
			t.Fatalf("policies.go uses %s, which methods.go does not define", m[1])
		}
		perm, ok := groups[m[2]]
		if !ok || perm == "" {
			t.Fatalf("policies.go maps %s to %s, which is not a single-permission group", m[1], m[2])
		}
		out[path] = perm
	}
	if len(out) != len(paths) {
		t.Fatalf("parsed %d policy entries for %d methods", len(out), len(paths))
	}
	return out
}

func TestOperationsMatchServerPolicy(t *testing.T) {
	want := serverPolicy(t)
	got := map[string]string{}
	for _, op := range citiusOperations() {
		if _, dup := got[op.Method]; dup {
			t.Errorf("duplicate operation %s", op.Method)
		}
		if op.DisplayName == "" {
			t.Errorf("%s has no display name", op.Method)
		}
		got[op.Method] = op.Permission
	}

	var problems []string
	for m, p := range want {
		switch g, ok := got[m]; {
		case !ok:
			problems = append(problems, "missing "+m)
		case g != p:
			problems = append(problems, m+": bootstrap "+g+", server "+p)
		}
	}
	for m := range got {
		if _, ok := want[m]; !ok {
			problems = append(problems, "not served: "+m)
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

func TestAllPermissionsCoverOperations(t *testing.T) {
	all := map[string]bool{}
	for _, p := range allCitiusPermissions() {
		all[p] = true
	}
	for _, op := range citiusOperations() {
		if !all[op.Permission] {
			t.Errorf("%s needs %s, which the admin grant list lacks", op.Method, op.Permission)
		}
	}
}
