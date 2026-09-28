package crypto_test

import (
	"context"
	"testing"

	messagespb "github.com/agile-crypto/citius-api-go/gen/go/messages"
)

// TestSmoke_ListKeys_inventory lists keys through the full server stack: every
// created key appears once, in name order, at its current provider, and the
// provider filter follows a migration.
func TestSmoke_ListKeys_inventory(t *testing.T) {
	ctx := context.Background()
	h := buildServer(t)
	pol := seedPolicy(t, ctx, h, "inventory", []string{aeadTemplate}, []string{"create_key", "read_key"})
	a := createAEADKey(t, ctx, h, "inventory-a", pol)
	b := createAEADKey(t, ctx, h, "inventory-b", pol)

	list := func(req *messagespb.ListKeysRequest) map[string]string {
		t.Helper()
		resp, err := h.KeysHandler.ListKeys(ctx, req)
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		out := map[string]string{}
		prev := ""
		for _, k := range resp.GetKeys() {
			if k.GetName() <= prev {
				t.Errorf("keys out of order: %q after %q", k.GetName(), prev)
			}
			prev = k.GetName()
			out[k.GetName()] = k.GetProvider()
		}
		return out
	}

	all := list(&messagespb.ListKeysRequest{})
	if all[a] != "software" || all[b] != "software" {
		t.Fatalf("listing = %v, want %s and %s on software", all, a, b)
	}

	if _, err := h.KeysHandler.MigrateKey(ctx, &messagespb.MigrateKeyRequest{
		Name:     b,
		Target:   &messagespb.MigrateKeyRequest_TargetInstanceId{TargetInstanceId: "openssl"},
		Strategy: messagespb.MigrationStrategy_MIGRATION_STRATEGY_PROVIDER_SWITCH,
	}); err != nil {
		t.Fatalf("MigrateKey: %v", err)
	}
	onOpenSSL := list(&messagespb.ListKeysRequest{ProviderId: "openssl"})
	if _, ok := onOpenSSL[b]; !ok || len(onOpenSSL) != 1 {
		t.Errorf("openssl listing = %v, want only %s", onOpenSSL, b)
	}
}
