package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/agile-crypto/zitadel-grpc-auth/admin"
)

func TestReconcileIdentityResources(t *testing.T) {
	acl, err := loadACLText(t, validHumanACL)
	if err != nil {
		t.Fatalf("load ACL: %v", err)
	}
	acl.MachineUsers = []admin.OnboardInput{{Username: "service"}}
	t.Setenv("ALICE_INITIAL_PASSWORD", "initial-secret")

	client := &fakeIdentityAdmin{}
	got, err := reconcileIdentityResources(context.Background(), client, acl)
	if err != nil {
		t.Fatalf("reconcile identities: %v", err)
	}
	if len(client.calls) != 3 || strings.Join(client.calls, ",") != "web:citius-ui,machine:service,human:alice" {
		t.Fatalf("calls = %v", client.calls)
	}
	if client.humanPassword != "initial-secret" {
		t.Fatalf("human password = %q", client.humanPassword)
	}
	if got.WebApplication == nil || got.WebApplication.ClientID != "web-client" {
		t.Fatalf("Web application result = %#v", got.WebApplication)
	}
	if got.MachineUsers["service"].ClientID != "machine-client" {
		t.Fatalf("machine result = %#v", got.MachineUsers)
	}
	if got.HumanUsers["alice"].LoginName != "alice@example.test" {
		t.Fatalf("human result = %#v", got.HumanUsers)
	}
}

func TestReconcileIdentityResourcesRetainsMachineOnlyFlow(t *testing.T) {
	acl, err := loadACL("../acl.yaml")
	if err != nil {
		t.Fatalf("load repository ACL: %v", err)
	}

	client := &fakeIdentityAdmin{}
	got, err := reconcileIdentityResources(context.Background(), client, acl)
	if err != nil {
		t.Fatalf("reconcile identities: %v", err)
	}
	if len(client.calls) != len(acl.MachineUsers) {
		t.Fatalf("calls = %v, want one per machine user", client.calls)
	}
	if got.WebApplication != nil || len(got.HumanUsers) != 0 {
		t.Fatalf("machine-only result contains human login resources: %#v", got)
	}
	if len(got.MachineUsers) != len(acl.MachineUsers) {
		t.Fatalf("machine results = %d, want %d", len(got.MachineUsers), len(acl.MachineUsers))
	}
}

func TestReconcileIdentityResourcesRequiresHumanPassword(t *testing.T) {
	acl, err := loadACLText(t, validHumanACL)
	if err != nil {
		t.Fatalf("load ACL: %v", err)
	}
	t.Setenv("ALICE_INITIAL_PASSWORD", "")

	client := &fakeIdentityAdmin{}
	_, err = reconcileIdentityResources(context.Background(), client, acl)
	if err == nil || !strings.Contains(err.Error(), "ALICE_INITIAL_PASSWORD") {
		t.Fatalf("reconcile error = %v, want missing password environment", err)
	}
	if len(client.calls) != 0 {
		t.Fatalf("calls before password failure = %v, want none", client.calls)
	}
}

func TestReconcileIdentityResourcesStopsOnFailure(t *testing.T) {
	acl, err := loadACLText(t, validHumanACL)
	if err != nil {
		t.Fatalf("load ACL: %v", err)
	}
	acl.MachineUsers = []admin.OnboardInput{{Username: "service"}}
	t.Setenv("ALICE_INITIAL_PASSWORD", "initial-secret")

	client := &fakeIdentityAdmin{machineErr: errors.New("grant failed")}
	_, err = reconcileIdentityResources(context.Background(), client, acl)
	if err == nil || !strings.Contains(err.Error(), `onboard machine user "service"`) {
		t.Fatalf("reconcile error = %v", err)
	}
	if strings.Join(client.calls, ",") != "web:citius-ui,machine:service" {
		t.Fatalf("calls = %v", client.calls)
	}
}

type fakeIdentityAdmin struct {
	calls         []string
	humanPassword string
	machineErr    error
}

func (f *fakeIdentityAdmin) EnsureWebApplication(_ context.Context, in admin.WebApplicationInput) (*admin.WebApplicationResult, error) {
	f.calls = append(f.calls, "web:"+in.Name)
	return &admin.WebApplicationResult{ApplicationID: "web-app", ClientID: "web-client"}, nil
}

func (f *fakeIdentityAdmin) Onboard(_ context.Context, in admin.OnboardInput) (*admin.OnboardResult, error) {
	f.calls = append(f.calls, "machine:"+in.Username)
	if f.machineErr != nil {
		return nil, f.machineErr
	}
	return &admin.OnboardResult{UserID: "machine-user", ClientID: "machine-client"}, nil
}

func (f *fakeIdentityAdmin) OnboardHuman(_ context.Context, in admin.HumanOnboardInput) (*admin.HumanOnboardResult, error) {
	f.calls = append(f.calls, "human:"+in.Username)
	f.humanPassword = in.InitialPassword
	return &admin.HumanOnboardResult{UserID: "human-user", LoginName: "alice@example.test"}, nil
}
