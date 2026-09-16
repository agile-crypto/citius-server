package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHTTPClientRejectsRedirects(t *testing.T) {
	client, err := newHTTPClient("")
	if err != nil {
		t.Fatalf("newHTTPClient: %v", err)
	}
	if err := client.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect error = %v, want ErrUseLastResponse", err)
	}
}

func TestLoadAuthConfigSelectsDeclaredPersona(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth.json")
	writeTestConfig(t, path, authConfig{
		Issuer:   "https://issuer.example.test",
		Audience: "project-audience",
		WebApp: webApplication{
			ClientID:     "public-client",
			RedirectURIs: []string{"http://127.0.0.1:7861/auth/callback"},
		},
		DemoUsers: map[string]demoUserConfig{
			"citius-producer": {UserID: "user-1", LoginName: "citius-producer@example.test"},
		},
	})

	config, user, err := loadAuthConfig(path, "citius-producer")
	if err != nil {
		t.Fatalf("loadAuthConfig: %v", err)
	}
	if config.WebApp.ClientID != "public-client" || user.UserID != "user-1" {
		t.Fatalf("unexpected config or user: %#v %#v", config, user)
	}
	if _, _, err := loadAuthConfig(path, "citius-consumer"); err == nil || !strings.Contains(err.Error(), "not declared") {
		t.Fatalf("missing persona error = %v", err)
	}
}

func TestDiscoverRequiresConfiguredIssuerOrigin(t *testing.T) {
	document, err := json.Marshal(discoveryDocument{
		Issuer:                "https://issuer.example.test",
		AuthorizationEndpoint: "https://attacker.example.test/authorize",
		TokenEndpoint:         "https://attacker.example.test/token",
		UserinfoEndpoint:      "https://attacker.example.test/userinfo",
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	client := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, string(document)), nil
	})}

	_, err = discover(context.Background(), client, "https://issuer.example.test")
	if err == nil || !strings.Contains(err.Error(), "must use configured issuer origin") {
		t.Fatalf("discover error = %v", err)
	}
}

func TestAuthorizationURLUsesS256AndProjectAudience(t *testing.T) {
	config := authConfig{
		Audience: "urn:zitadel:iam:org:project:id:project-1:aud",
		WebApp:   webApplication{ClientID: "public-client"},
	}
	got, err := authorizationURL(
		"https://issuer.example.test/oauth/v2/authorize",
		config,
		"http://127.0.0.1:7861/auth/callback",
		"state-value",
		"verifier-value",
	)
	if err != nil {
		t.Fatalf("authorizationURL: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	query := parsed.Query()
	checks := map[string]string{
		"client_id":             "public-client",
		"redirect_uri":          "http://127.0.0.1:7861/auth/callback",
		"response_type":         "code",
		"state":                 "state-value",
		"code_challenge":        pkceChallenge("verifier-value"),
		"code_challenge_method": "S256",
		"prompt":                "login",
	}
	for key, want := range checks {
		if value := query.Get(key); value != want {
			t.Errorf("%s = %q, want %q", key, value, want)
		}
	}
	if scope := query.Get("scope"); !strings.Contains(scope, config.Audience) || !strings.Contains(scope, "openid") {
		t.Errorf("scope = %q", scope)
	}
}

func TestValidateCallbackRejectsWrongState(t *testing.T) {
	result := validateCallback(url.Values{"code": {"code-1"}, "state": {"wrong"}}, "expected")
	if result.Err == nil || !strings.Contains(result.Err.Error(), "state mismatch") {
		t.Fatalf("validateCallback error = %v", result.Err)
	}
	result = validateCallback(url.Values{"code": {"code-1"}, "state": {"expected"}}, "expected")
	if result.Err != nil || result.Code != "code-1" {
		t.Fatalf("validateCallback result = %#v", result)
	}
}

func TestExchangeAndVerifyBindsTokenToSelectedPersona(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Path {
		case "/token":
			if err := request.ParseForm(); err != nil {
				t.Fatalf("ParseForm: %v", err)
			}
			if got := request.Form.Get("code_verifier"); got != "verifier" {
				t.Errorf("code_verifier = %q", got)
			}
			if got := request.Form.Get("client_id"); got != "public-client" {
				t.Errorf("client_id = %q", got)
			}
			return response(http.StatusOK, `{"access_token":"secret-token","token_type":"Bearer"}`), nil
		case "/userinfo":
			if got := request.Header.Get("Authorization"); got != "Bearer secret-token" {
				t.Errorf("Authorization = %q", got)
			}
			return response(http.StatusOK, `{"sub":"user-1"}`), nil
		default:
			return response(http.StatusNotFound, ""), nil
		}
	})}

	discovery := discoveryDocument{TokenEndpoint: "https://issuer.example.test/token", UserinfoEndpoint: "https://issuer.example.test/userinfo"}
	config := authConfig{WebApp: webApplication{ClientID: "public-client"}}
	token, err := exchangeAndVerify(context.Background(), client, discovery, config, "http://callback", "verifier", "code", "user-1")
	if err != nil {
		t.Fatalf("exchangeAndVerify: %v", err)
	}
	if token != "secret-token" {
		t.Fatalf("token = %q", token)
	}
	if _, err := exchangeAndVerify(context.Background(), client, discovery, config, "http://callback", "verifier", "code", "other-user"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("subject mismatch error = %v", err)
	}
}

func TestWriteTokenUsesOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens", "persona.token")
	if err := writeToken(path, "secret-token"); err != nil {
		t.Fatalf("writeToken: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("permissions = %o, want 600", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "secret-token" {
		t.Fatalf("token contents = %q", data)
	}
}

func writeTestConfig(t *testing.T, path string, config authConfig) {
	t.Helper()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}
