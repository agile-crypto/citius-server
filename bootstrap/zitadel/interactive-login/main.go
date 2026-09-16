// interactive-login obtains a short-lived human access token through
// Zitadel's hosted Authorization Code + PKCE flow. It is an operator-run
// acceptance helper, not an application session implementation.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const maxResponseBytes = 1 << 20

type authConfig struct {
	Issuer    string                    `json:"issuer"`
	Audience  string                    `json:"audience"`
	WebApp    webApplication            `json:"web_app"`
	DemoUsers map[string]demoUserConfig `json:"demo_users"`
}

type webApplication struct {
	ClientID     string   `json:"client_id"`
	RedirectURIs []string `json:"redirect_uris"`
}

type demoUserConfig struct {
	UserID    string `json:"user_id"`
	LoginName string `json:"login_name"`
}

type discoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type userinfoResponse struct {
	Subject string `json:"sub"`
}

type callbackResult struct {
	Code string
	Err  error
}

type options struct {
	ConfigPath string
	Persona    string
	TokenPath  string
	CAPath     string
	Timeout    time.Duration
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "interactive login: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}

	config, user, err := loadAuthConfig(opts.ConfigPath, opts.Persona)
	if err != nil {
		return err
	}
	client, err := newHTTPClient(opts.CAPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	discovery, err := discover(ctx, client, config.Issuer)
	if err != nil {
		return err
	}
	redirectURI, listener, err := listenForCallback(config.WebApp.RedirectURIs)
	if err != nil {
		return err
	}
	defer listener.Close()

	verifier, err := randomBase64URL(32)
	if err != nil {
		return fmt.Errorf("generate PKCE verifier: %w", err)
	}
	state, err := randomBase64URL(32)
	if err != nil {
		return fmt.Errorf("generate OAuth state: %w", err)
	}
	result := make(chan callbackResult, 1)
	server := callbackServer(listener, redirectURI, state, result)
	defer server.Close()

	authURL, err := authorizationURL(discovery.AuthorizationEndpoint, config, redirectURI, state, verifier)
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "Open this URL in a browser and sign in as %s:\n\n%s\n\n", user.LoginName, authURL)

	var callback callbackResult
	select {
	case callback = <-result:
	case <-ctx.Done():
		return fmt.Errorf("waiting for browser callback: %w", ctx.Err())
	}
	if callback.Err != nil {
		return callback.Err
	}

	accessToken, err := exchangeAndVerify(ctx, client, discovery, config, redirectURI, verifier, callback.Code, user.UserID)
	if err != nil {
		return err
	}
	if err := writeToken(opts.TokenPath, accessToken); err != nil {
		return err
	}
	fmt.Fprintf(output, "Authenticated %s; wrote the short-lived access token to %s\n", user.LoginName, opts.TokenPath)
	return nil
}

func parseOptions(args []string) (options, error) {
	fs := flag.NewFlagSet("interactive-login", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	configPath := fs.String("config", "../citius-ui-auth.json", "path to generated UI authentication configuration")
	persona := fs.String("persona", "", "demo username to authenticate")
	tokenPath := fs.String("output", "", "path for the short-lived access token")
	caPath := fs.String("ca-file", "", "optional PEM CA bundle for Zitadel")
	timeout := fs.Duration("timeout", 5*time.Minute, "maximum time to complete hosted login")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if *persona == "" {
		return options{}, errors.New("-persona is required")
	}
	if *tokenPath == "" {
		return options{}, errors.New("-output is required")
	}
	if *timeout <= 0 {
		return options{}, errors.New("-timeout must be positive")
	}
	return options{
		ConfigPath: *configPath,
		Persona:    *persona,
		TokenPath:  *tokenPath,
		CAPath:     *caPath,
		Timeout:    *timeout,
	}, nil
}

func loadAuthConfig(path, persona string) (authConfig, demoUserConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return authConfig{}, demoUserConfig{}, fmt.Errorf("open auth config %s: %w", path, err)
	}
	defer f.Close()
	var config authConfig
	decoder := json.NewDecoder(io.LimitReader(f, maxResponseBytes))
	if err := decoder.Decode(&config); err != nil {
		return authConfig{}, demoUserConfig{}, fmt.Errorf("decode auth config %s: %w", path, err)
	}
	user, ok := config.DemoUsers[persona]
	if !ok {
		return authConfig{}, demoUserConfig{}, fmt.Errorf("persona %q is not declared in %s", persona, path)
	}
	if config.Issuer == "" || config.Audience == "" || config.WebApp.ClientID == "" || user.UserID == "" || user.LoginName == "" {
		return authConfig{}, demoUserConfig{}, errors.New("auth config is missing issuer, audience, client, or user identity")
	}
	return config, user, nil
}

func newHTTPClient(caPath string) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if caPath != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system CA pool: %w", err)
		}
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA file %s: %w", caPath, err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s contains no certificates", caPath)
		}
		transport.TLSClientConfig.RootCAs = roots
	}
	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func discover(ctx context.Context, client *http.Client, issuer string) (discoveryDocument, error) {
	issuer = strings.TrimRight(issuer, "/")
	issuerURL, err := secureEndpoint(issuer)
	if err != nil {
		return discoveryDocument{}, fmt.Errorf("invalid issuer: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return discoveryDocument{}, fmt.Errorf("create discovery request: %w", err)
	}
	response, err := client.Do(request)
	if err != nil {
		return discoveryDocument{}, fmt.Errorf("OIDC discovery: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return discoveryDocument{}, fmt.Errorf("OIDC discovery returned %s", response.Status)
	}
	var document discoveryDocument
	if err := decodeJSON(response.Body, &document); err != nil {
		return discoveryDocument{}, fmt.Errorf("decode OIDC discovery: %w", err)
	}
	if strings.TrimRight(document.Issuer, "/") != issuer {
		return discoveryDocument{}, fmt.Errorf("discovery issuer %q does not match configured issuer %q", document.Issuer, issuer)
	}
	for name, endpoint := range map[string]string{
		"authorization_endpoint": document.AuthorizationEndpoint,
		"token_endpoint":         document.TokenEndpoint,
		"userinfo_endpoint":      document.UserinfoEndpoint,
	} {
		parsed, err := secureEndpoint(endpoint)
		if err != nil {
			return discoveryDocument{}, fmt.Errorf("invalid %s: %w", name, err)
		}
		if parsed.Scheme != issuerURL.Scheme || parsed.Host != issuerURL.Host {
			return discoveryDocument{}, fmt.Errorf("%s must use configured issuer origin", name)
		}
	}
	return document, nil
}

func secureEndpoint(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("unsafe URL %q", raw)
	}
	if parsed.Scheme == "https" {
		return parsed, nil
	}
	if parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname()) {
		return parsed, nil
	}
	return nil, fmt.Errorf("URL %q must use HTTPS (HTTP is allowed only on loopback)", raw)
}

func listenForCallback(redirects []string) (string, net.Listener, error) {
	if len(redirects) != 1 {
		return "", nil, fmt.Errorf("interactive verifier requires exactly one redirect URI, got %d", len(redirects))
	}
	redirect, err := url.Parse(redirects[0])
	if err != nil || redirect.Scheme != "http" || redirect.Host == "" || redirect.User != nil ||
		redirect.RawQuery != "" || redirect.Fragment != "" || !isLoopbackHost(redirect.Hostname()) {
		return "", nil, fmt.Errorf("redirect URI %q must be an absolute loopback HTTP URL without query or fragment", redirects[0])
	}
	listener, err := net.Listen("tcp", redirect.Host)
	if err != nil {
		return "", nil, fmt.Errorf("listen on redirect URI %s: %w", redirects[0], err)
	}
	return redirects[0], listener, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func callbackServer(listener net.Listener, redirectURI, expectedState string, result chan<- callbackResult) *http.Server {
	redirect, _ := url.Parse(redirectURI)
	handler := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != redirect.Path {
			http.NotFound(w, request)
			return
		}
		callback := validateCallback(request.URL.Query(), expectedState)
		if callback.Err != nil {
			http.Error(w, "Login could not be completed. Return to the terminal for details.", http.StatusBadRequest)
		} else {
			_, _ = io.WriteString(w, "Login received. You can close this browser tab and return to the terminal.\n")
		}
		select {
		case result <- callback:
		default:
		}
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return server
}

func validateCallback(values url.Values, expectedState string) callbackResult {
	if errCode := values.Get("error"); errCode != "" {
		return callbackResult{Err: fmt.Errorf("authorization failed: %s", errCode)}
	}
	if values.Get("state") == "" || values.Get("state") != expectedState {
		return callbackResult{Err: errors.New("authorization callback state mismatch")}
	}
	code := values.Get("code")
	if code == "" {
		return callbackResult{Err: errors.New("authorization callback has no code")}
	}
	return callbackResult{Code: code}
}

func authorizationURL(endpoint string, config authConfig, redirectURI, state, verifier string) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse authorization endpoint: %w", err)
	}
	scopes := []string{"openid", "profile", "email", config.Audience}
	query := parsed.Query()
	query.Set("client_id", config.WebApp.ClientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("scope", strings.Join(scopes, " "))
	query.Set("state", state)
	query.Set("code_challenge", pkceChallenge(verifier))
	query.Set("code_challenge_method", "S256")
	query.Set("prompt", "login")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func exchangeAndVerify(
	ctx context.Context,
	client *http.Client,
	discovery discoveryDocument,
	config authConfig,
	redirectURI, verifier, code, expectedSubject string,
) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {config.WebApp.ClientID},
		"redirect_uri":  {redirectURI},
		"code":          {code},
		"code_verifier": {verifier},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.Do(request)
	if err != nil {
		return "", fmt.Errorf("exchange authorization code: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %s", response.Status)
	}
	var token tokenResponse
	if decodeErr := decodeJSON(response.Body, &token); decodeErr != nil {
		return "", fmt.Errorf("decode token response: %w", decodeErr)
	}
	if token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") {
		return "", errors.New("token response does not contain a bearer access token")
	}

	userinfoRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, discovery.UserinfoEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("create userinfo request: %w", err)
	}
	userinfoRequest.Header.Set("Authorization", "Bearer "+token.AccessToken)
	userinfoResponseHTTP, err := client.Do(userinfoRequest)
	if err != nil {
		return "", fmt.Errorf("request userinfo: %w", err)
	}
	defer userinfoResponseHTTP.Body.Close()
	if userinfoResponseHTTP.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo endpoint returned %s", userinfoResponseHTTP.Status)
	}
	var userinfo userinfoResponse
	if err := decodeJSON(userinfoResponseHTTP.Body, &userinfo); err != nil {
		return "", fmt.Errorf("decode userinfo response: %w", err)
	}
	if userinfo.Subject != expectedSubject {
		return "", fmt.Errorf("authenticated subject %q does not match selected persona", userinfo.Subject)
	}
	return token.AccessToken, nil
}

func decodeJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(io.LimitReader(reader, maxResponseBytes))
	return decoder.Decode(target)
}

func randomBase64URL(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func writeToken(path, token string) error {
	if token == "" {
		return errors.New("refusing to write an empty access token")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create token directory %s: %w", directory, err)
	}
	temporary, err := os.CreateTemp(directory, ".interactive-token-*")
	if err != nil {
		return fmt.Errorf("create temporary token file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("secure temporary token file: %w", err)
	}
	if _, err := io.WriteString(temporary, token); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("write temporary token file: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary token file: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace token file %s: %w", path, err)
	}
	return nil
}
