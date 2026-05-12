package auth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadFromEnv_DisabledByDefault(t *testing.T) {
	for _, k := range []string{
		EnvAuthEnabled, EnvIssuer, EnvIntrospectID, EnvIntrospectSecret,
		EnvInsecure, EnvCacheTTLSeconds, EnvCacheMaxEntries, EnvExpectedAudience,
	} {
		t.Setenv(k, "")
	}
	cfg, err := LoadFromEnv()
	require.NoError(t, err)
	require.False(t, cfg.Enabled)
	require.Equal(t, defaultCacheTTL, cfg.CacheTTL)
	require.Equal(t, defaultCacheMaxEntries, cfg.CacheMaxEntries)
	require.Empty(t, cfg.ExpectedAudience)
}

func TestLoadFromEnv_EnabledRequiresIssuerAndCreds(t *testing.T) {
	t.Setenv(EnvAuthEnabled, "true")
	t.Setenv(EnvIssuer, "")
	t.Setenv(EnvIntrospectID, "")
	t.Setenv(EnvIntrospectSecret, "")
	_, err := LoadFromEnv()
	require.Error(t, err)
	require.Contains(t, err.Error(), EnvIssuer)
}

func TestLoadFromEnv_EnabledHappyPath(t *testing.T) {
	t.Setenv(EnvAuthEnabled, "true")
	t.Setenv(EnvIssuer, "https://citius-auth.localhost")
	t.Setenv(EnvIntrospectID, "client-id")
	t.Setenv(EnvIntrospectSecret, "client-secret")
	t.Setenv(EnvCacheTTLSeconds, "60")
	t.Setenv(EnvCacheMaxEntries, "500")
	t.Setenv(EnvExpectedAudience, " a , b ,, c ")
	cfg, err := LoadFromEnv()
	require.NoError(t, err)
	require.True(t, cfg.Enabled)
	require.Equal(t, "https://citius-auth.localhost", cfg.Issuer)
	require.Equal(t, 60*time.Second, cfg.CacheTTL)
	require.Equal(t, 500, cfg.CacheMaxEntries)
	require.Equal(t, []string{"a", "b", "c"}, cfg.ExpectedAudience)
}

func TestLoadFromEnv_RejectsNegativeCacheTTL(t *testing.T) {
	t.Setenv(EnvCacheTTLSeconds, "-1")
	_, err := LoadFromEnv()
	require.Error(t, err)
}

func TestLoadFromEnv_RejectsBadCacheMax(t *testing.T) {
	t.Setenv(EnvCacheMaxEntries, "not-a-number")
	_, err := LoadFromEnv()
	require.Error(t, err)
}

func TestSplitCSV(t *testing.T) {
	require.Equal(t, []string{"a", "b"}, splitCSV(" a , b "))
	require.Empty(t, splitCSV(""))
	require.Empty(t, splitCSV(" , , "))
}
