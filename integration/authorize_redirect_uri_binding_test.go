// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
)

// redirectBindingEnv bundles everything the redirect URI binding tests need:
// an isolated in-memory store, a fosite provider served over a local HTTP
// fixture, two confidential clients and an attacker controlled callback
// server that records every hit it receives.
type redirectBindingEnv struct {
	t           *testing.T
	store       *storage.MemoryStore
	ts          *httptest.Server
	attacker    *httptest.Server
	attackerMu  sync.Mutex
	attackerHit []string

	victimID     string
	victimSecret string
	otherID      string
	otherSecret  string

	callback        string // plain registered callback of the victim client
	callbackEncoded string // registered callback containing a percent-encoded query value
	callbackAlt     string // second registered callback of the victim client
}

const redirectBindingState = "12345678901234567890"

// bcrypt hash of the password "foobar", identical to the one used by the
// shared integration test fixtures.
const redirectBindingBcryptFoobar = `$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO`

func newRedirectBindingEnv(t *testing.T) *redirectBindingEnv {
	t.Helper()

	env := &redirectBindingEnv{
		t:            t,
		victimID:     "redirect-binding-client",
		victimSecret: "foobar",
		otherID:      "redirect-binding-other-client",
		otherSecret:  "foobar",
	}

	// The attacker server stands in for an endpoint an attacker would like
	// the authorization code to be delivered to. Every request is recorded
	// so tests can prove that no redirect ever reaches it.
	env.attacker = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		env.attackerMu.Lock()
		env.attackerHit = append(env.attackerHit, req.URL.String())
		env.attackerMu.Unlock()
		rw.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(env.attacker.Close)

	env.store = storage.NewMemoryStore()
	env.store.Clients[env.victimID] = &fosite.DefaultClient{
		ID:            env.victimID,
		Secret:        []byte(redirectBindingBcryptFoobar),
		RedirectURIs:  []string{""},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code", "refresh_token"},
		Scopes:        []string{"fosite", "offline", "openid"},
	}
	env.store.Clients[env.otherID] = &fosite.DefaultClient{
		ID:            env.otherID,
		Secret:        []byte(redirectBindingBcryptFoobar),
		RedirectURIs:  []string{""},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"fosite", "offline", "openid"},
	}

	provider := compose.Compose(
		new(fosite.Config),
		env.store,
		hmacStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2TokenIntrospectionFactory,
	)
	env.ts = mockServer(t, provider, &openid.DefaultSession{Subject: "redirect-binding-sub"})
	t.Cleanup(env.ts.Close)

	env.callback = env.ts.URL + "/callback"
	env.callbackEncoded = env.ts.URL + "/callback?foo=bar%2Fbaz"
	env.callbackAlt = env.ts.URL + "/callback-alt"

	env.store.Clients[env.victimID].(*fosite.DefaultClient).RedirectURIs = []string{
		env.callback,
		env.callbackEncoded,
		env.callbackAlt,
	}
	env.store.Clients[env.otherID].(*fosite.DefaultClient).RedirectURIs = []string{
		env.callback,
	}

	return env
}

// noRedirectClient never follows redirects, so the 303 responses of the
// authorize endpoint can be inspected directly.
func noRedirectClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// authorizeURL builds an authorize endpoint URL for the given client and
// redirect URI. An empty redirectURI omits the parameter entirely.
func (e *redirectBindingEnv) authorizeURL(clientID, redirectURI string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("state", redirectBindingState)
	if redirectURI != "" {
		q.Set("redirect_uri", redirectURI)
	}
	return e.ts.URL + "/auth?" + q.Encode()
}

// performAuthorizeRequest drives a single request against the authorize
// endpoint without following the resulting redirect.
func (e *redirectBindingEnv) performAuthorizeRequest(rawURL string) *http.Response {
	e.t.Helper()
	resp, err := noRedirectClient().Get(rawURL)
	require.NoError(e.t, err)
	return resp
}

// authorizeCode performs an authorize request that is expected to succeed and
// returns the issued authorization code taken from the redirect Location.
func (e *redirectBindingEnv) authorizeCode(clientID, redirectURI string) string {
	e.t.Helper()
	resp := e.performAuthorizeRequest(e.authorizeURL(clientID, redirectURI))
	require.Equal(e.t, http.StatusSeeOther, resp.StatusCode, "authorize request should redirect: %s", readBody(e.t, resp))
	location, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(e.t, err)
	code := location.Query().Get("code")
	require.NotEmpty(e.t, code, "redirect must carry an authorization code: %s", resp.Header.Get("Location"))
	return code
}

// exchangeCode posts an authorization code exchange to the token endpoint,
// authenticating as clientID with the given form parameters.
func (e *redirectBindingEnv) exchangeCode(clientID, secret string, form url.Values) (int, map[string]any) {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, e.ts.URL+tokenRelativePath, strings.NewReader(form.Encode()))
	require.NoError(e.t, err)
	req.SetBasicAuth(clientID, secret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(e.t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(e.t, err)

	parsed := map[string]any{}
	if len(body) > 0 {
		// Token endpoint responses are always JSON in this fixture.
		_ = json.Unmarshal(body, &parsed)
	}
	return resp.StatusCode, parsed
}

func (e *redirectBindingEnv) codeExchangeForm(code, redirectURI string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	if redirectURI != "" {
		form.Set("redirect_uri", redirectURI)
	}
	return form
}

// authorizeCodeSessionCount reports how many authorize code sessions are
// currently stored. The in-memory store keeps invalidated records on purpose
// (for replay detection), so this counts records rather than active codes.
func (e *redirectBindingEnv) authorizeCodeSessionCount() int {
	e.t.Helper()
	return len(e.store.AuthorizeCodes)
}

// codeSessionState returns the stored requester for a raw authorization code
// together with the error the storage layer returns on lookup. A nil error
// means the code is still active; fosite.ErrInvalidatedAuthorizeCode means it
// was consumed; fosite.ErrNotFound means no session exists at all.
func (e *redirectBindingEnv) codeSessionState(code string) (fosite.Requester, error) {
	e.t.Helper()
	signature := hmacStrategy.AuthorizeCodeSignature(context.Background(), code)
	return e.store.GetAuthorizeCodeSession(context.Background(), signature, nil)
}

func (e *redirectBindingEnv) attackerHits() []string {
	e.attackerMu.Lock()
	defer e.attackerMu.Unlock()
	hits := make([]string, len(e.attackerHit))
	copy(hits, e.attackerHit)
	return hits
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(body)
}

func requireOAuthError(t *testing.T, body map[string]any, expected string) {
	t.Helper()
	assert.Equal(t, expected, body["error"], "unexpected error body: %v", body)
}

// TestAuthorizeRedirectURIBinding verifies end-to-end that the redirect URI
// sent to the authorize endpoint is bound to the authorization code and
// re-validated at the token endpoint, as required by RFC 6749 section 4.1.3
// and RFC 6819 section 5.2.4.5. All traffic goes through local HTTP fixtures.
func TestAuthorizeRedirectURIBinding(t *testing.T) {
	t.Run("callback matching", testRedirectURICallbackMatching)
	t.Run("wrong endpoint rejection", testRedirectURIWrongEndpointRejection)
	t.Run("authorization state cleanup", testRedirectURIAuthorizationStateCleanup)
}

// testRedirectURICallbackMatching covers the authorize endpoint side of the
// binding: exact matches, percent-encoding differences, changed redirect
// chains, missing parameters and attacker supplied callbacks.
func testRedirectURICallbackMatching(t *testing.T) {
	cases := []struct {
		description string
		redirectURI func(env *redirectBindingEnv) string
		expectCode  bool
		expectError string
	}{
		{
			description: "exact match of a registered redirect URI",
			redirectURI: func(env *redirectBindingEnv) string { return env.callback },
			expectCode:  true,
		},
		{
			description: "second registered redirect URI matches exactly",
			redirectURI: func(env *redirectBindingEnv) string { return env.callbackAlt },
			expectCode:  true,
		},
		{
			description: "percent encoded query value matches its encoded registration",
			redirectURI: func(env *redirectBindingEnv) string { return env.callbackEncoded },
			expectCode:  true,
		},
		{
			description: "structurally identical URI with different percent encoding is rejected",
			// The registered value keeps the slash encoded (%2F); sending it
			// decoded changes the raw string and must not match.
			redirectURI: func(env *redirectBindingEnv) string { return env.ts.URL + "/callback?foo=bar/baz" },
			expectError: "invalid_request",
		},
		{
			description: "changed redirect chain path is rejected",
			redirectURI: func(env *redirectBindingEnv) string { return env.ts.URL + "/callback/changed" },
			expectError: "invalid_request",
		},
		{
			description: "missing redirect_uri with multiple registrations is rejected",
			redirectURI: func(env *redirectBindingEnv) string { return "" },
			expectError: "invalid_request",
		},
		{
			description: "attacker supplied callback address is rejected",
			redirectURI: func(env *redirectBindingEnv) string { return env.attacker.URL + "/stolen-code" },
			expectError: "invalid_request",
		},
		{
			description: "attacker callback trying a path traversal suffix is rejected",
			redirectURI: func(env *redirectBindingEnv) string { return env.callback + "/../attacker" },
			expectError: "invalid_request",
		},
	}

	for k, tc := range cases {
		t.Run(fmt.Sprintf("case=%d/description=%s", k, tc.description), func(t *testing.T) {
			env := newRedirectBindingEnv(t)
			redirectURI := tc.redirectURI(env)

			resp := env.performAuthorizeRequest(env.authorizeURL(env.victimID, redirectURI))

			if tc.expectCode {
				require.Equal(t, http.StatusSeeOther, resp.StatusCode, readBody(t, resp))
				location, err := url.Parse(resp.Header.Get("Location"))
				require.NoError(t, err)
				assert.NotEmpty(t, location.Query().Get("code"))
				assert.Equal(t, redirectBindingState, location.Query().Get("state"))
				// A successful issuance persists exactly one code session.
				assert.Equal(t, 1, env.authorizeCodeSessionCount())
			} else {
				// Without a valid redirect URI the error is rendered directly
				// as a JSON 400 instead of being redirected.
				bodyText := readBody(t, resp)
				require.Equal(t, http.StatusBadRequest, resp.StatusCode, bodyText)
				var body map[string]any
				require.NoError(t, json.Unmarshal([]byte(bodyText), &body))
				requireOAuthError(t, body, tc.expectError)
				// A rejected authorize request must never create a code session.
				assert.Equal(t, 0, env.authorizeCodeSessionCount())
			}

			// Under no circumstances may the user agent be sent to the
			// attacker controlled endpoint: the server must not redirect there
			// and, because it never issues a redirect, the attacker server
			// never receives a request.
			assert.Empty(t, env.attackerHits(), "attacker callback must never be invoked")
			if location := resp.Header.Get("Location"); location != "" {
				assert.NotContains(t, location, env.attacker.URL)
			}
		})
	}

	// With exactly one registered URI the parameter may be omitted, in which
	// case the server binds the code to the sole registered URI.
	t.Run("case=omitted parameter allowed with single registration", func(t *testing.T) {
		env := newRedirectBindingEnv(t)
		env.store.Clients[env.victimID].(*fosite.DefaultClient).RedirectURIs = []string{env.callback}

		resp := env.performAuthorizeRequest(env.authorizeURL(env.victimID, ""))
		require.Equal(t, http.StatusSeeOther, resp.StatusCode, readBody(t, resp))
		location, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		assert.NotEmpty(t, location.Query().Get("code"))
		assert.Empty(t, env.attackerHits())
	})
}

// testRedirectURIWrongEndpointRejection proves that an issued authorization
// code can only be exchanged by the same client against the same redirect URI
// that was used at the authorize endpoint.
func testRedirectURIWrongEndpointRejection(t *testing.T) {
	t.Run("matching redirect URI exchanges successfully", func(t *testing.T) {
		env := newRedirectBindingEnv(t)
		code := env.authorizeCode(env.victimID, env.callback)

		status, body := env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callback))
		require.Equal(t, http.StatusOK, status, body)
		assert.NotEmpty(t, body["access_token"])
		assert.Empty(t, env.attackerHits())
	})

	t.Run("redirect URI changed at the token endpoint is rejected", func(t *testing.T) {
		env := newRedirectBindingEnv(t)
		code := env.authorizeCode(env.victimID, env.callback)

		status, body := env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callbackAlt))
		require.Equal(t, http.StatusBadRequest, status, body)
		requireOAuthError(t, body, "invalid_grant")

		// The rejected exchange must not consume the code: retrying with the
		// correct binding still succeeds.
		status, body = env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callback))
		require.Equal(t, http.StatusOK, status, body)
		assert.NotEmpty(t, body["access_token"])
	})

	t.Run("attacker callback at the token endpoint is rejected", func(t *testing.T) {
		env := newRedirectBindingEnv(t)
		code := env.authorizeCode(env.victimID, env.callback)

		status, body := env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.attacker.URL+"/stolen-code"))
		require.Equal(t, http.StatusBadRequest, status, body)
		requireOAuthError(t, body, "invalid_grant")
		assert.Empty(t, env.attackerHits())

		status, body = env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callback))
		require.Equal(t, http.StatusOK, status, body)
		assert.NotEmpty(t, body["access_token"])
	})

	t.Run("encoded redirect URI must be replayed with the identical encoding", func(t *testing.T) {
		env := newRedirectBindingEnv(t)
		code := env.authorizeCode(env.victimID, env.callbackEncoded)

		// Same semantic URI, different raw encoding.
		status, body := env.exchangeCode(env.victimID, env.victimSecret,
			env.codeExchangeForm(code, env.ts.URL+"/callback?foo=bar/baz"))
		require.Equal(t, http.StatusBadRequest, status, body)
		requireOAuthError(t, body, "invalid_grant")

		// Exact replay of the original raw value succeeds.
		status, body = env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callbackEncoded))
		require.Equal(t, http.StatusOK, status, body)
		assert.NotEmpty(t, body["access_token"])
	})

	t.Run("missing redirect URI at the token endpoint is rejected when one was used", func(t *testing.T) {
		env := newRedirectBindingEnv(t)
		code := env.authorizeCode(env.victimID, env.callback)

		status, body := env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, ""))
		require.Equal(t, http.StatusBadRequest, status, body)
		requireOAuthError(t, body, "invalid_grant")

		status, body = env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callback))
		require.Equal(t, http.StatusOK, status, body)
		assert.NotEmpty(t, body["access_token"])
	})

	t.Run("code issued to another client cannot be exchanged", func(t *testing.T) {
		env := newRedirectBindingEnv(t)
		code := env.authorizeCode(env.victimID, env.callback)

		// The other client has the same callback registered; only the client
		// binding differs, which must still be enough to reject the exchange.
		status, body := env.exchangeCode(env.otherID, env.otherSecret, env.codeExchangeForm(code, env.callback))
		require.Equal(t, http.StatusBadRequest, status, body)
		requireOAuthError(t, body, "invalid_grant")

		status, body = env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callback))
		require.Equal(t, http.StatusOK, status, body)
		assert.NotEmpty(t, body["access_token"])
	})

	t.Run("unknown code is rejected", func(t *testing.T) {
		env := newRedirectBindingEnv(t)

		status, body := env.exchangeCode(env.victimID, env.victimSecret,
			env.codeExchangeForm("ory_ac_not-a-real-code.signature", env.callback))
		require.Equal(t, http.StatusBadRequest, status, body)
		requireOAuthError(t, body, "invalid_grant")
	})

	t.Run("replayed code is rejected and the minted tokens are revoked", func(t *testing.T) {
		env := newRedirectBindingEnv(t)
		code := env.authorizeCode(env.victimID, env.callback)

		status, first := env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callback))
		require.Equal(t, http.StatusOK, status, first)
		require.NotEmpty(t, first["access_token"])

		status, body := env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callback))
		require.Equal(t, http.StatusBadRequest, status, body)
		requireOAuthError(t, body, "invalid_grant")

		// The token minted by the first exchange is revoked as a consequence
		// of the replay attempt, observable through the introspection endpoint.
		introspectReq, err := http.NewRequest(http.MethodPost, env.ts.URL+"/introspect",
			strings.NewReader(url.Values{"token": {first["access_token"].(string)}}.Encode()))
		require.NoError(t, err)
		introspectReq.SetBasicAuth(env.victimID, env.victimSecret)
		introspectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		introspectResp, err := http.DefaultClient.Do(introspectReq)
		require.NoError(t, err)
		defer introspectResp.Body.Close()
		var introspection map[string]any
		require.NoError(t, json.NewDecoder(introspectResp.Body).Decode(&introspection))
		assert.Equal(t, false, introspection["active"])
	})
}

// testRedirectURIAuthorizationStateCleanup verifies that failed attempts leave
// the stored authorization state intact (no pollution) while successful
// exchanges invalidate the consumed code, and that one request's state never
// leaks into the next request.
func testRedirectURIAuthorizationStateCleanup(t *testing.T) {
	t.Run("failed authorize request stores nothing", func(t *testing.T) {
		env := newRedirectBindingEnv(t)
		require.Equal(t, 0, env.authorizeCodeSessionCount())

		resp := env.performAuthorizeRequest(env.authorizeURL(env.victimID, env.attacker.URL+"/stolen-code"))
		require.Equal(t, http.StatusBadRequest, resp.StatusCode)
		assert.Equal(t, 0, env.authorizeCodeSessionCount(), "rejected authorize request must not persist state")

		// The next, legitimate request is unaffected by the failure.
		code := env.authorizeCode(env.victimID, env.callback)
		status, body := env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callback))
		require.Equal(t, http.StatusOK, status, body)
		assert.NotEmpty(t, body["access_token"])
	})

	t.Run("failed token exchange does not invalidate the code", func(t *testing.T) {
		env := newRedirectBindingEnv(t)
		code := env.authorizeCode(env.victimID, env.callback)
		require.Equal(t, 1, env.authorizeCodeSessionCount())

		status, body := env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callbackAlt))
		require.Equal(t, http.StatusBadRequest, status, body)
		requireOAuthError(t, body, "invalid_grant")
		assert.Equal(t, 1, env.authorizeCodeSessionCount(), "failed exchange must not add or remove sessions")

		// The stored request must still carry the original redirect URI and
		// client bindings, proving no state was overwritten by the failure.
		requester, err := env.codeSessionState(code)
		require.NoError(t, err)
		assert.Equal(t, env.callback, requester.GetRequestForm().Get("redirect_uri"))
		assert.Equal(t, env.victimID, requester.GetClient().GetID())

		// The code remains exchangeable through its original binding.
		status, body = env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callback))
		require.Equal(t, http.StatusOK, status, body)
		assert.NotEmpty(t, body["access_token"])
	})

	t.Run("successful exchange invalidates the consumed code", func(t *testing.T) {
		env := newRedirectBindingEnv(t)
		code := env.authorizeCode(env.victimID, env.callback)
		require.Equal(t, 1, env.authorizeCodeSessionCount())

		status, body := env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callback))
		require.Equal(t, http.StatusOK, status, body)

		// The session record is retained for replay detection but must be
		// inactive; retrieving it yields ErrInvalidatedAuthorizeCode.
		_, err := env.codeSessionState(code)
		assert.ErrorIs(t, err, fosite.ErrInvalidatedAuthorizeCode)
	})

	t.Run("state from one request does not pollute the next request", func(t *testing.T) {
		env := newRedirectBindingEnv(t)

		// First request bound to the plain callback, then deliberately
		// exchanged with the wrong binding.
		firstCode := env.authorizeCode(env.victimID, env.callback)
		status, body := env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(firstCode, env.callbackAlt))
		require.Equal(t, http.StatusBadRequest, status, body)

		// Second request bound to a different, encoded callback must be fully
		// independent: the earlier failure must not influence its validation.
		secondCode := env.authorizeCode(env.victimID, env.callbackEncoded)
		assert.NotEqual(t, firstCode, secondCode)
		status, body = env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(secondCode, env.callbackEncoded))
		require.Equal(t, http.StatusOK, status, body)
		assert.NotEmpty(t, body["access_token"])

		// And the first code remains exchangeable through its own binding.
		status, body = env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(firstCode, env.callback))
		require.Equal(t, http.StatusOK, status, body)
		assert.NotEmpty(t, body["access_token"])
	})

	t.Run("repeated failures followed by success all behave consistently", func(t *testing.T) {
		env := newRedirectBindingEnv(t)
		code := env.authorizeCode(env.victimID, env.callback)

		for i := 0; i < 3; i++ {
			status, body := env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callbackAlt))
			require.Equal(t, http.StatusBadRequest, status, body)
			requireOAuthError(t, body, "invalid_grant")
		}
		assert.Equal(t, 1, env.authorizeCodeSessionCount())

		status, body := env.exchangeCode(env.victimID, env.victimSecret, env.codeExchangeForm(code, env.callback))
		require.Equal(t, http.StatusOK, status, body)
		assert.NotEmpty(t, body["access_token"])
	})
}
