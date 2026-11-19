// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package integration_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/storage"
)

const (
	pkceReplayCorrectVerifier = "somechallengesomechallengesomechallengesomechallengesomechallengesomechallenge"
	pkceReplayWrongVerifier   = "failchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallengefailchallenge"
	// The server is configured to allow the plain challenge method, where the
	// challenge equals the verifier.
	pkceReplayChallenge = pkceReplayCorrectVerifier
)

func newPKCEReplayServer(t *testing.T) (string, *storage.MemoryStore) {
	t.Helper()
	store := storage.NewMemoryStore()
	store.Clients["public-client"] = &fosite.DefaultClient{
		ID:            "public-client",
		Secret:        []byte{},
		Public:        true,
		RedirectURIs:  []string{"http://localhost:3846/callback"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"fosite"},
	}
	store.Clients["other-client"] = &fosite.DefaultClient{
		ID:            "other-client",
		Secret:        []byte{},
		Public:        true,
		RedirectURIs:  []string{"http://localhost:3846/callback"},
		ResponseTypes: []string{"code"},
		GrantTypes:    []string{"authorization_code"},
		Scopes:        []string{"fosite"},
	}

	c := new(fosite.Config)
	c.EnforcePKCE = true
	c.EnablePKCEPlainChallengeMethod = true
	f := compose.Compose(c, store, hmacStrategy,
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2PKCEFactory)
	ts := mockServer(t, f, &fosite.DefaultSession{})
	t.Cleanup(ts.Close)

	store.Clients["public-client"].(*fosite.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"
	store.Clients["other-client"].(*fosite.DefaultClient).RedirectURIs[0] = ts.URL + "/callback"
	return ts.URL, store
}

func issuePKCEAuthorizeCode(t *testing.T, serverURL string) string {
	t.Helper()
	authURL := serverURL + "/auth?response_type=code&client_id=public-client&redirect_uri=" +
		url.QueryEscape(serverURL+"/callback") + "&scope=fosite&state=state-state&code_challenge=" + pkceReplayChallenge
	resp, err := http.Get(authURL)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return resp.Request.URL.Query().Get("code")
}

func exchangePKCECode(t *testing.T, serverURL, code, verifier, clientID string) (int, map[string]any) {
	t.Helper()
	resp, err := http.PostForm(serverURL+"/token", url.Values{
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"redirect_uri":  {serverURL + "/callback"},
		"code_verifier": {verifier},
	})
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	payload := map[string]any{}
	_ = json.Unmarshal(body, &payload)
	return resp.StatusCode, payload
}

// End-to-end check that a wrong verifier does not destroy the challenge: the
// same code can still be exchanged once with the correct verifier, and every
// replay afterwards is denied.
func TestPKCEFailedVerifierRetryAndReplay(t *testing.T) {
	serverURL, _ := newPKCEReplayServer(t)
	code := issuePKCEAuthorizeCode(t, serverURL)

	status, payload := exchangePKCECode(t, serverURL, code, pkceReplayWrongVerifier, "public-client")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", payload["error"])

	// The retained challenge gives the same stable mismatch result on repeat.
	status, payload = exchangePKCECode(t, serverURL, code, pkceReplayWrongVerifier, "public-client")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", payload["error"])

	// Retrying with the correct verifier still succeeds exactly once.
	status, payload = exchangePKCECode(t, serverURL, code, pkceReplayCorrectVerifier, "public-client")
	require.Equal(t, http.StatusOK, status, payload)
	assert.NotEmpty(t, payload["access_token"])

	// Replays with the correct verifier are now denied.
	status, payload = exchangePKCECode(t, serverURL, code, pkceReplayCorrectVerifier, "public-client")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", payload["error"])

	// Replays with a wrong verifier get the same stable denial.
	status, payload = exchangePKCECode(t, serverURL, code, pkceReplayWrongVerifier, "public-client")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", payload["error"])
}

// Concurrent exchanges of the same code must produce exactly one token.
func TestPKCEConcurrentExchangeSingleToken(t *testing.T) {
	serverURL, _ := newPKCEReplayServer(t)
	code := issuePKCEAuthorizeCode(t, serverURL)

	const goroutines = 30
	var wg sync.WaitGroup
	statuses := make(chan int, goroutines)
	start := make(chan struct{})
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			status, _ := exchangePKCECode(t, serverURL, code, pkceReplayCorrectVerifier, "public-client")
			statuses <- status
		}()
	}
	close(start)
	wg.Wait()
	close(statuses)

	ok, denied := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusOK:
			ok++
		case http.StatusBadRequest:
			denied++
		default:
			t.Fatalf("unexpected status %d", status)
		}
	}
	assert.Equal(t, 1, ok, "exactly one exchange must succeed")
	assert.Equal(t, goroutines-1, denied)
}

// A different client can neither exchange the code nor consume the challenge.
func TestPKCEDifferentClientCannotExchange(t *testing.T) {
	serverURL, _ := newPKCEReplayServer(t)
	code := issuePKCEAuthorizeCode(t, serverURL)

	// The other client knows the code and the correct verifier, but the
	// challenge is bound to public-client.
	status, payload := exchangePKCECode(t, serverURL, code, pkceReplayCorrectVerifier, "other-client")
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "invalid_grant", payload["error"])

	// The legitimate owner is still able to perform the single exchange.
	status, payload = exchangePKCECode(t, serverURL, code, pkceReplayCorrectVerifier, "public-client")
	require.Equal(t, http.StatusOK, status, fmt.Sprintf("%v", payload))
	assert.NotEmpty(t, payload["access_token"])
}
