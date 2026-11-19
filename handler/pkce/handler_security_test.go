// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
)

const (
	pkceSecurityVerifierA = "KGCt4m8AmjUvIR5ArTByrmehjtbxn1A49YpTZhsH8N7fhDr7LQayn9xx6mck"
	pkceSecurityVerifierB = "9B6bRQ0m7zFbXb5m4uL0XcX9pQ1vR8kT2wY3hN5jV7dE6gA0sW4qZ2xL8cV1nM3"
)

func s256ChallengeFor(verifier string) string {
	hash := sha256.New()
	hash.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash.Sum(nil))
}

func newSecurityTestHandler(t *testing.T, enforcePKCE bool) (*Handler, *storage.MemoryStore, *mockCodeStrategy) {
	t.Helper()
	store := storage.NewMemoryStore()
	strategy := &mockCodeStrategy{}
	config := &fosite.Config{
		EnforcePKCE: enforcePKCE,
	}
	h := &Handler{Storage: store, AuthorizeCodeStrategy: strategy, Config: config}
	return h, store, strategy
}

func createPKCESession(t *testing.T, store *storage.MemoryStore, signature, challenge, method string, client fosite.Client) {
	t.Helper()
	ar := fosite.NewAuthorizeRequest()
	ar.Client = client
	ar.Form.Set("code_challenge", challenge)
	ar.Form.Set("code_challenge_method", method)
	require.NoError(t, store.CreatePKCERequestSession(context.Background(), signature, ar))
}

func newTokenExchangeRequest(code, verifier string, client fosite.Client, grantTypes ...string) *fosite.AccessRequest {
	r := fosite.NewAccessRequest(nil)
	r.Client = client
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}
	r.GrantTypes = fosite.Arguments(grantTypes)
	r.Form.Set("code", code)
	if verifier != "" {
		r.Form.Set("code_verifier", verifier)
	}
	return r
}

// A failed verification must leave the challenge in place. Retrying with the
// correct verifier must therefore succeed instead of being downgraded into a
// "PKCE data not found" path.
func TestPKCEFailedVerificationKeepsChallengeAndRetrySucceeds(t *testing.T) {
	h, store, strategy := newSecurityTestHandler(t, false)
	client := &fosite.DefaultClient{ID: "client-retry"}
	signature := "sig-retry"
	strategy.signature = signature
	createPKCESession(t, store, signature, s256ChallengeFor(pkceSecurityVerifierA), "S256", client)

	// First attempt with the wrong verifier must fail with the mismatch error,
	// and the error must be identical on every failed attempt.
	for attempt := 0; attempt < 3; attempt++ {
		err := h.HandleTokenEndpointRequest(context.Background(),
			newTokenExchangeRequest("code", pkceSecurityVerifierB, client))
		require.Error(t, err)
		assert.True(t, errors.Is(err, fosite.ErrInvalidGrant), "attempt %d: %v", attempt, err)
		assert.Contains(t, newtesterr(err).Error(), "The PKCE code challenge did not match the code verifier.")
	}

	// The challenge must still be available: retrying with the correct verifier
	// succeeds exactly once.
	require.NoError(t, h.HandleTokenEndpointRequest(context.Background(),
		newTokenExchangeRequest("code", pkceSecurityVerifierA, client)))

	// A replay after the successful consumption must be denied.
	err := h.HandleTokenEndpointRequest(context.Background(),
		newTokenExchangeRequest("code", pkceSecurityVerifierA, client))
	require.Error(t, err)
	assert.True(t, errors.Is(err, fosite.ErrInvalidGrant))
}

// When PKCE is not enforced, a failed attempt must not allow dropping the
// verifier entirely: the retained challenge keeps requiring a valid verifier.
func TestPKCEFailedVerificationCannotDowngradeWithoutVerifier(t *testing.T) {
	h, store, strategy := newSecurityTestHandler(t, false)
	client := &fosite.DefaultClient{ID: "client-downgrade"}
	signature := "sig-downgrade"
	strategy.signature = signature
	createPKCESession(t, store, signature, s256ChallengeFor(pkceSecurityVerifierA), "S256", client)

	require.Error(t, h.HandleTokenEndpointRequest(context.Background(),
		newTokenExchangeRequest("code", pkceSecurityVerifierB, client)))

	// Retrying without any verifier must not slip through the no-PKCE path.
	err := h.HandleTokenEndpointRequest(context.Background(),
		newTokenExchangeRequest("code", "", client))
	require.Error(t, err)
	assert.True(t, errors.Is(err, fosite.ErrInvalidGrant))
	assert.Contains(t, newtesterr(err).Error(), "The PKCE code verifier must be at least 43 characters.")
}

// A successful exchange consumes the session exactly once, and every replay
// (with any verifier, correct or wrong) gets a stable invalid_grant result.
func TestPKCESessionConsumedExactlyOnce(t *testing.T) {
	h, store, strategy := newSecurityTestHandler(t, true)
	client := &fosite.DefaultClient{ID: "client-once"}
	signature := "sig-once"
	strategy.signature = signature
	createPKCESession(t, store, signature, s256ChallengeFor(pkceSecurityVerifierA), "S256", client)

	require.NoError(t, h.HandleTokenEndpointRequest(context.Background(),
		newTokenExchangeRequest("code", pkceSecurityVerifierA, client)))

	for _, verifier := range []string{pkceSecurityVerifierA, pkceSecurityVerifierB, ""} {
		err := h.HandleTokenEndpointRequest(context.Background(),
			newTokenExchangeRequest("code", verifier, client))
		require.Error(t, err)
		assert.True(t, errors.Is(err, fosite.ErrInvalidGrant), "verifier %q: %v", verifier, err)
		assert.Contains(t, newtesterr(err).Error(), "The PKCE request session has already been used.")
	}
}

// Concurrent exchanges of the same code must resolve deterministically:
// exactly one request consumes the session, all others are denied with
// invalid_grant.
func TestPKCEConcurrentExchangeHasSingleWinner(t *testing.T) {
	h, store, strategy := newSecurityTestHandler(t, true)
	client := &fosite.DefaultClient{ID: "client-concurrent"}
	signature := "sig-concurrent"
	strategy.signature = signature
	createPKCESession(t, store, signature, s256ChallengeFor(pkceSecurityVerifierA), "S256", client)

	const goroutines = 50
	var wg sync.WaitGroup
	results := make(chan error, goroutines)
	wg.Add(goroutines)
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			results <- h.HandleTokenEndpointRequest(context.Background(),
				newTokenExchangeRequest("code", pkceSecurityVerifierA, client))
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes, failures := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else {
			failures++
			assert.True(t, errors.Is(err, fosite.ErrInvalidGrant), err)
		}
	}
	assert.Equal(t, 1, successes, "exactly one exchange must succeed")
	assert.Equal(t, goroutines-1, failures, "all other exchanges must be denied")
}

// A PKCE session is bound to the client that created it. Another client must
// never be able to validate against, or consume, that challenge.
func TestPKCEDifferentClientsCannotPolluteEachOther(t *testing.T) {
	h, store, strategy := newSecurityTestHandler(t, true)
	owner := &fosite.DefaultClient{ID: "client-owner"}
	attacker := &fosite.DefaultClient{ID: "client-attacker"}
	signature := "sig-client-binding"
	strategy.signature = signature
	createPKCESession(t, store, signature, s256ChallengeFor(pkceSecurityVerifierA), "S256", owner)

	// The attacker knows the code and a verifier matching the challenge, but the
	// session belongs to the owner and must be rejected without being consumed.
	err := h.HandleTokenEndpointRequest(context.Background(),
		newTokenExchangeRequest("code", pkceSecurityVerifierA, attacker))
	require.Error(t, err)
	assert.True(t, errors.Is(err, fosite.ErrInvalidGrant))
	assert.Contains(t, newtesterr(err).Error(),
		"The OAuth 2.0 Client ID from this request does not match the one from the authorize request.")

	// The owner can still perform the exchange, proving no pollution occurred.
	require.NoError(t, h.HandleTokenEndpointRequest(context.Background(),
		newTokenExchangeRequest("code", pkceSecurityVerifierA, owner)))

	// And the attacker still cannot replay the now-consumed session either.
	err = h.HandleTokenEndpointRequest(context.Background(),
		newTokenExchangeRequest("code", pkceSecurityVerifierA, attacker))
	require.Error(t, err)
	assert.True(t, errors.Is(err, fosite.ErrInvalidGrant))
}

// A challenge that survives past the authorization code lifetime keeps
// returning stable denial results: nothing mutates the stored PKCE state, so
// the outcome is identical on every attempt.
func TestPKCEExpiredChallengeGivesStableResults(t *testing.T) {
	h, store, strategy := newSecurityTestHandler(t, true)
	client := &fosite.DefaultClient{ID: "client-expired"}
	signature := "sig-expired"
	strategy.signature = signature
	createPKCESession(t, store, signature, s256ChallengeFor(pkceSecurityVerifierA), "S256", client)

	// In the full flow the authorization code layer rejects expired codes before
	// the PKCE handler runs; the PKCE session itself must remain untouched
	// regardless of how many attempts are made, keeping every result stable.
	first := h.HandleTokenEndpointRequest(context.Background(),
		newTokenExchangeRequest("code", pkceSecurityVerifierB, client))
	require.Error(t, first)

	for attempt := 0; attempt < 5; attempt++ {
		err := h.HandleTokenEndpointRequest(context.Background(),
			newTokenExchangeRequest("code", pkceSecurityVerifierB, client))
		require.Error(t, err)
		assert.Equal(t, newtesterr(first).Error(), newtesterr(err).Error(), "attempt %d", attempt)
	}

	// The session was never consumed by the failed attempts.
	stored, err := store.GetPKCERequestSession(context.Background(), signature, nil)
	require.NoError(t, err)
	assert.Equal(t, "client-expired", stored.GetClient().GetID())
}

// Sessions never carrying PKCE data keep their original behavior when PKCE is
// not enforced: requests without a verifier are allowed, requests with a
// verifier get the "unable to find initial PKCE data" error.
func TestPKCELegacySessionsWithoutChallenge(t *testing.T) {
	h, _, strategy := newSecurityTestHandler(t, false)
	client := &fosite.DefaultClient{ID: "client-legacy"}
	strategy.signature = "sig-legacy"

	// No PKCE session exists and no verifier is sent: the no-PKCE path applies.
	require.NoError(t, h.HandleTokenEndpointRequest(context.Background(),
		newTokenExchangeRequest("legacy-code", "", client)))

	// A verifier without any stored challenge is still rejected.
	err := h.HandleTokenEndpointRequest(context.Background(),
		newTokenExchangeRequest("legacy-code", pkceSecurityVerifierA, client))
	require.Error(t, err)
	assert.True(t, errors.Is(err, fosite.ErrInvalidGrant))
	assert.Contains(t, newtesterr(err).Error(), "Unable to find initial PKCE data tied to this request")
}

// customConsumedStorage keeps sessions in a consumed state via the exported
// marker helpers instead of hard-deleting them, exercising the storage
// extension point used by real database backends.
type customConsumedStorage struct {
	sessions map[string]fosite.Requester
}

func newCustomConsumedStorage() *customConsumedStorage {
	return &customConsumedStorage{sessions: map[string]fosite.Requester{}}
}

func (s *customConsumedStorage) GetPKCERequestSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	rel, ok := s.sessions[signature]
	if !ok {
		return nil, fosite.ErrNotFound
	}
	if IsPKCERequestSessionConsumed(rel) {
		return rel, ErrPKCERequestSessionConsumed
	}
	return rel, nil
}

func (s *customConsumedStorage) CreatePKCERequestSession(_ context.Context, signature string, requester fosite.Requester) error {
	s.sessions[signature] = requester
	return nil
}

func (s *customConsumedStorage) DeletePKCERequestSession(_ context.Context, signature string) error {
	rel, ok := s.sessions[signature]
	if !ok {
		return fosite.ErrNotFound
	}
	if IsPKCERequestSessionConsumed(rel) {
		return ErrPKCERequestSessionConsumed
	}
	s.sessions[signature] = MarkPKCERequestSessionConsumed(rel)
	return nil
}

// Custom storage implementations that retain consumed sessions are supported
// through the exported marker helpers and sentinel error.
func TestPKCECustomStorageConsumedStateRejectsReplays(t *testing.T) {
	store := newCustomConsumedStorage()
	strategy := &mockCodeStrategy{signature: "sig-custom"}
	h := &Handler{
		Storage:               store,
		AuthorizeCodeStrategy: strategy,
		Config:                &fosite.Config{EnforcePKCE: true},
	}
	client := &fosite.DefaultClient{ID: "client-custom"}
	require.NoError(t, store.CreatePKCERequestSession(context.Background(), "sig-custom",
		func() fosite.Requester {
			ar := fosite.NewAuthorizeRequest()
			ar.Client = client
			ar.Form.Set("code_challenge", s256ChallengeFor(pkceSecurityVerifierA))
			ar.Form.Set("code_challenge_method", "S256")
			return ar
		}()))

	require.NoError(t, h.HandleTokenEndpointRequest(context.Background(),
		newTokenExchangeRequest("code", pkceSecurityVerifierA, client)))

	for i := 0; i < 3; i++ {
		err := h.HandleTokenEndpointRequest(context.Background(),
			newTokenExchangeRequest("code", pkceSecurityVerifierA, client))
		require.Error(t, err)
		assert.True(t, errors.Is(err, fosite.ErrInvalidGrant))
		assert.Contains(t, newtesterr(err).Error(), "The PKCE request session has already been used.")
	}
}

// MarkPKCERequestSessionConsumed / IsPKCERequestSessionConsumed are stable
// helpers for storage implementers.
func TestPKCEConsumedMarkerHelpers(t *testing.T) {
	assert.False(t, IsPKCERequestSessionConsumed(nil))
	assert.Nil(t, MarkPKCERequestSessionConsumed(nil))

	ar := fosite.NewAuthorizeRequest()
	marked := MarkPKCERequestSessionConsumed(ar)
	assert.True(t, IsPKCERequestSessionConsumed(marked))
	// Marking twice must not wrap repeatedly and must keep the original requester.
	assert.Same(t, marked, MarkPKCERequestSessionConsumed(marked))
	assert.Equal(t, ar, marked.(*consumedRequester).Requester)
}

func TestPKCESecurityScenarioTable(t *testing.T) {
	clientA := &fosite.DefaultClient{ID: "client-a"}
	clientB := &fosite.DefaultClient{ID: "client-b"}

	for k, tc := range []struct {
		d          string
		enforce    bool
		storedFor  fosite.Client
		requestFor fosite.Client
		verifier   string
		expectErr  error
	}{
		{
			d:          "correct verifier for the owning client succeeds",
			enforce:    true,
			storedFor:  clientA,
			requestFor: clientA,
			verifier:   pkceSecurityVerifierA,
		},
		{
			d:          "wrong verifier is denied with invalid_grant",
			enforce:    true,
			storedFor:  clientA,
			requestFor: clientA,
			verifier:   pkceSecurityVerifierB,
			expectErr:  fosite.ErrInvalidGrant,
		},
		{
			d:          "different client is denied with invalid_grant",
			enforce:    true,
			storedFor:  clientA,
			requestFor: clientB,
			verifier:   pkceSecurityVerifierA,
			expectErr:  fosite.ErrInvalidGrant,
		},
		{
			d:          "empty verifier is denied with invalid_grant",
			enforce:    true,
			storedFor:  clientA,
			requestFor: clientA,
			verifier:   "",
			expectErr:  fosite.ErrInvalidGrant,
		},
	} {
		t.Run(fmt.Sprintf("case=%d/%s", k, tc.d), func(t *testing.T) {
			h, store, strategy := newSecurityTestHandler(t, tc.enforce)
			signature := fmt.Sprintf("sig-table-%d", k)
			strategy.signature = signature
			createPKCESession(t, store, signature, s256ChallengeFor(pkceSecurityVerifierA), "S256", tc.storedFor)

			err := h.HandleTokenEndpointRequest(context.Background(),
				newTokenExchangeRequest("code", tc.verifier, tc.requestFor))
			if tc.expectErr == nil {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
				assert.True(t, errors.Is(err, tc.expectErr), err)
			}
		})
	}
}
