// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/ory/fosite"
	"github.com/ory/fosite/internal/gen"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
)

const testClientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// clientAssertionFixture wires a private_key_jwt client to a real in-memory
// store so assertions can be replayed against the same jti ledger the handler
// writes to.
type clientAssertionFixture struct {
	t        *testing.T
	f        *Fosite
	store    *storage.MemoryStore
	clientID string
	keyID    string
	key      *rsa.PrivateKey
}

func newClientAssertionFixture(t *testing.T, store *storage.MemoryStore, clientID string) *clientAssertionFixture {
	t.Helper()

	privateKey := gen.MustRSAKey()
	keyID := "kid-" + clientID

	client := &DefaultOpenIDConnectClient{
		DefaultClient: &DefaultClient{ID: clientID},
		JSONWebKeys: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{
				KeyID: keyID,
				Use:   "sig",
				Key:   &privateKey.PublicKey,
			}},
		},
		TokenEndpointAuthMethod: "private_key_jwt",
	}

	if store == nil {
		store = storage.NewMemoryStore()
	}
	store.Clients[clientID] = client

	return &clientAssertionFixture{
		t:        t,
		f:        &Fosite{Store: store, Config: &Config{TokenURL: "https://example.com/token"}},
		store:    store,
		clientID: clientID,
		keyID:    keyID,
		key:      privateKey,
	}
}

func (fx *clientAssertionFixture) assertionFor(clientID, jti string, mutate func(jwt.MapClaims)) string {
	fx.t.Helper()

	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": "https://example.com/token",
		"jti": jti,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(30 * time.Minute).Unix(),
	}
	if mutate != nil {
		mutate(claims)
	}

	token := jwt.NewWithClaims(jose.RS256, claims)
	token.Header["kid"] = fx.keyID
	raw, err := token.SignedString(fx.key)
	require.NoError(fx.t, err)

	return raw
}

func (fx *clientAssertionFixture) assertion(jti string, mutate func(jwt.MapClaims)) string {
	return fx.assertionFor(fx.clientID, jti, mutate)
}

func (fx *clientAssertionFixture) authenticate(clientID, assertion string) (Client, error) {
	fx.t.Helper()

	return fx.f.AuthenticateClient(
		context.Background(),
		new(http.Request),
		url.Values{
			"client_id":             {clientID},
			"client_assertion":      {assertion},
			"client_assertion_type": {testClientAssertionType},
		},
	)
}

// requireRFCError pins the error category (error code and HTTP status) so a
// regression cannot silently turn a replay rejection into a generic failure.
func requireRFCError(t *testing.T, err error, want *RFC6749Error) {
	t.Helper()
	require.Error(t, err)
	got := ErrorToRFC6749Error(err)
	assert.Equal(t, want.ErrorField, got.ErrorField, "error code")
	assert.Equal(t, want.CodeField, got.CodeField, "status code")
}

func TestAuthenticateClient_ClientAssertionJTILifecycle(t *testing.T) {
	t.Run("first use succeeds and records the jti until exp", func(t *testing.T) {
		fx := newClientAssertionFixture(t, nil, "client-a")
		exp := time.Now().Add(30 * time.Minute)
		raw := fx.assertion("jti-first", func(c jwt.MapClaims) {
			c["exp"] = exp.Unix()
		})

		client, err := fx.authenticate(fx.clientID, raw)
		require.NoError(t, err)
		require.NotNil(t, client)
		assert.Equal(t, fx.clientID, client.GetID())

		recorded, ok := fx.store.BlacklistedJTIs["jti-first"]
		require.True(t, ok, "successful authentication must record the jti")
		assert.Equal(t, exp.Unix(), recorded.Unix())
	})

	t.Run("same jti from the same client is rejected on replay", func(t *testing.T) {
		fx := newClientAssertionFixture(t, nil, "client-a")
		raw := fx.assertion("jti-replay", nil)

		_, err := fx.authenticate(fx.clientID, raw)
		require.NoError(t, err)

		client, err := fx.authenticate(fx.clientID, raw)
		requireRFCError(t, err, ErrJTIKnown)
		assert.Nil(t, client)
		assert.Contains(t, ErrorToRFC6749Error(err).HintField, "only be used once")
	})

	t.Run("expired assertion is rejected and does not consume the jti", func(t *testing.T) {
		fx := newClientAssertionFixture(t, nil, "client-a")
		raw := fx.assertion("jti-expired", func(c jwt.MapClaims) {
			c["exp"] = time.Now().Add(-time.Minute).Unix()
		})

		_, err := fx.authenticate(fx.clientID, raw)
		require.Error(t, err)
		assert.NotContains(t, fx.store.BlacklistedJTIs, "jti-expired",
			"a rejected assertion must not be recorded as used")
	})

	t.Run("jti whose validity window already elapsed may be reused", func(t *testing.T) {
		fx := newClientAssertionFixture(t, nil, "client-a")
		require.NoError(t, fx.store.SetClientAssertionJWT(context.Background(), "jti-window", time.Now().Add(-time.Second)))

		client, err := fx.authenticate(fx.clientID, fx.assertion("jti-window", nil))
		require.NoError(t, err, "an expired jti record must not block a fresh assertion")
		require.NotNil(t, client)
	})

	t.Run("audience failure burns the jti before the retry", func(t *testing.T) {
		// The jti is written to the store before the audience claim is
		// checked, so an aud mismatch consumes the jti and a corrected retry
		// is rejected as a replay. Pinned here so that any reordering is a
		// deliberate, test-visible decision.
		fx := newClientAssertionFixture(t, nil, "client-a")
		bad := fx.assertion("jti-burned", func(c jwt.MapClaims) {
			c["aud"] = "https://wrong.example.com/token"
		})

		_, err := fx.authenticate(fx.clientID, bad)
		requireRFCError(t, err, ErrInvalidClient)
		assert.Contains(t, fx.store.BlacklistedJTIs, "jti-burned",
			"the current implementation records the jti before validating aud")

		_, err = fx.authenticate(fx.clientID, fx.assertion("jti-burned", nil))
		requireRFCError(t, err, ErrJTIKnown)
	})
}

func TestAuthenticateClient_ClientAssertionErrorSemantics(t *testing.T) {
	for _, tc := range []struct {
		name    string
		jti     string
		mutate  func(jwt.MapClaims)
		want    *RFC6749Error
		consume bool
	}{
		{
			name:   "missing jti",
			jti:    "",
			mutate: func(c jwt.MapClaims) { delete(c, "jti") },
			want:   ErrInvalidClient,
		},
		{
			name: "empty jti",
			jti:  "",
			want: ErrInvalidClient,
		},
		{
			name:   "issuer does not match client",
			jti:    "jti-iss",
			mutate: func(c jwt.MapClaims) { c["iss"] = "someone-else" },
			want:   ErrInvalidClient,
		},
		{
			name:   "subject does not match client",
			jti:    "jti-sub",
			mutate: func(c jwt.MapClaims) { c["sub"] = "someone-else" },
			want:   ErrInvalidClient,
		},
		{
			name:    "audience does not match token endpoint",
			jti:     "jti-aud",
			mutate:  func(c jwt.MapClaims) { c["aud"] = "https://wrong.example.com/token" },
			want:    ErrInvalidClient,
			consume: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newClientAssertionFixture(t, nil, "client-a")
			raw := fx.assertion(tc.jti, tc.mutate)

			client, err := fx.authenticate(fx.clientID, raw)
			requireRFCError(t, err, tc.want)
			assert.Nil(t, client)

			if tc.jti != "" {
				_, recorded := fx.store.BlacklistedJTIs[tc.jti]
				assert.Equal(t, tc.consume, recorded,
					"store state after rejection must be intentional: %s", tc.name)
			}
		})
	}

	t.Run("expired assertion surfaces as a non-RFC6749 error", func(t *testing.T) {
		fx := newClientAssertionFixture(t, nil, "client-a")
		raw := fx.assertion("jti-exp", func(c jwt.MapClaims) {
			c["exp"] = time.Now().Add(-time.Minute).Unix()
		})

		_, err := fx.authenticate(fx.clientID, raw)
		require.Error(t, err)
		// The expiry is enforced by jwt.MapClaims.Valid, which returns a bare
		// error rather than a categorized OAuth2 error. Pin the current
		// semantics so a change here is visible in review.
		assert.Equal(t, "error", ErrorToRFC6749Error(err).ErrorField)
		assert.Equal(t, http.StatusInternalServerError, ErrorToRFC6749Error(err).CodeField)
	})

	t.Run("replay error is written as a 400 jti_known response", func(t *testing.T) {
		fx := newClientAssertionFixture(t, nil, "client-a")
		raw := fx.assertion("jti-response", nil)
		_, err := fx.authenticate(fx.clientID, raw)
		require.NoError(t, err)

		_, err = fx.authenticate(fx.clientID, raw)
		require.Error(t, err)

		rec := httptest.NewRecorder()
		fx.f.WriteAccessError(context.Background(), rec, nil, err)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "jti_known", body["error"])
	})
}

// TestAuthenticateClient_ClientAssertionReplayAcrossClients pins the jti key
// space: the ledger is keyed by jti only, so a jti used by one client cannot be
// presented by another, even with a fully valid, differently signed assertion.
func TestAuthenticateClient_ClientAssertionReplayAcrossClients(t *testing.T) {
	store := storage.NewMemoryStore()
	fxA := newClientAssertionFixture(t, store, "client-a")
	fxB := newClientAssertionFixture(t, store, "client-b")

	// First use by client-a.
	_, err := fxA.authenticate("client-a", fxA.assertion("jti-cross", nil))
	require.NoError(t, err)

	// client-b's assertion is intrinsically valid: its own iss/sub/kid and a
	// signature over its own key. Only the jti collides.
	_, err = fxB.authenticate("client-b", fxB.assertion("jti-cross", nil))
	requireRFCError(t, err, ErrJTIKnown)

	// A fresh jti from client-b still works, proving the rejection above was
	// caused by the replay and not by a broken fixture.
	_, err = fxB.authenticate("client-b", fxB.assertion("jti-fresh", nil))
	require.NoError(t, err)
}

// TestAuthenticateClient_ClientAssertionReplayAcrossIssuers shows that an
// issuer without a registered client is rejected before the jti ledger is
// consulted, so the rejected attempt does not burn the jti.
func TestAuthenticateClient_ClientAssertionReplayAcrossIssuers(t *testing.T) {
	fx := newClientAssertionFixture(t, nil, "client-a")
	raw := fx.assertionFor("unregistered-issuer", "jti-unregistered", nil)

	_, err := fx.authenticate("unregistered-issuer", raw)
	requireRFCError(t, err, ErrInvalidClient)
	assert.NotContains(t, fx.store.BlacklistedJTIs, "jti-unregistered",
		"an unknown client must be rejected before the jti is recorded")

	// Register that issuer with the same key and jti: the identical assertion
	// now succeeds, proving the earlier rejection did not consume the jti.
	fx.store.Clients["unregistered-issuer"] = &DefaultOpenIDConnectClient{
		DefaultClient: &DefaultClient{ID: "unregistered-issuer"},
		JSONWebKeys: &jose.JSONWebKeySet{
			Keys: []jose.JSONWebKey{{KeyID: fx.keyID, Use: "sig", Key: &fx.key.PublicKey}},
		},
		TokenEndpointAuthMethod: "private_key_jwt",
	}

	_, err = fx.authenticate("unregistered-issuer", raw)
	require.NoError(t, err)
	assert.Contains(t, fx.store.BlacklistedJTIs, "jti-unregistered",
		"the first successful use records the jti")
}
