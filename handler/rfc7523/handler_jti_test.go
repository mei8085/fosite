// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rfc7523

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/storage"
)

const testAssertionTokenURL = "https://as.example.com/token"

// grantFixture runs the real Handler against the real memory store so that jti
// replay behavior is exercised end to end instead of through mocks. Mocks
// would let IsJWTUsed and MarkJWTUsedForTime disagree, which is exactly the
// failure mode these tests need to rule out.
type grantFixture struct {
	t       *testing.T
	store   *storage.MemoryStore
	handler *Handler
	signer  jose.Signer
	keyID   string
	pubKey  *rsa.PublicKey
}

func newGrantFixture(t *testing.T, issuers ...string) *grantFixture {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	keyID := "kid-rfc7523"
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: privateKey, KeyID: keyID, Algorithm: string(jose.RS256)}},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	require.NoError(t, err)

	store := storage.NewMemoryStore()
	fx := &grantFixture{
		t:      t,
		store:  store,
		signer: signer,
		keyID:  keyID,
		pubKey: &privateKey.PublicKey,
	}

	cfg := &fosite.Config{
		ScopeStrategy:                        fosite.HierarchicScopeStrategy,
		AudienceMatchingStrategy:             fosite.DefaultAudienceMatchingStrategy,
		TokenURL:                             testAssertionTokenURL,
		GrantTypeJWTBearerIDOptional:         false,
		GrantTypeJWTBearerIssuedDateOptional: false,
		GrantTypeJWTBearerMaxDuration:        24 * time.Hour,
		AccessTokenLifespan:                  time.Hour,
	}
	fx.handler = &Handler{
		Storage:      store,
		Config:       cfg,
		HandleHelper: &oauth2.HandleHelper{Config: cfg},
	}

	for _, issuer := range issuers {
		fx.registerIssuer(issuer, "subject-1")
	}

	return fx
}

func (fx *grantFixture) registerIssuer(issuer, subject string) {
	entry, ok := fx.store.IssuerPublicKeys[issuer]
	keysBySubject := entry.KeysBySub
	if !ok || keysBySubject == nil {
		keysBySubject = map[string]storage.SubjectPublicKeys{}
	}
	keysBySubject[subject] = storage.SubjectPublicKeys{
		Subject: subject,
		Keys: map[string]storage.PublicKeyScopes{
			fx.keyID: {
				Key:    &jose.JSONWebKey{Key: fx.pubKey, KeyID: fx.keyID, Algorithm: string(jose.RS256), Use: "sig"},
				Scopes: []string{"read"},
			},
		},
	}
	fx.store.IssuerPublicKeys[issuer] = storage.IssuerPublicKeys{
		Issuer:    issuer,
		KeysBySub: keysBySubject,
	}
}

// assertion signs claims for issuer/subject, applying mutate for the scenario.
func (fx *grantFixture) assertion(issuer, subject, jti string, mutate func(*jwt.Claims)) string {
	fx.t.Helper()

	claims := jwt.Claims{
		Issuer:   issuer,
		Subject:  subject,
		Audience: jwt.Audience{testAssertionTokenURL},
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
		ID:       jti,
	}
	if mutate != nil {
		mutate(&claims)
	}

	raw, err := jwt.Signed(fx.signer).Claims(claims).CompactSerialize()
	require.NoError(fx.t, err)

	return raw
}

// handle runs one token-endpoint request with the given assertion.
func (fx *grantFixture) handle(assertion string, requestedScopes ...string) (fosite.AccessRequester, error) {
	return fx.handleAs("client", assertion, requestedScopes...)
}

// handleAs runs the request as a specific OAuth2 client. The grant handler's
// jti ledger is keyed by jti only, so changing the client must not change the
// replay outcome.
func (fx *grantFixture) handleAs(clientID, assertion string, requestedScopes ...string) (fosite.AccessRequester, error) {
	fx.t.Helper()

	request := fosite.NewAccessRequest(new(fosite.DefaultSession))
	request.Client = &fosite.DefaultClient{ID: clientID, GrantTypes: []string{grantTypeJWTBearer}}
	request.GrantTypes = []string{grantTypeJWTBearer}
	request.Form = url.Values{}
	request.Form.Set("assertion", assertion)
	request.SetRequestedScopes(requestedScopes)

	return request, fx.handler.HandleTokenEndpointRequest(context.Background(), request)
}

func requireGrantError(t *testing.T, err error, want *fosite.RFC6749Error) {
	t.Helper()
	require.Error(t, err)
	got := fosite.ErrorToRFC6749Error(err)
	assert.Equal(t, want.ErrorField, got.ErrorField, "error code")
	assert.Equal(t, want.CodeField, got.CodeField, "status code")
}

func TestGrantHandler_JTIReplayBoundaries(t *testing.T) {
	t.Run("first use succeeds and stores the jti with the assertion expiry", func(t *testing.T) {
		fx := newGrantFixture(t, "issuer-a")
		exp := time.Now().Add(30 * time.Minute).Round(time.Second)
		assertion := fx.assertion("issuer-a", "subject-1", "jti-1", func(c *jwt.Claims) {
			c.Expiry = jwt.NewNumericDate(exp)
		})

		request, err := fx.handle(assertion)
		require.NoError(t, err)
		assert.Equal(t, "subject-1", request.GetSession().GetSubject())

		used, err := fx.store.IsJWTUsed(context.Background(), "jti-1")
		require.NoError(t, err)
		assert.True(t, used, "a successful grant must mark the jti as used")

		recorded, ok := fx.store.BlacklistedJTIs["jti-1"]
		require.True(t, ok)
		assert.Equal(t, exp.Unix(), recorded.Unix(), "the mark must extend to the assertion expiry")
	})

	t.Run("same jti presented again is rejected", func(t *testing.T) {
		fx := newGrantFixture(t, "issuer-a")
		assertion := fx.assertion("issuer-a", "subject-1", "jti-replay", nil)

		_, err := fx.handle(assertion)
		require.NoError(t, err)

		_, err = fx.handle(assertion)
		requireGrantError(t, err, fosite.ErrJTIKnown)
	})

	t.Run("rejected replay does not extend or alter the stored window", func(t *testing.T) {
		fx := newGrantFixture(t, "issuer-a")
		exp := time.Now().Add(30 * time.Minute).Round(time.Second)
		assertion := fx.assertion("issuer-a", "subject-1", "jti-stable", func(c *jwt.Claims) {
			c.Expiry = jwt.NewNumericDate(exp)
		})

		_, err := fx.handle(assertion)
		require.NoError(t, err)
		before := fx.store.BlacklistedJTIs["jti-stable"]

		// Replay with a later exp: the store must not let a replay push the
		// window out, which would otherwise keep the jti pinned forever.
		later := fx.assertion("issuer-a", "subject-1", "jti-stable", func(c *jwt.Claims) {
			c.Expiry = jwt.NewNumericDate(exp.Add(time.Hour))
		})
		_, err = fx.handle(later)
		requireGrantError(t, err, fosite.ErrJTIKnown)

		after, ok := fx.store.BlacklistedJTIs["jti-stable"]
		require.True(t, ok)
		assert.Equal(t, before, after, "the recorded window must be stable")
	})

	t.Run("same jti from a different issuer is rejected", func(t *testing.T) {
		// Both issuers use the same signing key so the assertion for issuer-b
		// is otherwise entirely valid; only the jti collides.
		fx := newGrantFixture(t, "issuer-a", "issuer-b")

		_, err := fx.handle(fx.assertion("issuer-a", "subject-1", "jti-shared", nil))
		require.NoError(t, err)

		_, err = fx.handle(fx.assertion("issuer-b", "subject-1", "jti-shared", nil))
		requireGrantError(t, err, fosite.ErrJTIKnown)

		// A fresh jti from issuer-b still works.
		_, err = fx.handle(fx.assertion("issuer-b", "subject-1", "jti-fresh-b", nil))
		require.NoError(t, err)
	})

	t.Run("same jti from a different subject is rejected", func(t *testing.T) {
		fx := newGrantFixture(t, "issuer-a")
		fx.registerIssuer("issuer-a", "subject-2")

		_, err := fx.handle(fx.assertion("issuer-a", "subject-1", "jti-subject", nil))
		require.NoError(t, err)

		_, err = fx.handle(fx.assertion("issuer-a", "subject-2", "jti-subject", nil))
		requireGrantError(t, err, fosite.ErrJTIKnown)
	})

	t.Run("same jti presented by a different client is rejected", func(t *testing.T) {
		fx := newGrantFixture(t, "issuer-a")

		_, err := fx.handleAs("client-a", fx.assertion("issuer-a", "subject-1", "jti-client", nil))
		require.NoError(t, err)

		_, err = fx.handleAs("client-b", fx.assertion("issuer-a", "subject-1", "jti-client", nil))
		requireGrantError(t, err, fosite.ErrJTIKnown)

		// A distinct jti from client-b works, so the rejection is specific to
		// the replay rather than to the client identity.
		_, err = fx.handleAs("client-b", fx.assertion("issuer-a", "subject-1", "jti-client-b", nil))
		require.NoError(t, err)
	})
}

func TestGrantHandler_JTIExpiryAndWindowBoundaries(t *testing.T) {
	t.Run("expired assertion is rejected before the jti is consumed", func(t *testing.T) {
		fx := newGrantFixture(t, "issuer-a")
		assertion := fx.assertion("issuer-a", "subject-1", "jti-expired", func(c *jwt.Claims) {
			c.Expiry = jwt.NewNumericDate(time.Now().Add(-time.Minute))
		})

		_, err := fx.handle(assertion)
		requireGrantError(t, err, fosite.ErrInvalidGrant)
		assert.Contains(t, fosite.ErrorToRFC6749Error(err).HintField, "expired")

		_, recorded := fx.store.BlacklistedJTIs["jti-expired"]
		assert.False(t, recorded, "a rejected assertion must not consume its jti")

		// The same jti remains usable once repackaged in a valid assertion.
		_, err = fx.handle(fx.assertion("issuer-a", "subject-1", "jti-expired", nil))
		require.NoError(t, err)
	})

	t.Run("expiry beyond the configured maximum duration is rejected and not consumed", func(t *testing.T) {
		fx := newGrantFixture(t, "issuer-a")
		assertion := fx.assertion("issuer-a", "subject-1", "jti-window", func(c *jwt.Claims) {
			c.Expiry = jwt.NewNumericDate(time.Now().Add(48 * time.Hour))
			c.IssuedAt = jwt.NewNumericDate(time.Now())
		})

		_, err := fx.handle(assertion)
		requireGrantError(t, err, fosite.ErrInvalidGrant)
		assert.Contains(t, fosite.ErrorToRFC6749Error(err).HintField, "unreasonably far in the future")

		_, recorded := fx.store.BlacklistedJTIs["jti-window"]
		assert.False(t, recorded)

		_, err = fx.handle(fx.assertion("issuer-a", "subject-1", "jti-window", nil))
		require.NoError(t, err)
	})

	t.Run("expiry exactly at the maximum duration is accepted", func(t *testing.T) {
		fx := newGrantFixture(t, "issuer-a")
		// The handler compares with a strict ">" so exp-iat == max is allowed.
		issued := time.Now().Add(-time.Minute)
		assertion := fx.assertion("issuer-a", "subject-1", "jti-max", func(c *jwt.Claims) {
			c.IssuedAt = jwt.NewNumericDate(issued)
			c.Expiry = jwt.NewNumericDate(issued.Add(fx.handler.Config.GetJWTMaxDuration(context.Background())))
		})

		_, err := fx.handle(assertion)
		require.NoError(t, err)

		used, err := fx.store.IsJWTUsed(context.Background(), "jti-max")
		require.NoError(t, err)
		assert.True(t, used)
	})

	t.Run("a jti whose recorded window has passed may be used again", func(t *testing.T) {
		fx := newGrantFixture(t, "issuer-a")
		require.NoError(t, fx.store.MarkJWTUsedForTime(context.Background(), "jti-recycled", time.Now().Add(-time.Second)))

		_, err := fx.handle(fx.assertion("issuer-a", "subject-1", "jti-recycled", nil))
		require.NoError(t, err, "an elapsed replay window must not block a new assertion")
	})

	t.Run("rejected assertion can be retried when the failure is not replay", func(t *testing.T) {
		fx := newGrantFixture(t, "issuer-a")
		// Scope rejection happens after the jti check but before the mark, so
		// the jti survives and a corrected request succeeds.
		bad := fx.assertion("issuer-a", "subject-1", "jti-scope", nil)
		_, err := fx.handle(bad, "write")
		requireGrantError(t, err, fosite.ErrInvalidScope)
		assert.NotContains(t, fx.store.BlacklistedJTIs, "jti-scope")

		_, err = fx.handle(bad, "read")
		require.NoError(t, err)
	})

	t.Run("jti is optional when configured and then never recorded", func(t *testing.T) {
		fx := newGrantFixture(t, "issuer-a")
		fx.handler.Config.(*fosite.Config).GrantTypeJWTBearerIDOptional = true

		assertion := fx.assertion("issuer-a", "subject-1", "", func(c *jwt.Claims) {
			c.ID = ""
		})
		_, err := fx.handle(assertion)
		require.NoError(t, err)

		// No jti means no replay protection; the second use is accepted too.
		_, err = fx.handle(assertion)
		require.NoError(t, err, "without a jti there is nothing to replay-protect")
		assert.Empty(t, fx.store.BlacklistedJTIs)
	})
}

func TestGrantHandler_ErrorSemantics(t *testing.T) {
	for _, tc := range []struct {
		name   string
		jti    string
		mutate func(*jwt.Claims)
		want   *fosite.RFC6749Error
		hint   string
	}{
		{
			name:   "missing required jti",
			jti:    "",
			mutate: func(c *jwt.Claims) { c.ID = "" },
			want:   fosite.ErrInvalidGrant,
			hint:   `MUST contain an "jti" (JWT ID) claim`,
		},
		{
			name: "expired",
			jti:  "jti-e",
			mutate: func(c *jwt.Claims) {
				c.Expiry = jwt.NewNumericDate(time.Now().Add(-time.Minute))
			},
			want: fosite.ErrInvalidGrant,
			hint: "expired",
		},
		{
			name: "not yet valid",
			jti:  "jti-nbf",
			mutate: func(c *jwt.Claims) {
				c.NotBefore = jwt.NewNumericDate(time.Now().Add(time.Hour))
			},
			want: fosite.ErrInvalidGrant,
			hint: `contains an "nbf" (not before) claim`,
		},
		{
			name: "wrong audience",
			jti:  "jti-aud",
			mutate: func(c *jwt.Claims) {
				c.Audience = jwt.Audience{"https://elsewhere.example.com/token"}
			},
			want: fosite.ErrInvalidGrant,
			hint: `"aud" (audience) claim containing a value`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fx := newGrantFixture(t, "issuer-a")
			_, err := fx.handle(fx.assertion("issuer-a", "subject-1", tc.jti, tc.mutate))
			requireGrantError(t, err, tc.want)
			assert.Contains(t, fosite.ErrorToRFC6749Error(err).HintField, tc.hint)
			if tc.jti != "" {
				assert.NotContains(t, fx.store.BlacklistedJTIs, tc.jti,
					"a failed request must not consume the jti")
			}
		})
	}

	t.Run("replay is reported as a distinct error category", func(t *testing.T) {
		fx := newGrantFixture(t, "issuer-a")
		assertion := fx.assertion("issuer-a", "subject-1", "jti-dup", nil)

		_, err := fx.handle(assertion)
		require.NoError(t, err)
		_, err = fx.handle(assertion)
		requireGrantError(t, err, fosite.ErrJTIKnown)

		// Every other rejection in this handler is invalid_grant; replay is
		// the one that must not be confused with a malformed or expired JWT.
		assert.NotEqual(t, fosite.ErrInvalidGrant.ErrorField, fosite.ErrorToRFC6749Error(err).ErrorField)

		rec := httptest.NewRecorder()
		errorWriter := &fosite.Fosite{Config: &fosite.Config{}}
		errorWriter.WriteAccessError(context.Background(), rec, nil, err)

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "jti_known", body["error"])
	})
}

// Ensure the fixture's request rejects an unsupported grant type before any
// jti handling, which keeps the error categories above unambiguous.
func TestGrantHandler_ErrorSemanticsPreconditions(t *testing.T) {
	fx := newGrantFixture(t, "issuer-a")
	request := fosite.NewAccessRequest(new(fosite.DefaultSession))
	request.Client = &fosite.DefaultClient{ID: "client", GrantTypes: []string{grantTypeJWTBearer}}
	request.GrantTypes = []string{"authorization_code"}
	request.Form = url.Values{}

	err := fx.handler.HandleTokenEndpointRequest(context.Background(), request)
	requireGrantError(t, err, fosite.ErrUnknownRequest)
	assert.Empty(t, fx.store.BlacklistedJTIs)
}
