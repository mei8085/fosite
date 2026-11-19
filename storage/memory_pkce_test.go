// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
)

func newPKCERequester(clientID string) fosite.Requester {
	ar := fosite.NewAuthorizeRequest()
	ar.Client = &fosite.DefaultClient{ID: clientID}
	ar.Form.Set("code_challenge", "challenge")
	ar.Form.Set("code_challenge_method", "S256")
	return ar
}

// A consumed PKCE session is retained and reported as invalidated instead of
// being hard-deleted, which keeps replay rejection stable.
func TestMemoryStore_PKCESessionConsumeIsRetained(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	const code = "code-retained"
	req := newPKCERequester("client-1")

	require.NoError(t, s.CreatePKCERequestSession(ctx, code, req))

	got, err := s.GetPKCERequestSession(ctx, code, nil)
	require.NoError(t, err)
	assert.Equal(t, "client-1", got.GetClient().GetID())

	// Consuming keeps the session around in a consumed state.
	require.NoError(t, s.DeletePKCERequestSession(ctx, code))

	got, err = s.GetPKCERequestSession(ctx, code, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidatedPKCERequest), err)
	require.NotNil(t, got)
	assert.Equal(t, "client-1", got.GetClient().GetID())
	assert.True(t, isPKCERequestConsumed(got))

	// Consuming a second time is rejected with the same sentinel error.
	err = s.DeletePKCERequestSession(ctx, code)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidatedPKCERequest), err)
}

// A missing PKCE session keeps the legacy ErrNotFound contract, and consuming
// an unknown session reports not found rather than silently succeeding.
func TestMemoryStore_PKCESessionNotFound(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	got, err := s.GetPKCERequestSession(ctx, "unknown", nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, fosite.ErrNotFound), err)
	assert.Nil(t, got)

	err = s.DeletePKCERequestSession(ctx, "unknown")
	require.Error(t, err)
	assert.True(t, errors.Is(err, fosite.ErrNotFound), err)
}

// Distinct codes never share state: consuming one must not invalidate another.
func TestMemoryStore_PKCESessionsDoNotPolluteEachOther(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()

	require.NoError(t, s.CreatePKCERequestSession(ctx, "code-a", newPKCERequester("client-a")))
	require.NoError(t, s.CreatePKCERequestSession(ctx, "code-b", newPKCERequester("client-b")))

	require.NoError(t, s.DeletePKCERequestSession(ctx, "code-a"))

	_, err := s.GetPKCERequestSession(ctx, "code-a", nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidatedPKCERequest))

	got, err := s.GetPKCERequestSession(ctx, "code-b", nil)
	require.NoError(t, err)
	assert.Equal(t, "client-b", got.GetClient().GetID())
	assert.False(t, isPKCERequestConsumed(got))
}

// Concurrent consume attempts must have exactly one winner; the rest observe
// the invalidated state.
func TestMemoryStore_PKCEConcurrentConsumeSingleWinner(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	const code = "code-race"
	require.NoError(t, s.CreatePKCERequestSession(ctx, code, newPKCERequester("client-race")))

	const goroutines = 100
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	start := make(chan struct{})
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			errs <- s.DeletePKCERequestSession(ctx, code)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)

	ok, invalidated := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrInvalidatedPKCERequest):
			invalidated++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	assert.Equal(t, 1, ok)
	assert.Equal(t, goroutines-1, invalidated)
}

func TestMarkPKCERequestConsumedHelpers(t *testing.T) {
	assert.False(t, isPKCERequestConsumed(nil))
	assert.Nil(t, markPKCERequestConsumed(nil))

	req := newPKCERequester("client-helper")
	marked := markPKCERequestConsumed(req)
	assert.True(t, isPKCERequestConsumed(marked))
	// Idempotent: marking an already marked requester must not re-wrap it.
	assert.Equal(t, marked, markPKCERequestConsumed(marked))
}
