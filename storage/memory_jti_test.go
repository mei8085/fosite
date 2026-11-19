// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/fosite"
)

// The in-memory store is the reference implementation for the two JTI replay
// primitives used by both assertion entry points. The tests below pin the
// window semantics that the assertion handlers rely on: a JTI is replayable
// only once its stored expiry has passed, and "expiry" is exclusive
// (exp.After(now)), which makes an entry with exp == now already reusable.
func TestMemoryStore_ClientAssertionJWT_ReplayBoundaries(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown jti is accepted", func(t *testing.T) {
		s := NewMemoryStore()
		require.NoError(t, s.ClientAssertionJWTValid(ctx, "unknown"))
	})

	t.Run("first use is recorded and second use is rejected", func(t *testing.T) {
		s := NewMemoryStore()
		exp := time.Now().Add(time.Hour).Round(time.Second)
		require.NoError(t, s.SetClientAssertionJWT(ctx, "jti-1", exp))

		require.ErrorIs(t, s.ClientAssertionJWTValid(ctx, "jti-1"), fosite.ErrJTIKnown)
		require.Equal(t, exp, s.BlacklistedJTIs["jti-1"])

		// Re-marking an unexpired JTI is rejected and must not move the
		// recorded expiry, otherwise a replay could extend its own window.
		require.ErrorIs(t, s.SetClientAssertionJWT(ctx, "jti-1", exp.Add(time.Hour)), fosite.ErrJTIKnown)
		require.Equal(t, exp, s.BlacklistedJTIs["jti-1"])
	})

	t.Run("expiry exactly at now is already reusable", func(t *testing.T) {
		s := NewMemoryStore()
		now := time.Now()
		require.NoError(t, s.SetClientAssertionJWT(ctx, "jti-boundary", now))

		// ClientAssertionJWTValid only rejects if exp is strictly after now.
		require.NoError(t, s.ClientAssertionJWTValid(ctx, "jti-boundary"))
		// And the entry may then be written again, because the duplicate
		// check runs after expired entries are pruned.
		require.NoError(t, s.SetClientAssertionJWT(ctx, "jti-boundary", now.Add(time.Hour)))
		require.ErrorIs(t, s.ClientAssertionJWTValid(ctx, "jti-boundary"), fosite.ErrJTIKnown)
	})

	t.Run("entries whose window has passed do not block reuse", func(t *testing.T) {
		s := NewMemoryStore()
		require.NoError(t, s.SetClientAssertionJWT(ctx, "jti-old", time.Now().Add(-time.Minute)))

		require.NoError(t, s.ClientAssertionJWTValid(ctx, "jti-old"))
		require.NoError(t, s.SetClientAssertionJWT(ctx, "jti-old", time.Now().Add(time.Hour)))
		require.ErrorIs(t, s.ClientAssertionJWTValid(ctx, "jti-old"), fosite.ErrJTIKnown)
	})

	t.Run("writing prunes expired entries but keeps live ones", func(t *testing.T) {
		s := NewMemoryStore()
		// Margins are wide enough that execution time cannot flip a case.
		now := time.Now()
		require.NoError(t, s.SetClientAssertionJWT(ctx, "expired", now.Add(-time.Hour)))
		require.NoError(t, s.SetClientAssertionJWT(ctx, "live", now.Add(time.Hour)))

		require.NoError(t, s.SetClientAssertionJWT(ctx, "new", now.Add(time.Hour)))

		assert.NotContains(t, s.BlacklistedJTIs, "expired", "expired entries are pruned on write")
		assert.Contains(t, s.BlacklistedJTIs, "live")
		assert.Contains(t, s.BlacklistedJTIs, "new")
	})

	t.Run("a recorded expiry immediately before now is no longer blocking", func(t *testing.T) {
		// This is the exclusive-boundary case without the flakiness of an
		// exp that equals time.Now(): an exp in the recent past never counts
		// as live, and the record can be written again.
		s := NewMemoryStore()
		now := time.Now()
		require.NoError(t, s.SetClientAssertionJWT(ctx, "just-expired", now.Add(-time.Nanosecond)))

		require.NoError(t, s.ClientAssertionJWTValid(ctx, "just-expired"))
		require.NoError(t, s.SetClientAssertionJWT(ctx, "just-expired", now.Add(time.Hour)))
		require.ErrorIs(t, s.ClientAssertionJWTValid(ctx, "just-expired"), fosite.ErrJTIKnown)
	})
}

// IsJWTUsed and MarkJWTUsedForTime are the RFC7523-facing view of the same
// primitives. Note that IsJWTUsed deliberately collapses storage errors into
// "used" so that a broken store fails closed.
func TestMemoryStore_IsJWTUsed_And_MarkJWTUsedForTime(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown jti is not used", func(t *testing.T) {
		s := NewMemoryStore()
		used, err := s.IsJWTUsed(ctx, "unknown")
		require.NoError(t, err)
		assert.False(t, used)
	})

	t.Run("marked jti is used for exactly the given expiry", func(t *testing.T) {
		s := NewMemoryStore()
		exp := time.Now().Add(30 * time.Minute).Round(time.Second)
		require.NoError(t, s.MarkJWTUsedForTime(ctx, "jti-1", exp))

		used, err := s.IsJWTUsed(ctx, "jti-1")
		require.NoError(t, err)
		assert.True(t, used)
		assert.Equal(t, exp, s.BlacklistedJTIs["jti-1"])
	})

	t.Run("jti whose mark has expired is not used", func(t *testing.T) {
		s := NewMemoryStore()
		require.NoError(t, s.MarkJWTUsedForTime(ctx, "jti-expired", time.Now().Add(-time.Second)))

		used, err := s.IsJWTUsed(ctx, "jti-expired")
		require.NoError(t, err)
		assert.False(t, used)
	})

	t.Run("marking the same unexpired jti twice reports the storage error", func(t *testing.T) {
		s := NewMemoryStore()
		exp := time.Now().Add(time.Hour)
		require.NoError(t, s.MarkJWTUsedForTime(ctx, "jti-dup", exp))

		err := s.MarkJWTUsedForTime(ctx, "jti-dup", exp.Add(time.Hour))
		require.Error(t, err)
		assert.True(t, errors.Is(err, fosite.ErrJTIKnown))
		assert.Equal(t, exp.Round(0), s.BlacklistedJTIs["jti-dup"].Round(0))
	})
}
