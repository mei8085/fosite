// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pkce

import (
	"context"

	"github.com/ory/x/errorsx"
	"github.com/pkg/errors"

	"github.com/ory/fosite"
)

// ErrPKCERequestSessionConsumed is returned by PKCERequestStorage implementations
// when a PKCE session has already been consumed by a successful token exchange.
//
// It is a sentinel error (not an RFC6749Error) so storage implementations can
// return it together with the original fosite.Requester value. The PKCE handler
// translates it into a stable fosite.ErrInvalidGrant response.
var ErrPKCERequestSessionConsumed = errors.New("PKCE request session has already been consumed")

type PKCERequestStorage interface {
	// GetPKCERequestSession hydrates the PKCE session for the given authorize code
	// signature.
	//
	// If the session was already consumed by a successful token exchange,
	// implementations SHOULD return the original requester together with
	// ErrPKCERequestSessionConsumed instead of fosite.ErrNotFound, so that replays
	// are rejected with a stable result rather than being confused with a request
	// that never had PKCE data.
	GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
	// CreatePKCERequestSession stores the PKCE session for the given authorize code
	// signature.
	CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error
	// DeletePKCERequestSession consumes the PKCE session for the given authorize code
	// signature.
	//
	// It is only called after the code_verifier has been validated successfully.
	// Implementations are free to hard-delete the record or to retain it in a
	// consumed state (returning ErrPKCERequestSessionConsumed from
	// GetPKCERequestSession afterwards); both keep the replay-rejection guarantees.
	DeletePKCERequestSession(ctx context.Context, signature string) error
}

// consumedRequester wraps a PKCE requester that has already been used in a
// successful token exchange. Storage implementations can return it (together
// with ErrPKCERequestSessionConsumed) from GetPKCERequestSession.
type consumedRequester struct {
	fosite.Requester
}

// MarkPKCERequestSessionConsumed wraps requester so that
// IsPKCERequestSessionConsumed reports it as consumed. Storage implementations
// can use this when retaining consumed sessions instead of hard-deleting them.
func MarkPKCERequestSessionConsumed(requester fosite.Requester) fosite.Requester {
	if requester == nil {
		return nil
	}
	if _, ok := requester.(*consumedRequester); ok {
		return requester
	}
	return &consumedRequester{Requester: requester}
}

// IsPKCERequestSessionConsumed reports whether the given requester represents a
// PKCE session that has already been consumed.
func IsPKCERequestSessionConsumed(requester fosite.Requester) bool {
	if requester == nil {
		return false
	}
	_, ok := requester.(*consumedRequester)
	return ok
}

// validatePKCERequestNotConsumed rejects replays of already consumed PKCE
// sessions with a stable invalid_grant result.
func validatePKCERequestNotConsumed(requester fosite.Requester) error {
	if !IsPKCERequestSessionConsumed(requester) {
		return nil
	}
	return errorsx.WithStack(fosite.ErrInvalidGrant.
		WithHint("The PKCE request session has already been used.").
		WithWrap(ErrPKCERequestSessionConsumed).
		WithDebug(ErrPKCERequestSessionConsumed.Error()))
}
