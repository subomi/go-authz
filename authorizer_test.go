package goauthz

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

type project struct{}
type authCtx struct{}

func (a *authCtx) Role() error {
	return nil
}

type policyWithoutStruct struct{}

type projectPolicy struct {
}

func (pp *projectPolicy) Delete(ctx context.Context, args ...interface{}) error {
	// retrieve ctx

	// first arg is resource.

	// second arg is anything I choose.
	return nil
}

func (pp *projectPolicy) Create(ctx context.Context, r interface{}) error {
	// retrieve authCtx
	authCtx := ctx.Value(AuthCtxKey).(*authCtx)

	if authCtx.Role() != nil {
		// refuse access.
		return errors.New("Unauthorised")
	}

	// grant access.
	return nil
}

func (pp *projectPolicy) XDelete(ctx context.Context, p project) error {

	// print resource
	fmt.Println(p)

	return nil
}

func Test_Authorize(t *testing.T) {
	tests := map[string]struct {
		authCtx       interface{}
		policy        interface{}
		method        string
		args          []interface{}
		expectedError error
	}{
		"should_grant_access_to_a_valid_policy": {
			authCtx:       &authCtx{},
			policy:        projectPolicy{},
			method:        "Create",
			args:          []interface{}{&project{}},
			expectedError: nil,
		},
		"should_return_error_when_policy_does_not_have_method": {
			authCtx:       &authCtx{},
			policy:        &policyWithoutStruct{},
			method:        "InvalidMethod",
			args:          []interface{}{},
			expectedError: ErrMethodNotAvailable,
		},
		"should_return_error_when_policy_is_not_a_struct": {
			authCtx:       &authCtx{},
			policy:        "subomi",
			method:        "InvalidMethodXXX",
			args:          []interface{}{},
			expectedError: ErrMethodNotAvailable,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			authz := NewAuthorizer()
			ctx := authz.SetAuthCtx(context.Background(), tc.authCtx)

			// Act.
			err := authz.Authorize(ctx, tc.policy, tc.method, tc.args)

			// Assert.
			if tc.expectedError != nil {
				require.ErrorIs(t, err, tc.expectedError)
			}
		})
	}
}
