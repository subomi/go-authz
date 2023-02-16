package goauthz

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// Resource Stub.
type project struct{}
type object struct{}

// Authorization Context Stub.
type authCtx struct{}

func (a *authCtx) Role() error {
	return nil
}

// Policy Stub
type policyMethodParameterMismatch struct{}

func (p *policyMethodParameterMismatch) Create(ctx context.Context, o object) error {
	return nil
}

type policyWithoutMethod struct{}

type projectPolicy struct {
	authCtx authCtx
}

func (pp *projectPolicy) Create(ctx context.Context, p *project) error {
	if pp.authCtx.Role() != nil {
		// refuse access.
		return errors.New("Unauthorised")
	}

	// grant access.
	return nil
}

func (pp *projectPolicy) Delete(ctx context.Context, authCtx authCtx, p project) error {

	// print resource
	fmt.Println(p)

	return nil
}

func (pp *projectPolicy) SetAuthCtx(ctx authCtx) {
	pp.authCtx = ctx
}

func Test_Authorize(t *testing.T) {
	tests := map[string]struct {
		authCtx       interface{}
		policy        interface{}
		method        string
		resource      interface{}
		expectedError error
	}{
		"should_grant_access_to_a_valid_policy": {
			authCtx:       &authCtx{},
			policy:        &projectPolicy{},
			method:        "Create",
			resource:      &project{},
			expectedError: nil,
		},
		"should_return_error_on_valid_policy_when_auth_ctx_is_missing": {
			authCtx:       nil,
			policy:        &projectPolicy{},
			method:        "Create",
			resource:      &project{},
			expectedError: ErrInvalidAuthCtx,
		},
		"should_return_error_when_policy_does_not_have_method": {
			authCtx:       &authCtx{},
			policy:        &policyWithoutMethod{},
			method:        "InvalidMethod",
			resource:      nil,
			expectedError: ErrMethodNotAvailable,
		},
		"should_return_error_when_policy_is_not_a_struct": {
			authCtx:       &authCtx{},
			policy:        "subomi",
			method:        "InvalidMethodXXX",
			resource:      nil,
			expectedError: ErrMethodNotAvailable,
		},
		"should_return_error_when_there_is_a_concrete_type_mismatch": {
			authCtx:       &authCtx{},
			policy:        &policyMethodParameterMismatch{},
			method:        "Create",
			resource:      &project{},
			expectedError: ErrInvalidResource,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			authz := NewAuthorizer()
			ctx := authz.SetAuthCtx(context.Background(), tc.authCtx)

			// Act.
			err := authz.Authorize(ctx, tc.resource, tc.policy, tc.method)

			// Assert.
			if tc.expectedError != nil {
				require.ErrorIs(t, err, tc.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
