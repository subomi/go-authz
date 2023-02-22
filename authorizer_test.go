package goauthz

import (
	"context"
	"errors"
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

type invalidauthCtx struct{}

func (a *invalidauthCtx) Role() error {
	return errors.New("Invalid authCtx")
}

// Policy Stubs
type policyWithoutMethod struct{}

type policyWithNonPointerAuthCtx struct {
	AuthCtx authCtx
}

func (pp *policyWithNonPointerAuthCtx) Create(ctx context.Context, p *project) error {
	return nil
}

type policyMethodParameterMismatch struct{}

func (p *policyMethodParameterMismatch) Create(ctx context.Context, o object) error {
	return nil
}

type validPolicyWithPointerAuthCtx struct {
	AuthCtx *authCtx
}

func (pp *validPolicyWithPointerAuthCtx) Create(ctx context.Context, p *project) error {
	if pp.AuthCtx.Role() != nil {
		// refuse access.
		return errors.New("Unauthorised")
	}

	// grant access.
	return nil
}

func Test_Authorize(t *testing.T) {
	tests := map[string]struct {
		authCtx        interface{}
		resource       interface{}
		policy         string
		method         string
		policyFn       PolicyFn
		authorizerOpts *AuthorizerOptions
		expectedError  error
		assertion      require.ErrorAssertionFunc
	}{
		"should_return_an_error_when_policy_does_not_exist": {
			authCtx:        &authCtx{},
			resource:       &project{},
			policy:         "InvalidPolicy",
			method:         "InvalidMethod",
			policyFn:       nil,
			authorizerOpts: &AuthorizerOptions{},
			expectedError:  ErrPolicyNotFound,
			assertion:      require.Error,
		},
		"should_grant_access_to_a_valid_policy": {
			authCtx:  &authCtx{},
			resource: &project{},
			policy:   "validPolicyWithPointerAuthCtx",
			method:   "Create",
			policyFn: func() interface{} {
				return &validPolicyWithPointerAuthCtx{}
			},
			authorizerOpts: &AuthorizerOptions{},
			expectedError:  nil,
			assertion:      require.NoError,
		},
		"should_return_an_error_when_authCtx_mismatch": {
			authCtx:  authCtx{},
			resource: &project{},
			policy:   "validpolicyWithPointerAuthCtx",
			method:   "Create",
			policyFn: func() interface{} {
				return &validPolicyWithPointerAuthCtx{}
			},
			authorizerOpts: &AuthorizerOptions{},
			expectedError:  ErrAuthCtxTypeMismatch,
			assertion:      require.Error,
		},
		"should_return_an_error_when_auth_ctx_is_missing": {
			authCtx:  nil,
			resource: &project{},
			policy:   "policyWithNonPointerAuthCtx",
			method:   "Create",
			policyFn: func() interface{} {
				return &policyWithNonPointerAuthCtx{}
			},
			authorizerOpts: &AuthorizerOptions{},
			expectedError:  ErrInvalidAuthCtx,
			assertion:      require.Error,
		},
		"should_return_error_when_policy_does_not_have_method": {
			authCtx:  &authCtx{},
			resource: &project{},
			policy:   "policyWithoutMethod",
			method:   "InvalidMethod",
			policyFn: func() interface{} {
				return &policyWithoutMethod{}
			},
			authorizerOpts: &AuthorizerOptions{},
			expectedError:  ErrMethodNotAvailable,
			assertion:      require.Error,
		},
		"should_return_error_when_there_is_a_concrete_type_mismatch": {
			authCtx:       &authCtx{},
			policy:        "policyMethodParameterMismatch",
			method:        "Create",
			resource:      &project{},
			expectedError: ErrInvalidResource,
			assertion:     require.Error,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			authz := NewAuthorizer(tc.authorizerOpts)

			if tc.policyFn != nil {
				authz.RegisterPolicy(tc.policy, tc.policyFn)
			}

			ctx := authz.SetAuthCtx(context.Background(), tc.authCtx)

			// Act.
			err := authz.Authorize(ctx, tc.resource, tc.policy, tc.method)

			// Assert.
			tc.assertion(t, err)
		})
	}
}

func Test_RegisterPolicy(t *testing.T) {
	tests := map[string]struct{}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
		}
	}
}
