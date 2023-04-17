package goauthz

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type authCtx struct {
	Role string
}

type resource struct{}

func CreateResourceRule(ctx context.Context, project interface{}) error {
	// retrieve authCtx
	authCtx := ctx.Value(AuthCtxKey).(*authCtx)

	if authCtx.Role != "Admin" {
		// refuse access.
		return errors.New("Unauthorised")
	}

	// grant access.
	return nil
}

func Test_Authorize_With_Rule(t *testing.T) {
	tests := map[string]struct {
		authCtx       interface{}
		rule          string
		resource      interface{}
		assertion     require.ErrorAssertionFunc
		expectedError error
	}{
		"should_return_error_when_rule_is_not_found": {
			authCtx:       &authCtx{},
			rule:          "rule",
			resource:      nil,
			assertion:     require.Error,
			expectedError: ErrRuleNotFound,
		},
		"should_return_unauthorized_error_when_rule_fails": {
			authCtx: &authCtx{
				Role: "Guest",
			},
			rule:      "create-resource",
			resource:  &resource{},
			assertion: require.Error,
		},
		"should_return_nil_error_when_rule_passes": {
			authCtx: &authCtx{
				Role: "Admin",
			},
			rule:          "create-resource",
			resource:      &resource{},
			assertion:     require.NoError,
			expectedError: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			authz, _ := NewAuthz(&AuthzOpts{})
			_ = authz.RegisterRule("create-resource", RuleFunc(CreateResourceRule))

			ctx := authz.SetAuthCtx(context.Background(), tc.authCtx)

			// Act.
			err := authz.Authorize(ctx, tc.rule, tc.resource)

			// Assert.
			tc.assertion(t, err)
		})
	}
}

type InvalidPolicy struct {
	*BasePolicy
}

func (ip *InvalidPolicy) GetName() string {
	return "invalid"
}

type projectPolicy struct {
	*BasePolicy
}

func (pp *projectPolicy) GetName() string {
	return "project"
}

func (pp *projectPolicy) Create(ctx context.Context, res interface{}) error {
	return nil
}

func Test_Authorize_With_Policy(t *testing.T) {
	tests := map[string]struct {
		authCtx       interface{}
		policy        func() Policy
		rule          string
		resource      interface{}
		assertion     require.ErrorAssertionFunc
		expectedError error
	}{
		"should_return_error_when_policy_and_rule_combination_is_not_found": {
			authCtx: &authCtx{},
			policy: func() Policy {
				po := &InvalidPolicy{
					BasePolicy: NewBasePolicy(),
				}

				return po
			},
			rule:          "project.create",
			resource:      &resource{},
			assertion:     require.Error,
			expectedError: ErrRuleNotFound,
		},
		"should_return_nil_error_when_rule_passes": {
			authCtx: &authCtx{},
			policy: func() Policy {
				newprojectPolicy := func() *projectPolicy {
					po := &projectPolicy{
						BasePolicy: NewBasePolicy(),
					}

					po.SetRule("create", RuleFunc(po.Create))
					return po
				}

				return newprojectPolicy()
			},
			rule:          "project.create",
			resource:      &resource{},
			assertion:     require.NoError,
			expectedError: nil,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			authz, _ := NewAuthz(&AuthzOpts{})
			_ = authz.RegisterPolicy(tc.policy())

			ctx := authz.SetAuthCtx(context.Background(), tc.authCtx)

			// Act.
			err := authz.Authorize(ctx, tc.rule, tc.resource)

			// Assert.
			tc.assertion(t, err)
		})
	}
}
