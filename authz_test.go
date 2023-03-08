package goauthz

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type projectPolicy struct {
	*BasePolicy

	name string
}

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

func Test_Authorize(t *testing.T) {
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
