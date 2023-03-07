package goauthz

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type project struct{}
type projectPolicy struct {
	*BasePolicy

	name string
}

type authCtx struct{}

func (a *authCtx) Role() error {
	return nil
}

func CreateProjectRule(ctx context.Context, project interface{}) error {
	// retrieve authCtx
	authCtx := ctx.Value(AuthCtxKey).(*authCtx)

	if authCtx.Role() != nil {
		// refuse access.
		return errors.New("Unauthorised")
	}

	// grant access.
	return nil
}

func Test_Authorize(t *testing.T) {
	policy := &projectPolicy{
		name:       "project",
		BasePolicy: NewBasePolicy(),
	}

	policy.SetRule("project.create", RuleFunc(CreateProjectRule))

	tests := map[string]struct {
		authCtx       interface{}
		policy        Policy
		rule          string
		resource      interface{}
		assertion     require.ErrorAssertionFunc
		expectedError error
	}{
		"should_return_error_when_rule_is_not_found": {
			authCtx:       &authCtx{},
			policy:        policy,
			rule:          "rule",
			resource:      nil,
			assertion:     require.Error,
			expectedError: ErrRuleNotFound,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			authz, _ := NewAuthz(&AuthzOpts{})
			authz.RegisterPolicy("project", policy)

			ctx := authz.SetAuthCtx(context.Background(), tc.authCtx)

			// Act.
			err := authz.Authorize(ctx, tc.rule, tc.resource)

			// Assert.
			tc.assertion(t, err)
		})
	}
}
