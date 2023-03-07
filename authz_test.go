package goauthz

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type project struct{}
type object struct{}
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
	tests := map[string]struct {
		authCtx       interface{}
		rule          string
		resource      interface{}
		assertion     require.ErrorAssertionFunc
		expectedError error
	}{
		"should_return_error_when_rule_is_not_found": {
			authCtx:       &authCtx{},
			rule:          "invalid.rule",
			resource:      nil,
			assertion:     require.NoError,
			expectedError: ErrRuleNotFound,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Arrange
			authz := NewAuthz(&AuthzOpts{})
			ctx := authz.SetAuthCtx(context.Background(), tc.authCtx)

			// Act.
			err := authz.Authorize(ctx, tc.rule, tc.resource)

			// Assert.
			tc.assertion(t, err)
		})
	}
}
