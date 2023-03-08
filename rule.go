package goauthz

import "context"

type RuleStore map[string]Rule

type Rule interface {
	Authorize(ctx context.Context, resource interface{}) error
}

// Adapter type to turn a func to a Rule type
// rule := RuleFunc(fn)
type RuleFunc func(ctx context.Context, resource interface{}) error

func (f RuleFunc) Authorize(ctx context.Context, resource interface{}) error {
	return f(ctx, resource)
}
