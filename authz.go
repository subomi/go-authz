package goauthz

import (
	"context"
	"errors"
	"strings"
	"sync"
)

var (
	// ErrRuleNotFound is the error we return when we can't find a method on a policy.
	ErrRuleNotFound = errors.New("rule not found on policy")

	ErrPolicyAlreadyRegistered = errors.New("Policy already in policy store")
)

const (
	AuthCtxKey       = "GoAuthzCtx"
	DefaultSeperator = "."
)

type AuthzOpts struct {
	authCtxKey string
	seperator  string
}

// Authz exposes a single API for authorization
type Authz struct {
	opts          *AuthzOpts
	defaultPolicy Policy
	policyStore   map[string]Policy
}

func NewAuthz(opts *AuthzOpts) (*Authz, error) {
	if isStringEmpty(opts.seperator) {
		opts.seperator = DefaultSeperator
	}

	if isStringEmpty(opts.authCtxKey) {
		opts.authCtxKey = AuthCtxKey
	}

	defaultPolicy := &DefaultPolicy{
		BasePolicy: NewBasePolicy(),
	}

	authz := &Authz{
		opts:          opts,
		defaultPolicy: defaultPolicy,
		policyStore:   make(map[string]Policy),
	}

	err := authz.RegisterPolicy("default", defaultPolicy)
	if err != nil {
		return nil, err
	}

	return authz, nil
}

func (a *Authz) SetAuthCtx(ctx context.Context, authCtx interface{}) context.Context {
	return context.WithValue(ctx, a.opts.authCtxKey, authCtx)
}

func (a *Authz) Authorize(ctx context.Context, ruleName string, res interface{}) error {
	var po Policy

	namespace, rule, _ := a.parseRuleName(ruleName)

	for k, v := range a.policyStore {
		if k == namespace {
			po = v
			break
		}
	}

	if po == nil {
		po = a.defaultPolicy
	}

	ruleFn, err := po.GetRule(rule)
	if err != nil {
		return err
	}

	return ruleFn.Authorize(ctx, res)
}

func (a *Authz) RegisterRule(name string, rule Rule) {
	namespace, _, n := a.parseRuleName(name)
	if n == 1 {
		name = strings.Join([]string{"default", namespace}, ".")
	}
	a.defaultPolicy.SetRule(name, rule)
}

func (a *Authz) RegisterPolicy(namespace string, policy Policy) error {
	_, ok := a.policyStore[namespace]
	if ok {
		return ErrPolicyAlreadyRegistered
	}

	a.policyStore[namespace] = policy
	return nil
}

func (a *Authz) parseRuleName(ruleName string) (string, string, int) {
	parts := strings.SplitN(ruleName, a.opts.seperator, 2)
	rem := ""

	if len(parts) > 1 {
		rem = parts[1:][0]
	}

	return parts[0], rem, len(parts)
}

type Policy interface {
	GetRule(name string) (Rule, error)
	GetRules() RuleStore
	SetRule(name string, rule Rule)
}

type BasePolicy struct {
	mu    sync.Mutex
	store RuleStore
}

func NewBasePolicy() *BasePolicy {
	return &BasePolicy{
		store: make(RuleStore),
	}
}

func (bP *BasePolicy) SetRule(name string, rule Rule) {
	bP.store[name] = rule
}

func (bP *BasePolicy) GetRule(name string) (Rule, error) {
	rule, ok := bP.store[name]
	if !ok {
		return nil, ErrRuleNotFound
	}

	return rule, nil
}

func (bP *BasePolicy) GetRules() RuleStore {
	return bP.store
}

type DefaultPolicy struct {
	*BasePolicy
}

func isStringEmpty(s string) bool { return len(strings.TrimSpace(s)) == 0 }
