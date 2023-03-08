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

	ErrInvalidRuleName = errors.New("Rule name provided was invalid")
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

	err := authz.RegisterPolicy(defaultPolicy)
	if err != nil {
		return nil, err
	}

	return authz, nil
}

func (a *Authz) SetAuthCtx(ctx context.Context, authCtx interface{}) context.Context {
	return context.WithValue(ctx, a.opts.authCtxKey, authCtx)
}

func (a *Authz) Authorize(ctx context.Context, ruleName string, res interface{}) error {
	namespace, rule, n := a.parseRuleName(ruleName)
	if n == 0 {
		return ErrInvalidRuleName
	}

	var po Policy
	po = a.policyLookup(namespace)

	if po == nil {
		po = a.defaultPolicy
	}

	ruleFn, err := po.GetRule(rule)
	if err != nil {
		return err
	}

	return ruleFn.Authorize(ctx, res)
}

func (a *Authz) RegisterRule(name string, rule Rule) error {
	namespace, _, n := a.parseRuleName(name)
	if n == 0 {
		return ErrInvalidRuleName
	}

	po := a.policyLookup(namespace)
	if po == nil {
		po = a.defaultPolicy
	}

	po.SetRule(name, rule)
	return nil
}

func (a *Authz) RegisterPolicy(po Policy) error {
	_, ok := a.policyStore[po.GetName()]
	if ok {
		return ErrPolicyAlreadyRegistered
	}

	a.policyStore[po.GetName()] = po
	return nil
}

func (a *Authz) policyLookup(namespace string) Policy {
	var po Policy
	for k, v := range a.policyStore {
		if k == namespace {
			po = v
			break
		}
	}

	return po
}

func (a *Authz) parseRuleName(ruleName string) (string, string, int) {
	if isStringEmpty(ruleName) {
		return "", "", 0
	}

	parts := strings.SplitN(ruleName, a.opts.seperator, 2)

	if len(parts) == 1 {
		return "", parts[0], 1
	}

	return parts[0], parts[1:][0], len(parts)
}

type Policy interface {
	GetName() string
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

func (df *DefaultPolicy) GetName() string {
	return "default"
}

func isStringEmpty(s string) bool { return len(strings.TrimSpace(s)) == 0 }
