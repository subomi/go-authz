package goauthz

import (
	"context"
	"errors"
	"strings"
	"sync"
)

var (
	// ErrRuleNotFound is the error we return when we can't find a method on a policy.
	ErrRuleNotFound = errors.New("method not found on policy")

	ErrPolicyAlreadyRegistered = errors.New("Policy already in policy store")
)

var AuthCtxKey = "GoAuthzCtx"

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

func NewAuthz(opts *AuthzOpts) *Authz {
	return &Authz{
		opts:          opts,
		defaultPolicy: &DefaultPolicy{},
	}
}

func (a *Authz) SetAuthCtx(ctx context.Context, authCtx interface{}) context.Context {
	return context.WithValue(ctx, a.opts.authCtxKey, authCtx)
}

func (a *Authz) Authorize(ctx context.Context, ruleName string, res interface{}) error {
	var po Policy

	namespace, rule := a.parseRuleName(ruleName)

	for k, v := range a.policyStore {
		if k == namespace {
			po = v
			break
		}
	}

	ruleFn, err := po.GetRule(rule)
	if err != nil {
		return err
	}

	return ruleFn.Authorize(ctx, res)
}

func (a *Authz) RegisterRule(name string, rule Rule) {
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

func (a *Authz) parseRuleName(ruleName string) (string, string) {
	parts := strings.SplitN(ruleName, a.opts.seperator, 2)
	return parts[0], parts[1:][0]
}

type Policy interface {
	GetRule(name string) (Rule, error)
	GetRules() RuleStore
	SetRule(name string, rule Rule)
}

type basePolicy struct {
	mu    sync.Mutex
	store RuleStore
}

func (bP *basePolicy) SetRule(name string, rule Rule) {
	bP.store[name] = rule
}

func (bP *basePolicy) GetRule(name string) (Rule, error) {
	rule, ok := bP.store[name]
	if !ok {
		return nil, ErrRuleNotFound
	}

	return rule, nil
}

func (bP *basePolicy) GetRules() RuleStore {
	return bP.store
}

// TODO(subomi): Apply mutex
type DefaultPolicy struct {
	basePolicy
}

type ProjectPolicy struct {
	basePolicy
}

func NewProjectPolicy() *ProjectPolicy {
	pp := &ProjectPolicy{}

	pp.SetRule("project.create", RuleFunc(func(ctx context.Context, res interface{}) error {
		return nil
	}))

	return pp
}
