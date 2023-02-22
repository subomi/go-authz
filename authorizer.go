package goauthz

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/iancoleman/strcase"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// ErrMethodNotAvailable is the error we return when we can't find a method on a policy.
	ErrMethodNotAvailable = errors.New("method not available on policy")

	// ErrInvalidResource is the error we return when resource does not match method signature
	// expected type.
	ErrInvalidResource = errors.New("resource does not match")

	// ErrInvalidAuthCtx is the error we return when an invalid authctx is sent in.
	ErrInvalidAuthCtx = errors.New("an invalid auth context was provided")

	// ErrAuthCtxTypeMismatch is returned if the policy's authCtx and the passed in authCtx des not mathc.
	ErrAuthCtxTypeMismatch = errors.New("authCtx type does not match")

	// ErrInvalidAuthCtxType is returned when the authCtx does not match the config.
	ErrInvalidAuthCtxType = errors.New("invalid authCtx type")

	ErrMisconfiguredPolicyType = errors.New("Policy Type missing SetAuthCtx method")

	ErrPolicyNotFound = errors.New("Policy Not Found")

	ErrRuleArgsLenMismatch = errors.New("Rule args length are not equal")

	ErrRuleArgItemMismatch = errors.New("Rule args item don't match")
)

var (
	AuthCtxKey = "GoAuthzCtx"

	AuthCtxPolicyField = "AuthCtx"
)

type PolicyFn func() interface{}

type PoliciesFn map[string]PolicyFn

type AuthorizerOptions struct {
	authCtxKey  string
	metricsPort string

	initialPoolSize int
	maxPoolSize     int
}

// Authorizer exposes a single API for authorization
type Authorizer struct {
	opts *AuthorizerOptions

	metrics  *metrics
	Registry prometheus.Registerer

	mu            sync.Mutex
	policyStore   map[string]interface{}
	policyFactory map[string]PolicyFn
}

func NewAuthorizer(opts *AuthorizerOptions) *Authorizer {
	// Setup Instrumentation
	reg := prometheus.NewRegistry()
	m := NewMetrics(reg)

	if opts.metricsPort != "" {
		httpServeMux := http.NewServeMux()
		httpServeMux.Handle("/metrics", promhttp.HandlerFor(
			reg,
			promhttp.HandlerOpts{
				// Pass custom registry
				Registry: reg,
			},
		))

		metricsSrv := &http.Server{
			Addr:    fmt.Sprintf(":%s", opts.metricsPort),
			Handler: httpServeMux,
		}

		// Start metrics server.
		go func() {
			err := metricsSrv.ListenAndServe()
			if err != nil && err != http.ErrServerClosed {
				log.Printf("Error: metrics server error: %v", err)
			}
		}()
	}

	return &Authorizer{
		opts:          opts,
		metrics:       m,
		Registry:      reg,
		policyFactory: make(map[string]PolicyFn),
	}
}

func (a *Authorizer) SetAuthCtx(ctx context.Context, authCtx interface{}) context.Context {
	return context.WithValue(ctx, a.opts.authCtxKey, authCtx)
}

func (a *Authorizer) Authorize(ctx context.Context, resource interface{}, policyID, rule string, args ...interface{}) error {
	startTime := time.Now()
	defer a.recordObservation(startTime, policyID, rule)

	// Retrieve Policy
	// 1.0 Retrieve Policy from factory
	policyFn, ok := a.policyFactory[policyID]
	if !ok {
		return ErrPolicyNotFound
	}

	policy := policyFn()

	// 1.1 Retrieve inner policy type.
	pV := reflect.ValueOf(policy)

	// Configure Policy
	// 2.0 Assert authCtx
	authCtx := ctx.Value(a.opts.authCtxKey)

	if err := a.validateAuthCtx(authCtx); err != nil {
		return err
	}

	authCtxValue := reflect.ValueOf(authCtx)
	policyAuthCtxField := pV.Elem().FieldByName(AuthCtxPolicyField)

	if policyAuthCtxField.Kind() == reflect.Invalid {
		return ErrInvalidAuthCtx
	}

	if authCtxValue.Type() != policyAuthCtxField.Type() {
		return ErrAuthCtxTypeMismatch
	}

	policyAuthCtxField.Set(authCtxValue)

	// Call Rule.
	// 3.0 normalize method name.
	rm := strcase.ToCamel(rule)

	// 3.1 retrieve method func from policy type.
	mFn := pV.MethodByName(rm)
	if !mFn.IsValid() {
		return ErrMethodNotAvailable
	}

	rArgs := a.buildArgs(ctx, args)
	if err := a.validateRuleArgs(mFn, rArgs); err != nil {
		return err
	}

	// 5. Return error
	errV := mFn.Call(rArgs)[0]
	errI := errV.Interface()

	err, ok := errI.(error)
	if !ok {
		return nil
	}

	return err
}

func (a *Authorizer) validateAuthCtx(authCtx interface{}) error {
	valueOf := reflect.ValueOf(authCtx)
	if authCtx == nil || (valueOf.Kind() == reflect.Ptr && valueOf.IsNil()) {
		return ErrInvalidAuthCtx
	}

	return nil
}

func (a *Authorizer) buildArgs(ctx context.Context, args ...interface{}) []reflect.Value {
	retVal := []reflect.Value{
		reflect.ValueOf(ctx),
	}

	for i := 0; i < len(args); i++ {
		retVal = append(retVal, reflect.ValueOf(args[i]))
	}

	return retVal
}

func (a *Authorizer) validateRuleArgs(fn reflect.Value, args []reflect.Value) error {
	fnType := fn.Type()
	argCount := fnType.NumIn()

	if argCount != len(args) {
		return ErrRuleArgsLenMismatch
	}

	for i := 0; i < fnType.NumIn(); i++ {
		argT := fnType.In(i)

		if argT.Kind() == args[i].Type().Kind() {
			return ErrRuleArgItemMismatch
		}
	}

	return nil
}

func (a *Authorizer) RegisterPolicy(name string, policyFn PolicyFn) error {
	return nil
}

func (a *Authorizer) RegisterPolicies(policies PoliciesFn) error {
	return nil
}

func (a *Authorizer) registerpolicy(name string, policyFn PolicyFn) error {
	// TODO(subomi): Add locks.
	// TODO(subomi): Validate the policy type has AuthCtx Field.
	// TODO(subomi): Validate policyFn is not nil.
	a.policyFactory[name] = policyFn
	return nil
}

func (a *Authorizer) recordObservation(startTime time.Time, policy, rule string) {
	a.metrics.authorizationRequestsHistogram.With(prometheus.Labels{
		"policy": policy,
		"rule":   rule,
	}).Observe(float64(time.Since(startTime)))
}
