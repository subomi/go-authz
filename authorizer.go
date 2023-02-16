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
)

var AuthCtxKey = "GoAuthzCtx"

type AuthorizerOptions struct {
	authCtxKey  string
	authCtxType string

	metricsPort string

	initialPoolSize int
	maxPoolSize     int
}

// Authorizer exposes a single API for authorization
type Authorizer struct {
	opts *AuthorizerOptions

	metrics  *metrics
	Registry prometheus.Registerer

	mu          sync.Mutex
	policyStore map[string]interface{}
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
		opts:     opts,
		metrics:  m,
		Registry: reg,
	}
}

func (a *Authorizer) SetAuthCtx(ctx context.Context, authCtx interface{}) context.Context {
	return context.WithValue(ctx, AuthCtxKey, authCtx)
}

func (a *Authorizer) Authorize(ctx context.Context, resource, policy, rule string) error {
	startTime := time.Now()
	defer a.recordObservation(startTime, policy, rule)

	// 1. Retrieve Policy from pool.

	// 2. Validate authCtx

	// 3. Validate resource.

	// 4. Invoke rule on policy.

	// 1. reflect policy struct.
	v := reflect.ValueOf(policy)

	// 2. normalize method name.
	rule = strcase.ToCamel(rule)

	// 3. retrieve the rule method from the policy struct.
	me := v.MethodByName(rule)
	if !me.IsValid() {
		return ErrMethodNotAvailable
	}

	// 4. Validate resource
	mT := me.Type().In(1).Name()
	argT := reflect.TypeOf(resource).Name()

	if mT != argT {
		return ErrInvalidResource
	}

	in := []reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(resource),
	}

	// 5. Return error
	ret := me.Call(in)

	if len(ret) > 1 {
		// error.
	}
	errI := ret[0].Interface()

	err, ok := errI.(error)
	if !ok {
		return nil
	}

	return err
}

func (a *Authorizer) RegisterPolicy(name string, policy interface{}) error {
	// TODO(subomi): Add locks
	a.policyStore[name] = policy
	return nil
}

func (a *Authorizer) recordObservation(startTime time.Time, policy, rule string) {
	a.metrics.authorizationRequestsHistogram.With(prometheus.Labels{
		"policy": policy,
		"rule":   rule,
	}).Observe(float64(time.Since(startTime)))
}
