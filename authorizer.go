package goauthz

import (
	"context"
	"errors"
	"reflect"

	"github.com/iancoleman/strcase"
)

var (
	// ErrMethodNotAvailable is the error we return when we can't find a method on a policy.
	ErrMethodNotAvailable = errors.New("method not available on policy")
)

var AuthCtxKey = "GoAuthzCtx"

// Authorizer exposes a single API for authorization
type Authorizer struct {
}

func NewAuthorizer() *Authorizer {
	return &Authorizer{}
}

func (a *Authorizer) SetAuthCtx(ctx context.Context, authCtx interface{}) context.Context {
	return context.WithValue(ctx, AuthCtxKey, authCtx)
}

func (a *Authorizer) Authorize(ctx context.Context, p interface{}, m string, args ...interface{}) error {
	// 1. reflect policy struct.
	v := reflect.ValueOf(p)

	// 2. normalize method name.
	m = strcase.ToCamel(m)

	// 3. retrieve method func from policy struct.
	me := v.MethodByName(m)
	if !me.IsValid() {
		return ErrMethodNotAvailable
	}

	// 4. Identify the number of methods required
	in := []reflect.Value{reflect.ValueOf(ctx)}

	for _, v := range args {
		in = append(in, reflect.ValueOf(v))
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
