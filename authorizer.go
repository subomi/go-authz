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

	// ErrInvalidResource is the error we return when resource does not match method signature
	// expected type.
	ErrInvalidResource = errors.New("resource does not match")
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

func (a *Authorizer) Authorize(ctx context.Context, p interface{}, m string, res interface{}) error {
	// 1. reflect policy struct.
	v := reflect.ValueOf(p)

	// 2. normalize method name.
	m = strcase.ToCamel(m)

	// 3. retrieve method func from policy struct.
	me := v.MethodByName(m)
	if !me.IsValid() {
		return ErrMethodNotAvailable
	}

	// 4. Validate resource
	mT := me.Type().In(1).Name()
	argT := reflect.TypeOf(res).Name()

	if mT != argT {
		return ErrInvalidResource
	}

	in := []reflect.Value{
		reflect.ValueOf(ctx),
		reflect.ValueOf(res),
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
