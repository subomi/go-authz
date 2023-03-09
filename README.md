# go-authz <br /> [![Go Reference](https://pkg.go.dev/badge/github.com/Subomi/go-authz.svg)](https://pkg.go.dev/github.com/Subomi/go-authz)
`go-authz` is an authorization library based on policies and rule functions. The goal is to have declarative policies in go alongside one simple API for granting and denying access.

## Installation
```bash
 $ go get github.com/Subomi/go-authz
```

## Usage
```go
package main

// Policy Definition
type ProjectPolicy {
    *authz.BasePolicy
}

func (pp *ProjectPolicy) GetAll(ctx context.Context) error {
    // logic for granting access.
    return nil
}

func (pp *ProjectPolicy) Delete(ctx context.Context, p Project) error {
    return nil
}

func (pp *ProjectPolicy) GetName() string {
    return "project"
}

func ApproveGuestAccess(ctx context.Context, resource interface{}) error {
    return nil
}

func main() {
    a := authz.NewAuthz(&AuthzOpts{})

    // Register a rule on the default policy.
    err := authz.RegisterRule("validate-guess-access", authz.RuleFunc(ApproveGuestAccess))


    // Register a policy.
    err := authz.RegisterPolicy(func() authz.Policy {
        po := &ProjectPolicy{
            BasePolicy: NewBasePolicy(),
        }

        po.SetRule("getall", authz.RuleFunc(po.GetAll))
        po.SetRule("delete", authz.RuleFunc(po.Delete))

        return po
    }

    if err != nil {
       return err 
    }

    // Set authCtx in context ideally immediately after authentication.
    ctx := a.SetAuthCtx(r.Context(), authUser)

    // Grant or Deny Permission
    err := a.Authorize(ctx, "project.create", resource)
    if err != nil {
	    // access denied
	    return err
    }
}
```
