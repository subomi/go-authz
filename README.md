# go-authz


```go
package main

// Policy Definition
type ProjectPolicy {}

func (pp *ProjectPolicy) GetAll(ctx context.Context) error {
    // logic for granting access.
    return nil
}

func (pp *ProjectPolicy) Delete(ctx context.Context, p Project) error {
    return nil
}

func main() {
    a := authz.NewAuthorizer()

    // Set authCtx in context ideally immediately after authentication.
    err := a.SetAuthCtx(r.Context(), authCtx)

    // Grant or Deny Permission
    err := a.Authorize(ctx, resource, policy, method)
    if err != nil {
	    // access denied
	    return err
    }
}
```
