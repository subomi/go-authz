# go-authz
go-authz is a simple authorization library for Golang. It is based off policy types with an attempt to port [Action Policy](https://github.com/palkan/action_policy) from programming in Ruby.

## Design Decisions
- Simple consistent API for Authorization.
- Very fast authorization queries.

## Usage
```go
package main

// Policy Definition
type ProjectPolicy {
    AuthCtx *authCtx
    AuthCtx authCtx
}

func (pp *ProjectPolicy) GetAll(ctx context.Context, args ...interface{}) error {
    // logic for granting access.
    return nil
}

func (pp *ProjectPolicy) Get(ctx context.Context, resource Project, args ...interface{}) error {

}

func main() {
    a := authz.NewAuthorizer()

    // Register Policies.
    a.RegisterPolicy("project", func() interface{} {
        return &policies.ProjectPolicyOpts{
		    OrganisationRepo:       mongo.NewOrgRepo(a.A.Store),
		    OrganisationMemberRepo: mongo.NewOrgMemberRepo(a.A.Store),
	    }
    })

    // Set authCtx in context ideally immediately after authentication.
    err := a.SetAuthCtx(r.Context(), authCtx)

    // Grant or Deny Permission
    err := a.Authorize(ctx, resource, policy, rule)
    if err != nil {
	    // access denied
	    return err
    }
}
```

## Performance
