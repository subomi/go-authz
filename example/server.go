package main

import (
	"context"
	"fmt"

	authz "github.com/Subomi/go-authz"
)

type authCtx struct {
	username string
}

// Policy Definition
type ProjectPolicy struct {
	authCtx authCtx
}

type Project struct {
	UID  string
	Name string
}

func (pp *ProjectPolicy) Get(ctx context.Context, p Project) error {
	// logic for granting access.
	return nil
}

func main() {
	a := authz.NewAuthorizer(&authz.AuthorizerOptions{})

	// Register Policies.
	a.RegisterPolicy("project", func() interface{} {
		return &ProjectPolicy{}
	})

	resource := &Project{}

	// Grant or Deny Permission
	err := a.Authorize(context.Background(), resource, "project", "get")
	if err != nil {
		// access denied
		fmt.Println(err)
	}
}
