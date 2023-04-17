package main

import (
	"context"
	"io"
	"log"
	"net/http"

	authz "github.com/Subomi/go-authz"
)

type Project struct {
	ID   string
	Name string
}

type authzCtx struct {
	Username string
}

func main() {
	a, err := authz.NewAuthz(&authz.AuthzOpts{})
	if err != nil {
		log.Fatal(err)
	}

	// Register Rules.
	rule := authz.RuleFunc(func(ctx context.Context, resource interface{}) error {
		return nil
	})
	a.RegisterRule("project.create", rule)

	authCtx := authzCtx{Username: "guest"}
	a.SetAuthCtx(context.Background(), authCtx)

	helloHandler := func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "Hello, world!\n")
	}

	restrictedHandler := func(w http.ResponseWriter, req *http.Request) {
		// Grant or Deny Permission
		err := a.Authorize(context.Background(), "project.default", nil)
		if err != nil {
			// access denied
			io.WriteString(w, "Access Denied!\n")
			return
		}
		io.WriteString(w, "Access Granted!\n")
	}

	http.HandleFunc("/hello", helloHandler)
	http.HandleFunc("/restricted", restrictedHandler)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
