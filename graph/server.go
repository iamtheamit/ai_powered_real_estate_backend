package graph

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/playground"
	"github.com/golang-jwt/jwt/v5"
)

func StartServer(port string) {
	log.Println("🚀 Starting GraphQL Server...")

	c := Config{Resolvers: &Resolver{}}

	// ✅ Implement the `@auth` directive
	c.Directives.Auth = func(ctx context.Context, obj interface{}, next graphql.Resolver, role *string) (interface{}, error) {
		user, ok := ctx.Value(UserKey).(jwt.MapClaims)
		if !ok {
			log.Println("🚨 Unauthorized: No user found in context")
			return nil, fmt.Errorf("unauthorized: no user in context")
		}

		if role != nil {
			userRole, ok := user["role"].(string)
			log.Printf("🔎 Checking role: expected=%s, got=%s", *role, userRole)

			if !ok || userRole != *role {
				return nil, fmt.Errorf("forbidden: requires role %s, got %v", *role, user["role"])
			}
		}

		return next(ctx)
	}

	log.Println("✅ GraphQL schema initialized")

	// Create a new GraphQL server
	srv := handler.NewDefaultServer(NewExecutableSchema(c))

	log.Println("✅ GraphQL server created")

	// ✅ Apply AuthMiddleware to GraphQL handler
	http.Handle("/query", AuthMiddleware(srv))
	http.Handle("/", playground.Handler("GraphQL Playground", "/query"))

	log.Printf("🔗 Connect to http://localhost:%s/ for GraphQL playground", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
