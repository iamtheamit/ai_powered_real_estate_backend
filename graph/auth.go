package graph

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type ErrorResponse struct {
	Message string `json:"message"`
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("🔍 AuthMiddleware triggered for:", r.URL.Path)

		buf, _ := io.ReadAll(r.Body)
		bodyStr := string(buf)
		log.Println("📩 Request Body:", bodyStr)
		r.Body = io.NopCloser(bytes.NewBuffer(buf))

		if strings.Contains(bodyStr, "register") || strings.Contains(bodyStr, "login") {
			next.ServeHTTP(w, r)
			return
		}

		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			log.Println("🚨 No token found, rejecting request")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		tokenString = strings.TrimPrefix(tokenString, "Bearer ")
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte("mysecretkey"), nil
		})

		if err != nil || !token.Valid {
			log.Println("🚨 Invalid token:", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			log.Println("🚨 Invalid token claims")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		log.Println("✅ Token Valid - Claims:", claims)
		ctx := context.WithValue(r.Context(), UserKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}