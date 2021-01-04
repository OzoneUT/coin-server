package middleware

import (
	"coin-server/controllers"
	"log"
	"net/http"
)

// EnsureAuthMW is a middleware function which ensures JWT tokens are valid before
// allowing the request to move forward. This is necessary for routes like /account,
// and /logout, which may assume the client is validated.
func EnsureAuthMW(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := controllers.TokenValid(r); err != nil {
			log.Println("Token couldn't be validated:", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}