package main

import (
	"coin-server/controllers"
	"coin-server/middleware"
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

func init() {
	// set env variables from /coin.env
	if err := godotenv.Load("coin.env"); err != nil {
		log.Fatal("No .env file found: ", err)
	}
}

func main() {
	// setup data connections
	db := setupMongoDB()
	cache := setupRedis()
	
	// create controllers
	authCtl := controllers.NewAuthController(db, cache)
	acctCtl := controllers.NewAccountController(db, cache)
	
	// simple routes
	http.Handle("/favicon.ico", http.NotFoundHandler())
	http.HandleFunc("/login", authCtl.LoginWithCredentials)
	http.HandleFunc("/register", authCtl.Register)
	
	// routes with middleware
	acctHandler := http.HandlerFunc(acctCtl.AccessAccount)
	logoutHandler := http.HandlerFunc(authCtl.Logout)
	http.Handle("/account", middleware.EnsureAuthMW(acctHandler))
	http.Handle("/logout", middleware.EnsureAuthMW(logoutHandler))
	
	// finally, start the server
	addr, found := os.LookupEnv("SERVER_ADDR")
	if !found {
		log.Fatal("SERVER_ADDR not found!")
	}
	log.Println("Listening on", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}