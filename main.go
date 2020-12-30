package main

import (
	"coin-server/controllers"
	"context"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"net/http"
	"time"
)

var ac *controllers.AuthController
var anc *controllers.AccountController

func init() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := mongo.Connect(ctx, options.Client().ApplyURI(
		"mongodb+srv://coin-server-admin-user:uqBB5gSv8KnWgeV@coincluster0.xaky7.mongodb.net/coin-dev?retryWrites=true&w=majority",
	))
	if err != nil {
		log.Fatal(err)
	}
	db := c.Database("coin-dev")
	ac = controllers.NewAuthController(db)
	anc = controllers.NewAccountController(db)
}

func main() {
	http.Handle("/favicon.ico", http.NotFoundHandler())

	http.HandleFunc("/login", ac.LoginWithCredentials)
	http.HandleFunc("/register", ac.Register)
	http.HandleFunc("/account", anc.AccessAcount)

	log.Println("Listening on port 8080.")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
