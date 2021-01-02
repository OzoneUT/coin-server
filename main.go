package main

import (
	"coin-server/controllers"
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-redis/redis/v7"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var authCtl *controllers.AuthController
var acctCtl *controllers.AccountController

func init() {
	// set env variables from /coin.env
	if err := godotenv.Load("coin.env"); err != nil {
		log.Fatal("No .env file found: ", err)
	}

	// connect to mongodb cluster
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	url, found := os.LookupEnv("MONGODB_URL")
	if !found {
		log.Fatal("MONGODB_URL env variable not found!")
	}
	c, err := mongo.Connect(ctx, options.Client().ApplyURI(url))
	if err != nil {
		log.Fatal(err)
	}
	db := c.Database("coin-dev")

	// connect to redis
	url, found = os.LookupEnv("REDIS_ADDR")
	if !found {
		log.Fatal("REDIS_ADDR not found!")
	}
	cache := redis.NewClient(&redis.Options{
		Addr: url,
	})
	if _, err := cache.Ping().Result(); err != nil {
		log.Fatal("Could not connect to redis:", err)
	}

	// create controllers
	authCtl = controllers.NewAuthController(db, cache)
	acctCtl = controllers.NewAccountController(db, cache)
}

func main() {
	http.Handle("/favicon.ico", http.NotFoundHandler())

	http.HandleFunc("/login", authCtl.LoginWithCredentials)
	http.HandleFunc("/register", authCtl.Register)
	http.HandleFunc("/account", acctCtl.AccessAccount)
	http.HandleFunc("/logout", authCtl.Logout)

	addr, found := os.LookupEnv("SERVER_ADDR")
	if !found {
		log.Fatal("SERVER_ADDR not found!")
	}
	log.Println("Listening on", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}
