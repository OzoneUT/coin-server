package controllers

import (
	"coin-server/models"
	"context"
	"log"
	"net/http"

	"github.com/go-redis/redis/v7"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// AccountController contains references to data sources needed by this account
// controller
type AccountController struct {
	db    *mongo.Database
	cache *redis.Client
}

// NewAccountController takes pointers to initialized data sources and returns a new
// account controller
func NewAccountController(db *mongo.Database, cache *redis.Client) *AccountController {
	return &AccountController{db, cache}
}

// AccessAccount handles the /account route as a test for cookie checks
func (c AccountController) AccessAccount(w http.ResponseWriter, r *http.Request) {
	// check if client is sent an authorized token
	accessDetails, err := ExtractTokenMetadata(r)
	if err != nil {
		log.Println("Could not extract bearer token's metadata...", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	userID, err := ConfirmCachedAuth(c.cache, accessDetails)
	if err != nil {
		log.Println("Could not find bearer token's data in cache:", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// look up user by userID in db
	dbUser := models.User{}
	rs := c.db.Collection("users").FindOne(context.Background(), bson.M{"_id": userID})
	if rs.Err() != nil {
		log.Println("Token was authorized but the associated userID is not present in the db", rs.Err())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err = rs.Decode(&dbUser); err != nil {
		log.Println("Could not decode db's bson into user struct", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// authenticated. return user's data
	w.Write([]byte("Welcome, " + dbUser.Name + "!"))
}
