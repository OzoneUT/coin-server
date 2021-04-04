package controllers

import (
	"coin-server/models"
	"context"
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-redis/redis/v7"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
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

// AccessAccount handles the /api/account route to return the associated authenticated user object
func (c AccountController) AccessAccount(w http.ResponseWriter, r *http.Request) {
	// get token metadata
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

	// look up user by userID in db, decode it into the dbStruct, then encode it into json
	dbUser := models.User{}
	rs := c.db.Collection("users").FindOne(
		context.Background(),
		bson.M{"_id": userID},
		options.FindOne().SetProjection(bson.M{"password": 0}))
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
	out, err := json.Marshal(dbUser)
	if err != nil {
		log.Println("Could not encode outbound data into writer:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// authenticated. return user's data
	w.Write(out)
}

// SetupAccount handles the /api/setup route to add user's initial setup amount
// to the DB and set the accountSetupCompleted flag. Returns the updated User object
func (c AccountController) SetupAccount(w http.ResponseWriter, r *http.Request) {
	const key = "setupAmount"
	// get token metadata and userID from request's Auth header
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

	// ensure the account has not already been setup
	dbUser := models.User{}
	rs := c.db.Collection("users").FindOne(
		context.Background(),
		bson.M{"_id": userID},
		options.FindOne().SetProjection(bson.M{"accountSetupComplete": 1}))
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
	if dbUser.SetupDone {
		log.Println("Error: This account has already been setup.")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	// extract the setupAmount from the request; check that it's a float64
	var f interface{}
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		log.Println("Could not decode the request body: ", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var setupAmount float64
	m := f.(map[string]interface{})
	if val, present := m[key]; present {
		switch val.(type) {
		case float64:
			setupAmount = val.(float64)
		default:
			log.Printf("%v value is not a float64\n", key)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	} else {
		log.Println("Could not find setupValue in request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// encode banks into bson, then update the existing user's document with
	// the new Banks and flag
	result := c.db.Collection("users").FindOneAndUpdate(
		context.Background(),
		bson.M{"_id": userID},
		bson.D{
			{Key: "$set", Value: bson.D{
				{Key: "setupAmount", Value: setupAmount},
				{Key: "accountSetupComplete", Value: true}},
			},
		},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
		options.FindOneAndUpdate().SetProjection(bson.M{"password": 0}),
	)

	// decode the resulting User object and sent it back to the client
	err = result.Decode(&dbUser)
	if err != nil {
		log.Println("Error updating/decoding dbUser: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Println("updated user in setupAccount()")
	out, err := json.Marshal(dbUser)
	if err != nil {
		log.Println("Couldn't decode dbUser into User struct: ", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Write(out)
}
