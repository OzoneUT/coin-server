package controllers

import (
	"coin-server/models"
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/go-redis/redis/v7"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

// AuthController contains references to data sources needed by this Auth controller
type AuthController struct {
	db    *mongo.Database
	cache *redis.Client
}

// NewAuthController takes pointers to initialized data sources and returns a new
// auth controller
func NewAuthController(db *mongo.Database, cache *redis.Client) *AuthController {
	return &AuthController{db, cache}
}

// LoginWithCredentials handles /login where the user passes in their username
// and password in the request body. If they check out, we create a new access
// and refresh token and send it back with the response's Authorization header
func (a AuthController) LoginWithCredentials(w http.ResponseWriter, r *http.Request) {
	// read the request body into u
	u := models.User{}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Println("Couldn't read the request's body:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := json.Unmarshal(b, &u); err != nil {
		log.Println("Could not unmarshal json into struct:", err)
		log.Println(b)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// verify credentials from users collection in db
	dbUser := models.User{}
	err = a.db.Collection("users").FindOne(context.Background(), bson.M{"_id": u.Email}).Decode(&dbUser)
	if err != nil {
		log.Println("Could get document using email (id) from request:", err)
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if err = bcrypt.CompareHashAndPassword([]byte(dbUser.Password), []byte(u.Password)); err != nil {
		// if err is not nil, the comparison failed.
		log.Println("Incorrect password for user", u.Email, err)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// replace this user's session token in redis
	tkMeta, err := CreateToken(dbUser.Id)
	if err != nil {
		log.Println("Could not create an auth token:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	outData, err := CreateAuth(a.cache, dbUser.Id, tkMeta)
	if err != nil {
		log.Println("Could not save the token meta in Redis:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// send the request with the authorization tokens
	result, err := json.Marshal(outData)
	if err != nil {
		log.Println("Could not encode outbound data into writer w:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(result)
}

// Logout handles the /logout route and invalidates the associated user's session entry in
// the Redis cache
func (a AuthController) Logout(w http.ResponseWriter, r *http.Request) {
	token, err := ExtractTokenMetadata(r)
	if err != nil {
		log.Println("Could not extract token metadata:", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	err = DeleteCachedAuth(a.cache, token.AccessID)
	if err != nil {
		log.Println("Could not delete session metadata in redis cache:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Println(token.UserID + "'s session removed from cache")
}

// Register handles the /register route to add a user to the db
func (a AuthController) Register(writer http.ResponseWriter, request *http.Request) {
	// read the request body into u
	u := models.User{}
	err := json.NewDecoder(request.Body).Decode(&u)
	if err != nil {
		writer.WriteHeader(http.StatusBadRequest)
		return
	}

	// process the plaintext password and user metadata
	hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), 14)
	if err != nil {
		log.Println("Could not generate bcrypt hash from given password:", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	u.Id = u.Email
	u.Password = string(hash)
	u.Created = time.Now()

	// marshal into bson and save the user in db
	bsonUser, err := bson.Marshal(&u)
	if err != nil {
		log.Println("Could not marshal user struct into bson:", err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	result, err := a.db.Collection("users").InsertOne(context.Background(), bsonUser)
	if err != nil {
		log.Println("Could not save the user into db:", err)
		writer.WriteHeader(http.StatusNotAcceptable) // probably duplicate key error
		return
	}
	log.Println("inserted 1 user: ", result.InsertedID)
	writer.WriteHeader(http.StatusCreated)
}
