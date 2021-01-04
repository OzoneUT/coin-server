package controllers

import (
	"coin-server/models"
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
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

// LoginWithCredentials handles /auth/login where the user passes in their username
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
		log.Println("Could not encode outbound data into writer:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Write(result)
}

// Logout handles the /auth/logout route and invalidates the associated user's
// session entry in the Redis cache
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
	log.Println("one session removed from cache for user", token.UserID)
}

// Register handles the /auth/register route to add a user to the db
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

// RefreshAuth handles the /auth/refresh route by doing the following:
// 1. checks the authorization header for a valid, unexpired refresh token
// 2. generates a new pair of access and refresh tokens, replacing the old
// refresh token in the cache, effectively making refresh tokens one-time use
// which *appear* non-expiring to users who visit regularly
// 3. returns the new pair of tokens to the client
func (a AuthController) RefreshAuth(w http.ResponseWriter, r *http.Request) {
	token, err := TokenValid(r)
	if err != nil {
		log.Println("Could not verify refresh token:", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		refreshID := claims["refresh_id"].(string)
		userID := claims["user_id"].(string)
		if err := DeleteCachedAuth(a.cache, refreshID); err != nil {
			log.Println("Could not delete refresh token:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		newMeta, err := CreateToken(userID)
		if err != nil {
			log.Println("Could not create new tokens:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		outData, err := CreateAuth(a.cache, userID, newMeta)
		if err != nil {
			log.Println("Could not save new tokens to cache:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		result, err := json.Marshal(outData)
		if err != nil {
			log.Println("Could not marshal new tokens:", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Write(result)
	} else {
		log.Println("Could not process the refresh token's claims: token.valid=", token.Valid, claims)
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
}
