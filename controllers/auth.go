package controllers

import (
	"coin-server/models"
	"context"
	"encoding/json"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type sidInfo struct {
	Token   string    `json:"token" bson:"token"`
	UserID  string    `json:"userid" bson:"userid"`
	Expires time.Time `json:"expires" bson:"expires"`
}

type AuthController struct {
	db *mongo.Database
}

func NewAuthController(db *mongo.Database) *AuthController {
	return &AuthController{db}
}

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

	// replace this user's session token and return the new one to them
	tk := []byte("TODO") //TODO
	tkHash, err := bcrypt.GenerateFromPassword(tk, 0)
	if err != nil {
		log.Println("Could not generate hash from UUID/sessionToken", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	exp := cookieExpDayFromNow()
	filter := bson.M{"userid": dbUser.Id}
	repl, _ := bson.Marshal(sidInfo{
		Token:   string(tkHash),
		UserID:  u.Email,
		Expires: exp,
	})
	opts := options.Replace().SetUpsert(true)
	if _, err = a.db.Collection("sessions").ReplaceOne(context.Background(), filter, repl, opts); err != nil {
		log.Println("Could not save session object to the db", err)
		// does not fail the request since it's not functionality-breaking
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    string(tk),
		Expires:  exp,
		HttpOnly: true,
	})
	w.WriteHeader(http.StatusFound)
}

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

////////////////////////////////////////////////////////////////////

func cookieExpDayFromNow() time.Time {
	return time.Now().Add(time.Hour * 24 * 30)
}
