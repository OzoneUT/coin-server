package controllers

import (
	"go.mongodb.org/mongo-driver/mongo"
	"net/http"
)

type AccountController struct {
	db *mongo.Database
}

func NewAccountController(db *mongo.Database) *AccountController {
	return &AccountController{db}
}

func (c AccountController) AccessAcount(w http.ResponseWriter, r *http.Request) {
	// check if the cookie is valid and session is unexpired
	// cookie validated. look up the corresponding user in the users collection
	// serve the user's personal information
}
