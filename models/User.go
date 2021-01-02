package models

import "time"

type User struct {
	Id       string    `json:"id" bson:"_id"`
	Name     string    `json:"name" bson:"name"`
	Email    string    `json:"email" bson:"email"`
	Password string    `json:"password" bson:"password"`
	Created  time.Time `json:"created" bson:"created"`
}
