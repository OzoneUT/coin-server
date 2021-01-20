package models

import "time"

type User struct {
	ID       string    `json:"id" bson:"_id"`
	Name     string    `json:"name" bson:"name"`
	Email    string    `json:"email" bson:"email"`
	Password string    `json:"password" bson:"password"`
	Created  time.Time `json:"created" bson:"created"`
}

type UserWithAuth struct {
	User			`json:"user"`
	OutboundToken	`json:"tokens"`
}
