package models

import "time"

type User struct {
	ID        string    `json:"id" bson:"_id"`
	Name      string    `json:"name" bson:"name"`
	Email     string    `json:"email" bson:"email"`
	Password  string    `json:"password" bson:"password"`
	Created   time.Time `json:"created" bson:"created"`
	SetupDone bool      `json:"accountSetupComplete" bson:"accountSetupComplete"`
	Banks     []Bank    `json:"bankInstitutionEntities" bson:"bankInstitutionEntities"`
}

type Bank struct {
	ID     string  `json:"id" bson:"_id"`
	Name   string  `json:"institutionName" bson:"institutionName"`
	Type   string  `json:"institutionType" bson:"institutionType"`
	Amount float64 `json:"initialAmount" bson:"initialAmount"`
}

type UserWithAuth struct {
	User          `json:"user"`
	OutboundToken `json:"tokens"`
}
