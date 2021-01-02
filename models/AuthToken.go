package models

// AuthToken struct to represent tokens and their respective IDs/exp times
// for use in authentication (access and refresh)
type AuthToken struct {
	AccessToken    string	
	RefreshToken   string
	AccessID       string
	RefreshID      string
	AccessExpires  int64
	RefreshExpires int64
}

// OutboundToken struct represents the JSON object we send back with the response
// upon authentication
type OutboundToken struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// AccessDetails represents the incoming request's bearer token's metadata used
// for confirming authentication in the Redis cache
type AccessDetails struct {
    AccessID string
    UserID   string
}