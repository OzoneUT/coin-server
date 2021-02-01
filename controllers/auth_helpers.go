package controllers

import (
	"coin-server/models"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v7"
	uuid "github.com/satori/go.uuid"
)

// ParseBasicAuthorization is a helper function that parses out the email and password
// used for basic authentication in the /auth/login handler
func ParseBasicAuthorization(val string) (usrn string, pwd string, err error) {
	header := strings.Split(val, " ")
	if len(header) != 2 {
		return usrn, pwd, fmt.Errorf("malformed authorization header: %s", header)
	}
	bs, err := base64.StdEncoding.DecodeString(header[1])
	if err != nil {
		return usrn, pwd, fmt.Errorf("malformed authorization header value: %s %v", header[1], err)
	}
	cred := strings.Split(string(bs), ":")
	if len(cred) != 2 {
		return usrn, pwd, fmt.Errorf("creds not encoded correctly: %s", bs)
	}
	return cred[0], cred[1], nil
}

// CreateToken is a helper that returns a fully formed AuthToken struct containing the meta
// data for both Access and Refresh tokens for a given user id
func CreateToken(id string) (*models.AuthToken, error) {
	meta := &models.AuthToken{}
	meta.AccessExpires = time.Now().Add(time.Minute * 30).Unix()
	meta.RefreshExpires = time.Now().Add(time.Hour * 24 * 30).Unix()
	meta.AccessID = uuid.NewV4().String()
	meta.RefreshID = uuid.NewV4().String()

	accessTkClaims := jwt.MapClaims{}
	accessTkClaims["authorized"] = true
	accessTkClaims["access_id"] = meta.AccessID
	accessTkClaims["user_id"] = id
	accessTkClaims["exp"] = meta.AccessExpires
	accessTk := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTkClaims)
	atkSigned, err := accessTk.SignedString([]byte(os.Getenv("ACCESS_SECRET")))
	if err != nil {
		return nil, err
	}
	meta.AccessToken = atkSigned

	refreshTkClaims := jwt.MapClaims{}
	refreshTkClaims["refresh_id"] = meta.RefreshID
	refreshTkClaims["user_id"] = id
	refreshTkClaims["exp"] = meta.RefreshExpires
	refreshTk := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTkClaims)
	rtkSigned, err := refreshTk.SignedString([]byte(os.Getenv("REFRESH_SECRET")))
	if err != nil {
		return nil, err
	}
	meta.RefreshToken = rtkSigned

	return meta, nil
}

// CreateAuth is a helper that takes a userID and *models.AuthToken and creates expiring
// entries in the Redis cache for both the Access and Refresh tokens in the AuthToken.
// Returns an *models.OutboundToken which contains just enough auth data to send back with the
// response to the user.
func CreateAuth(cache *redis.Client, userid string, meta *models.AuthToken) (*models.OutboundToken, error) {
	expAccess := time.Unix(meta.AccessExpires, 0)
	expRefresh := time.Unix(meta.RefreshExpires, 0)
	now := time.Now()

	err := cache.Set(meta.AccessID, userid, expAccess.Sub(now)).Err()
	if err != nil {
		return &models.OutboundToken{}, err
	}
	err = cache.Set(meta.RefreshID, userid, expRefresh.Sub(now)).Err()
	if err != nil {
		return &models.OutboundToken{}, err
	}

	return &models.OutboundToken{
		AccessToken:  meta.AccessToken,
		RefreshToken: meta.RefreshToken,
	}, nil
}

// ConfirmCachedAuth checks to see if an auth exists in our sessions cache by looking
// up a token's AccessID. If a userid is returned, we know that the token is in our
// cache and is, therefore, valid.
func ConfirmCachedAuth(cache *redis.Client, details *models.AccessDetails) (string, error) {
	return cache.Get(details.AccessID).Result()
}

// DeleteCachedAuth removes session meta associated with the provided tokenID and returns nil
// if successful. Otherwise, returns error.
func DeleteCachedAuth(cache *redis.Client, tokenID string) error {
	_, err := cache.Del(tokenID).Result()
	if err != nil {
		return err
	}
	return nil
}

// ExtractTokenMetadata calls VerifyToken (which extracts and verifies the token),
// then organizes the token's metadata into an AccessDetails struct for easy
// Redis lookup
func ExtractTokenMetadata(r *http.Request) (*models.AccessDetails, error) {
	token, err := VerifyToken(r)
	if err != nil {
		return nil, err
	}
	// token.Valid populated when token is parsed and verified by jwt
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		return &models.AccessDetails{
			AccessID: claims["access_id"].(string),
			UserID:   claims["user_id"].(string),
		}, nil
	}
	return nil, fmt.Errorf("there was an error getting claims from the jwt.Token")
}

// TokenValid returns nil if the token is valid (unexpired). Also calls VerifyToken
// to verify the token's signature and integrity first.
func TokenValid(r *http.Request) (*jwt.Token, error) {
	token, err := VerifyToken(r)
	if err != nil {
		return nil, err
	}
	// token.Valid field is populated when token is parsed/verified
	if _, ok := token.Claims.(jwt.Claims); !ok && token.Valid {
		return nil, err
	}
	return token, nil
}

// VerifyToken is a helper function that retreives the extracted token and verifies
// the integrity of the token using jwt.Parse, returns *jwt.Token or err if there
// is a problem.
func VerifyToken(r *http.Request) (*jwt.Token, error) {
	jwtString := ExtractToken(r)
	jwtToken, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		// Ensure token method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(getSecret(r.URL.Path)), nil
	})
	if err != nil {
		return nil, err
	}
	return jwtToken, nil
}

func getSecret(path string) string {
	if path == "/auth/refresh" {
		return os.Getenv("REFRESH_SECRET")
	}
	return os.Getenv("ACCESS_SECRET")
}

// ExtractToken is a helper function that extracts the bearer token from the Authorization
// header of the client's request
func ExtractToken(r *http.Request) string {
	header := r.Header.Get("Authorization")
	if xs := strings.Split(header, " "); len(xs) == 2 {
		return xs[1]
	}
	return ""
}
