package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func (c *appContext) authHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("Offline Login")
	//u := User{
	//	Name:  "Anthony Alaribe",
	//	PID:   "1234567890",
	//	Email: "anthonyalaribe@gmail.com",
	//	Image: "http://placehold.it/100x100",
	//}
	u := User{}
	log.Println(r.Body)
	err := json.NewDecoder(r.Body).Decode(&u)
log.Println(u)
	user, err := c.Authenticate(&u, "facebook")

	if err != nil {
		log.Println(err)
	}
	
	log.Println(user)
	// create a signer for rsa 256
	t := jwt.New(jwt.GetSigningMethod("RS256"))

	// set our claims
	t.Claims["AccessToken"] = user.Permission
	t.Claims["User"] = user

	// set the expire time
	// see http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4.1.4
	t.Claims["exp"] = time.Now().Add(time.Minute * 10).Unix()
	tokenString, err := t.SignedString(c.signKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "Sorry, error while Signing Token!")
		log.Printf("Token Signing error: %v\n", err)
		return
	}

	log.Println(c.token)
	log.Println(tokenString)

	// i know using cookies to store the token isn't really helpfull for cross domain api usage
	// but it's just an example and i did not want to involve javascript
	//	http.SetCookie(w, &http.Cookie{
	//		Name:       c.token,
	//		Value:      tokenString,
	//		Path:       "/",
	//		RawExpires: "0",
	//	})

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokenString))
	//http.Redirect(w, r, "/", http.StatusFound)
}
