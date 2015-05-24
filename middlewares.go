package main

import (
	"log"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
)

//Middlewares

//Middlewares

func loggingHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		t1 := time.Now()
		next.ServeHTTP(w, r)
		t2 := time.Now()
		log.Printf("[%s] %q %v\n", r.Method, r.URL.String(), t2.Sub(t1))
	}

	return http.HandlerFunc(fn)
}

func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("panic: %+v", err)
				WriteError(w, ErrInternalServer)
			}
		}()

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func acceptHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "application/vnd.api+json" {
			WriteError(w, ErrNotAcceptable)
			return
		}

		next.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

func (ac *appContext) frontAuthHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {

		// check if we have a cookie with out tokenName

		tokenCookie := r.Header.Get("X-AUTH-TOKEN")
		log.Println(tokenCookie)
		//log.Println(ac.token)
		//log.Println(tokenCookie)

		// validate the token
		token, err := jwt.Parse(tokenCookie, func(token *jwt.Token) (interface{}, error) {
			// since we only use the one private key to sign
			// the tokens,
			// we also only use its public counter
			// part to verify
			return ac.verifyKey, nil
		})

		// branch out into the possible error from signing
		switch err.(type) {

		case nil: // no error

			if !token.Valid { // but may still be invalid
				//w.WriteHeader(http.StatusUnauthorized)
				//fmt.Fprintln(w, "WHAT? Invalid Token? F*** off!")
				log.Println("Invalid Token.... Hack attempt?")
			}

			//log.Println("Someone accessed resricted area! Token:%+v\n", token)
			//w.Header().Set("Content-Type", "text/html")
			//w.WriteHeader(http.StatusOK)
			//fmt.Fprintln(w, "restricted Area")

			context.Set(r, "User", token.Claims["User"])
			log.Println(token.Claims["User"])
			next.ServeHTTP(w, r)

		case *jwt.ValidationError: // something was wrong during the validation
			vErr := err.(*jwt.ValidationError)

			switch vErr.Errors {
			case jwt.ValidationErrorExpired:
				//w.WriteHeader(http.StatusUnauthorized)
				//fmt.Fprintln(w, "Token Expired, get a new one.")
				next.ServeHTTP(w, r)

			default:
				//w.WriteHeader(http.StatusInternalServerError)
				//fmt.Fprintln(w, "Error while Parsing Token!")
				log.Printf("ValidationError error: %+v\n", vErr.Errors)
				next.ServeHTTP(w, r)
			}

		default: // something else went wrong
			//w.WriteHeader(http.StatusInternalServerError)
			//fmt.Fprintln(w, "Error while Parsing Token!")
			log.Printf("Token parse error: %v\n", err)
			next.ServeHTTP(w, r)
		}

	}
	return http.HandlerFunc(fn)

}
