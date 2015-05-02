package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"text/template"
	"time"

	"github.com/gorilla/context"
	"github.com/justinas/alice"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

const (
	//Cost is the well, cost of the bcrypt encryption used for storing user
	//passwords in the database
	Cost int = 5
)

type appContext struct {
	db *mgo.Database
}

type user struct {
	ID       string //Users ID in user collection
	UserID   string //Users ID returned by provider
	Username string
	Password string
	Name     string
	Provider string
	Email    string
}
type lookUp struct {
	Provider       string
	IDFromProvider string
	UserID         string
}

// Errors

//Errors holds a slice for situations where multiple errors would be sent to the
//client
type Errors struct {
	Errors []*Error `json:"errors"`
}

//Error holds schema for marshalling error messages in the JSON API standard way
type Error struct {
	ID     string `json:"id"`
	Status int    `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

//WriteError is a helper that sends the error message to the client based on an
//error name which is a pointer to a struct representing the error
func WriteError(w http.ResponseWriter, err *Error) {
	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(err.Status)
	json.NewEncoder(w).Encode(Errors{[]*Error{err}})
}

var (
	//ErrBadRequest represents situations when the request from the client does not make sense to the server
	ErrBadRequest = &Error{"bad_request", 400, "Bad request", "Request body is not well-formed. It must be JSON."}
	//ErrNotAcceptable is for when the message is not encoded in the json
	//api standard format
	ErrNotAcceptable = &Error{"not_acceptable", 406, "Not Acceptable", "Accept header must be set to 'application/vnd.api+json'."}
	//ErrUnsupportedMediaType is as the name goes
	ErrUnsupportedMediaType = &Error{"unsupported_media_type", 415, "Unsupported Media Type", "Content-Type header must be set to: 'application/vnd.api+json'."}
	//ErrInternalServer is for not so specific errors, like when the server
	//panics and shutsdown, etc
	ErrInternalServer = &Error{"internal_server_error", 500, "Internal Server Error", "Something went wrong."}
)

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

//DB helpers

func (c *appContext) newUser(u *user) (string, error) {
	users := c.db.C("users")
	err := users.Insert(u)

	if err != nil {
		return "", err
	}

	lookup := &lookUp{
		Provider:       u.Provider,
		IDFromProvider: u.ID,
		UserID:         u.UserID,
	}
	log.Println("struct")
	log.Println(lookup)

	l := c.db.C("lookup")
	err = l.Insert(lookup)

	if err != nil {
		return "", err
	}
	return u.UserID, nil
}

func (c *appContext) newLocalAuth(email, password string) (string, error) {
	phash, err := bcrypt.GenerateFromPassword([]byte(password), Cost)
	if err != nil {
		log.Println(err)
	}

	id := bson.NewObjectId()
	err = c.db.C("localauth").Insert(
		&bson.M{
			"_id":      id,
			"email":    email,
			"password": phash,
		})
	if err != nil {
		log.Println(err)
		return id.Hex(), err
	}
	return id.Hex(), nil
}

//Handlers
func landingHandler(w http.ResponseWriter, r *http.Request) {
}

func (c *appContext) userHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		r.ParseForm()
		data := &user{}
		err := json.NewDecoder(r.Body).Decode(data)
		if err != nil {
			log.Println(err)
		}

		if data.Provider == "local" {
			id, err := c.newLocalAuth(data.Email, data.Password)
			if err != nil {
				log.Println(err)
			}
			data.UserID = id

		}

		ID, err := c.newUser(data)
		if err != nil {
			log.Println(err)
		}

		log.Println(ID)

	}

}

//pre parse the template files, and store them in memory. Fail if
//they're not found
var templates = template.Must(template.ParseFiles("templates/index.html"))

//renderTemplate is simply a helper function that takes in the response writer
//interface, the template file name and the data to be passed in, as an
//interface. It causes an internal server error if any of the templates is not
//found. Better fail now than fail later, or display rubbish.
func renderTemplate(w http.ResponseWriter, tmpl string, q interface{}) {
	err := templates.ExecuteTemplate(w, tmpl, q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}


func init(){
  log.SetFlags(log.LstdFlags | log.Lshortfile)
}


func main() {
	MONGOSERVER := os.Getenv("MONGOLAB_URI")
	if MONGOSERVER == "" {
		fmt.Println("No mongo server address set, resulting to default address")
		MONGOSERVER = "localhost"
	}
	log.Println("MONGOSERVER is ", MONGOSERVER)

	MONGODB := os.Getenv("MONGODB")
	if MONGODB == "" {
		fmt.Println("No Mongo database name set, resulting to default")
		MONGODB = "pollo"
	}
	log.Println("MONGODB is ", MONGODB)

	session, err := mgo.Dial(MONGOSERVER)
	if err != nil {
		panic(err)
	}
	defer session.Close()
	session.SetMode(mgo.Monotonic, true)

	appC := appContext{session.DB(MONGODB)}

	cH := alice.New(context.ClearHandler, loggingHandler, recoverHandler, acceptHandler)
	//serve assets
	fs := http.FileServer(http.Dir("templates/assets/"))
	http.Handle("/assets/", http.StripPrefix("/assets/", fs))
	http.Handle("/me", cH.ThenFunc(appC.userHandler))
	http.HandleFunc("/", landingHandler)

	PORT := os.Getenv("PORT")
	if PORT == "" {
		log.Println("No Global port has been defined, using default")

		PORT = "8080"

	}

	log.Println("serving on http://localhost:" + PORT)
	log.Fatal(http.ListenAndServe(PORT, http.DefaultServeMux))
}
