package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"text/template"

	"github.com/gorilla/context"
	"github.com/justinas/alice"
	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/s3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
	"gopkg.in/redis.v2"
)

const (
	//Cost is the well, cost of the bcrypt encryption used for storing user
	//passwords in the database
	Cost int = 5
)

type appContext struct {
	db        *mgo.Database
	verifyKey []byte
	signKey   []byte
	token     string

	login      string
	fbclientid string
	fbsecret   string
	domain     string

	bucket *s3.Bucket
	redis  *redis.Client
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
	renderTemplate(w, "index.html", "")
}

func (c *appContext) userHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("user handler")
	switch r.Method {
	case "POST":
		r.ParseForm()
		data := User{}
		err := json.NewDecoder(r.Body).Decode(data)
		if err != nil {
			log.Println(err)
		}

		if data.Provider == "local" {
			id, err := c.newLocalAuth(data.Email, data.Password)
			if err != nil {
				log.Println(err)
			}
			data.ID = id

		}

		ID, err := c.NewUser(&data, "facebook")
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

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func checks() (MONGOSERVER, MONGODB string, Public []byte, Private []byte, FBURL, FBClientID, FBClientSecret, RootURL, AWSBucket string) {

	MONGOSERVER = os.Getenv("MONGOLAB_URI")
	if MONGOSERVER == "" {
		log.Println("No mongo server address set, resulting to default address")
		MONGOSERVER = "localhost"
	}
	log.Println("MONGOSERVER is ", MONGOSERVER)

	MONGODB = os.Getenv("MONGODB")
	if MONGODB == "" {
		log.Println("No Mongo database name set, resulting to default")
		MONGODB = "pollo"
	}
	log.Println("MONGODB is ", MONGODB)

	AWSBucket = os.Getenv("AWSBucket")
	if AWSBucket == "" {
		log.Println("No AWSBucket set, resulting to default")
		AWSBucket = "pollo"
	}
	log.Println("AWSBucket is ", AWSBucket)

	Public, err := ioutil.ReadFile("app.rsa.pub")
	if err != nil {
		log.Fatal("Error reading public key")
		return
	}

	Private, err = ioutil.ReadFile("app.rsa")
	if err != nil {
		log.Fatal("Error reading private key")
		return
	}

	FBClientID = os.Getenv("FBClientID")
	FBClientSecret = os.Getenv("FBClientSecret")
	RootURL = os.Getenv("RootURL")
	if RootURL == "" {
		RootURL = "http://localhost:8080"
	}
	fbConfig := &oauth2.Config{
		// ClientId: FBAppID(string), ClientSecret : FBSecret(string)
		// Example - ClientId: "1234567890", ClientSecret: "red2drdff6e2321e51aedcc94e19c76ee"

		ClientID:     FBClientID, // change this to yours
		ClientSecret: FBClientSecret,
		RedirectURL:  RootURL + "/FBLogin", // change this to your webserver adddress
		Scopes:       []string{"email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://www.facebook.com/dialog/oauth",
			TokenURL: "https://graph.facebook.com/oauth/access_token",
		},
	}
	FBURL = fbConfig.AuthCodeURL("")

	if FBClientID == "" {
		FBURL = RootURL + "/offlineauth"
	}
	return
}

func main() {

	MONGOSERVER, MONGODB, Public, Private, FBURL, FBClientID, FBClientSecret, RootURL, AWSBucket := checks()
	session, err := mgo.Dial(MONGOSERVER)
	if err != nil {
		panic(err)
	}
	defer session.Close()

	session.SetMode(mgo.Monotonic, true)
	database := session.DB(MONGODB)

	auth, err := aws.EnvAuth()
	if err != nil {
		//panic(err)
		log.Println("no aws ish")
	}
	s := s3.New(auth, aws.USWest2)
	s3bucket := s.Bucket(AWSBucket)

	appC := appContext{
		db:         database,
		verifyKey:  []byte(Public),
		signKey:    []byte(Private),
		token:      "AccessToken",
		login:      FBURL,
		fbclientid: FBClientID,
		fbsecret:   FBClientSecret,
		domain:     RootURL,
		bucket:     s3bucket,
	}

	//appC.xmain()
	cH := alice.New(context.ClearHandler, loggingHandler, recoverHandler)

	//serve assets
	fs := http.FileServer(http.Dir("templates/assets/"))
	http.Handle("/assets/", http.StripPrefix("/assets/", fs))
	http.Handle("/me", cH.Append(appC.frontAuthHandler).ThenFunc(appC.userHandler))
	http.Handle("/api/auth", cH.ThenFunc(appC.authHandler))

	http.Handle("/api/polls/new", cH.ThenFunc(appC.newPollHandler))
	http.Handle("/api/polls/all", cH.ThenFunc(appC.pollResultsHandler))
	http.HandleFunc("/", landingHandler)

	PORT := os.Getenv("PORT")
	if PORT == "" {
		log.Println("No Global port has been defined, using default")

		PORT = "8080"

	}

	log.Println("serving on http://localhost:" + PORT)
	log.Fatal(http.ListenAndServe(":"+PORT, http.DefaultServeMux))
}
